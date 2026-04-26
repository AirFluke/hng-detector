# How I Built a Real-Time DDoS Detection Engine from Scratch (No Fail2Ban)

*Published on Medium by Abraham Acha*

---

Assuming my boss walked in and said "we're getting hit with suspicious traffic and I need you to build something that detects and responds to it automatically," I had two choices: reach for Fail2Ban like everyone else, or build something I actually understood from the ground up.

I chose to build it from scratch. This post explains exactly how I did it — in plain English, with real code, and without assuming you've ever touched security tooling before.

By the end of this post you will understand:
- What the system does and why it matters
- How a sliding window works (and why it's not just "count requests per minute")
- How the system learns what normal traffic looks like
- How it decides something is an attack
- How it uses iptables to cut off an attacker at the firewall level

Let's go.

---

## What This Project Does and Why It Matters

We run a cloud storage platform built on Nextcloud. It's public-facing, which means anyone on the internet can send requests to it — including bots, scanners, and attackers.

Two types of attacks concern us most:

**A single aggressive IP** — one machine sending hundreds of requests per second, trying to brute-force logins, scrape data, or simply overwhelm the server. This is a classic DDoS from a single source.

**A global traffic spike** — thousands of different IPs each sending a small number of requests. No single IP looks suspicious, but the total volume is crushing the server. This is a distributed DDoS.

The tool I built watches every HTTP request in real time, learns what "normal" traffic looks like, and fires an automatic response the moment something deviates — whether it's a single aggressive IP or a global spike.

For a single aggressive IP: it adds an `iptables` firewall rule to drop every packet from that IP, sends a Slack alert, and automatically releases the ban on a backoff schedule (10 minutes, then 30, then 2 hours, then permanent for repeat offenders).

For a global spike: it sends a Slack alert (no single IP to block).

The whole thing runs as a daemon — a continuously running background process — alongside the Nextcloud stack in Docker. It never sleeps, never needs a cron job, and never relies on hardcoded thresholds.

Here's the architecture at a glance:

```
Internet → Nginx (reverse proxy) → Nextcloud
                ↓ writes JSON logs
         [HNG-nginx-logs volume]
                ↓ reads logs
         Python Daemon
           ├── monitor.py    (tail the log file)
           ├── baseline.py   (learn normal traffic)
           ├── detector.py   (spot anomalies)
           ├── blocker.py    (iptables + audit log)
           ├── unbanner.py   (auto-release bans)
           ├── notifier.py   (Slack alerts)
           └── dashboard.py  (live web UI)
```

Everything is wired together by `main.py` and configured through a single `config.yaml` file — no hardcoded numbers anywhere in the code.

---

## Part 1: Reading the Traffic — The Log Monitor

Before we can detect anything, we need to see the traffic. Nginx is our reverse proxy — every HTTP request passes through it. We configure Nginx to write each request as a JSON object to a log file.

Here's the Nginx log format we defined:

```nginx
log_format hng_json escape=json
    '{'
        '"source_ip":"$remote_addr",'
        '"timestamp":"$time_iso8601",'
        '"method":"$request_method",'
        '"path":"$uri",'
        '"status":$status,'
        '"response_size":$body_bytes_sent,'
        '"request_time":$request_time,'
        '"http_user_agent":"$http_user_agent"'
    '}';

access_log /var/log/nginx/hng-access.log hng_json;
```

Every request now produces a line like this in the log file:

```json
{
  "source_ip": "1.2.3.4",
  "timestamp": "2026-04-26T14:08:21+00:00",
  "method": "GET",
  "path": "/index.php/login",
  "status": 401,
  "response_size": 1842,
  "request_time": 0.043,
  "http_user_agent": "Mozilla/5.0..."
}
```

Now our Python daemon needs to read these lines as they appear — in real time, without missing any, and without crashing if the log file gets rotated. This is called "tailing" a file, like `tail -f` in Linux.

Here's how `monitor.py` does it:

```python
import os
import time
import json
import queue

def parse_line(raw: str) -> dict | None:
    """Parse one JSON log line. Returns None if malformed."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        entry = json.loads(raw)
    except json.JSONDecodeError:
        return None  # drop malformed lines silently

    # Make sure all required fields are present
    required = {"source_ip", "timestamp", "method", "path", "status", "response_size"}
    if required - entry.keys():
        return None

    # Coerce types and add a wall-clock timestamp for window math
    entry["status"] = int(entry["status"])
    entry["response_size"] = int(entry["response_size"])
    entry["_parsed_at"] = time.time()
    return entry


class LogMonitor:
    def run(self):
        fh = open("/var/log/nginx/hng-access.log", "r")
        fh.seek(0, 2)  # jump to END of file — don't replay old traffic

        current_inode = os.stat(fh.name).st_ino

        while True:
            line = fh.readline()
            if line:
                entry = parse_line(line)
                if entry:
                    self.out_queue.put(entry)  # send downstream
            else:
                # Check if the file was rotated (inode changed)
                new_inode = os.stat(fh.name).st_ino
                if new_inode != current_inode:
                    fh.close()
                    fh = open(fh.name, "r")
                    current_inode = new_inode
                else:
                    time.sleep(0.1)  # no new data, yield CPU briefly
```

Three things worth understanding here:

**`fh.seek(0, 2)`** — When we start the daemon, the log file already has entries from before we launched. We don't want to process all of those as if they're live traffic. Seeking to position 2 (the end) means we only see new lines written after the daemon starts.

**Inode check** — Log files get rotated (renamed and replaced with a fresh empty file) periodically. If we don't detect this, we'd keep reading the old file and miss all new traffic. The inode (a unique file identifier in Linux) changes when the file is replaced, so we check it on every "no new data" cycle.

**The queue** — We put parsed entries into a `queue.Queue`. This decouples reading from processing. The monitor thread just reads and queues; the main thread drains the queue and feeds entries to the baseline and detector. If the detector is temporarily slow, entries buffer in the queue rather than being dropped.

---

## Part 2: How the Sliding Window Works

This is the core data structure of the entire detection system. Get this right and everything else falls into place.

### The wrong way: per-minute counters

The naive approach is to count requests per minute:

```python
# WRONG — this is not a sliding window
requests_this_minute = 0
last_minute = int(time.time() / 60)

def on_request():
    current_minute = int(time.time() / 60)
    if current_minute != last_minute:
        requests_this_minute = 0  # reset
        last_minute = current_minute
    requests_this_minute += 1
```

The problem: imagine an attacker sends 1000 requests at 14:00:59 and another 1000 at 14:01:01. The per-minute counter resets at 14:01:00, so each minute only shows 1000 requests. But in reality, 2000 requests arrived in a 2-second window — a massive spike that the counter completely misses.

### The right way: a deque of timestamps

A sliding window stores the **exact timestamp of every request** in a `collections.deque`. When you want the current rate, you evict old entries and count what remains.

```python
from collections import deque
import time

# One deque per IP, one global
ip_window = deque()    # stores timestamps of requests from this IP
WINDOW = 60            # seconds

def on_request(ip: str, now: float):
    # Step 1: Add this request's timestamp
    ip_window.append(now)

    # Step 2: Evict entries older than 60 seconds from the LEFT
    cutoff = now - WINDOW
    while ip_window and ip_window[0] < cutoff:
        ip_window.popleft()   # O(1) — this is why we use deque, not list

    # Step 3: Rate = requests still in window / window size
    rate = len(ip_window) / WINDOW
    return rate  # requests per second over the last 60 seconds
```

Let's trace through a real example:

```
Time 14:00:00  → request arrives → deque: [14:00:00]             rate = 1/60 = 0.017 req/s
Time 14:00:01  → request arrives → deque: [14:00:00, 14:00:01]   rate = 2/60 = 0.033 req/s
...normal traffic...
Time 14:01:30  → attacker starts sending 100 req/s
Time 14:01:31  → deque has 100 new entries + a few old ones
               → evict everything before 14:00:31
               → 100 entries remain → rate = 100/60 = 1.67 req/s  ← anomaly detected
```

The window "slides" forward with real time. Old entries fall off the left; new entries pile up on the right. The rate you get is always "how many requests from this IP in the last 60 seconds."

**Why `deque` and not `list`?**

`list.pop(0)` is O(n) — it has to shift every element one position to the left every time you evict. With thousands of entries under a DDoS, this becomes very slow.

`deque.popleft()` is O(1) — it just moves a pointer. No matter how many entries are in the deque, eviction is instant.

Here's the actual implementation from our `detector.py`:

```python
from collections import deque, defaultdict
from dataclasses import dataclass, field

@dataclass
class IPState:
    """All per-IP sliding window state."""
    timestamps: deque = field(default_factory=deque)  # request timestamps
    error_ts: deque = field(default_factory=deque)     # 4xx/5xx timestamps

# One IPState per IP address, created on first request
ip_states = defaultdict(IPState)

# One global window for all traffic combined
global_ts: deque = deque()

def _evict(dq: deque, window: float, now: float):
    """Remove timestamps older than `window` seconds from the left."""
    cutoff = now - window
    while dq and dq[0] < cutoff:
        dq.popleft()

def _rate(dq: deque, window: float) -> float:
    """Requests per second over the window."""
    return len(dq) / window

def process(entry: dict):
    ip = entry["source_ip"]
    now = entry["_parsed_at"]

    state = ip_states[ip]

    # Update per-IP window
    state.timestamps.append(now)
    _evict(state.timestamps, 60, now)
    ip_rate = _rate(state.timestamps, 60)

    # Update global window
    global_ts.append(now)
    _evict(global_ts, 60, now)
    global_rate = _rate(global_ts, 60)
```

We maintain **two separate windows**: one per IP (so we can detect individual attackers) and one global (so we can detect distributed attacks from many IPs). Both are updated on every single request.

---

## Part 3: How the Baseline Learns from Traffic

Detecting anomalies requires knowing what normal looks like. If normal traffic is 50 req/s, then 100 req/s is suspicious. But if normal traffic is 5 req/s, then even 15 req/s might be an attack.

The key insight: **normal changes over time**. A file-sharing platform sees more traffic during business hours than at 3am. A global service sees more traffic from Asia during Asian business hours. You cannot hardcode a threshold — you have to learn it.

### Per-second bucketing

Our baseline engine counts requests per second and stores those counts in a rolling 30-minute window:

```python
from collections import deque
import math
import time
from datetime import datetime

# Stores one count per second, up to 30 minutes worth (1800 buckets)
second_buckets = deque(maxlen=1800)

current_second = int(time.time())
current_count = 0.0

def record(entry: dict):
    global current_second, current_count

    now = entry["_parsed_at"]
    bucket_sec = int(now)

    # When the clock second changes, flush the completed bucket
    if bucket_sec > current_second:
        # Fill any empty seconds (gaps where no traffic arrived)
        for s in range(current_second, bucket_sec):
            second_buckets.append(current_count)
            current_count = 0.0
        current_second = bucket_sec

    current_count += 1.0
```

So if 47 requests arrived in the second ending at 14:05:00, the deque gets `47.0` appended. If the next second was quiet (zero requests), it gets `0.0`. The deque holds up to 1800 of these values — 30 minutes of history.

### Computing mean and standard deviation

Every 60 seconds, we recompute the baseline from whatever is in the bucket deque:

```python
def _recalculate():
    samples = list(second_buckets)
    n = len(samples)

    if n < 30:
        return  # not enough data yet, keep the floor values

    # Mean: average requests per second over the last 30 minutes
    mean = sum(samples) / n

    # Standard deviation: how much does traffic vary?
    variance = sum((x - mean) ** 2 for x in samples) / (n - 1)
    stddev = math.sqrt(variance)

    # Apply floor values to prevent false positives during quiet periods
    mean = max(mean, 1.0)      # never let mean drop below 1 req/s
    stddev = max(stddev, 0.5)  # never let stddev drop below 0.5

    effective_mean = mean
    effective_stddev = stddev
```

**Why do we need floor values?**

Imagine the server is quiet at 3am with 0.1 req/s average. Without floor values:
- mean = 0.1, stddev = 0.05
- A burst to just 0.25 req/s gives z-score = (0.25 - 0.1) / 0.05 = **3.0** → false alarm!

With floor_mean = 1.0:
- The denominator stays reasonable
- You need a genuine spike to trigger detection

**Per-hour preference**

Traffic patterns repeat by hour of day. We also maintain 24 separate per-hour slot deques:

```python
hour_slots = {h: deque(maxlen=1800) for h in range(24)}

# When flushing a bucket, also file it into the current hour's slot
hour = datetime.fromtimestamp(current_second).hour
hour_slots[hour].append(current_count)
```

At recalculation time, if the current hour's slot has at least 30 samples, we use it instead of the 30-minute window. This means 9am traffic is compared to yesterday's 9am baseline, not to the 8:30am baseline — much more accurate.

---

## Part 4: How the Detection Logic Makes a Decision

We have a rate (from the sliding window) and a baseline (mean and stddev). How do we decide if the rate is an attack?

### Z-score: how many standard deviations above normal?

The z-score is a way of asking "how unusual is this number compared to what we normally see?"

```
z-score = (current_rate - baseline_mean) / baseline_stddev
```

If the baseline is mean=5 req/s, stddev=2:
- Current rate 7 req/s → z = (7-5)/2 = **1.0** → normal variation
- Current rate 11 req/s → z = (11-5)/2 = **3.0** → suspicious  
- Current rate 25 req/s → z = (25-5)/2 = **10.0** → attack

We flag anything with z-score > 3.0. In a normal distribution, only 0.13% of values naturally exceed z=3. So a false positive rate of 0.13% is acceptable.

### Multiplier: absolute rate check

Z-score alone has a weakness: if traffic is very consistent (low stddev), even a modest real attack might not produce a high z-score. So we add a second condition:

```
if rate > 5 × mean → flag it
```

If normal is 5 req/s and someone hits 26 req/s, that's more than 5× — flag it regardless of stddev.

Either condition firing triggers the response. Here's the actual detection code:

```python
def _zscore(rate: float, mean: float, stddev: float) -> float:
    if stddev == 0:
        return 0.0
    return (rate - mean) / stddev

def check_anomaly(ip_rate, mean, stddev):
    z_thresh = 3.0   # loaded from config.yaml
    m_thresh = 5.0   # loaded from config.yaml

    ip_z = _zscore(ip_rate, mean, stddev)

    # Either condition triggers the alert
    is_anomaly = (ip_z > z_thresh) or (ip_rate > m_thresh * mean and mean > 0)
    return is_anomaly, ip_z
```

### Error surge tightening

There's a third detection mode for slow attacks. An attacker doing credential stuffing (trying username/password combinations) won't necessarily send huge traffic volumes — but they'll generate lots of 401 Unauthorized responses. 

We track error rates separately:

```python
# If this IP's 4xx/5xx rate is 3× the baseline error rate,
# tighten the thresholds for this IP
if err_rate >= 3.0 * baseline_error_mean:
    z_thresh = 2.0   # lower bar → easier to trigger
    m_thresh = 3.0   # lower bar → easier to trigger
    state.tightened = True
```

This catches slow, stealthy attacks that would otherwise fly under the radar.

### Putting it all together

Here's the full `process()` function that runs on every log line:

```python
def process(self, entry: dict):
    ip = entry["source_ip"]
    now = entry["_parsed_at"]
    status = entry.get("status", 200)

    mean, stddev = self._baseline.get_baseline()

    with self._lock:
        state = self._ip_states[ip]

        # 1. Update sliding windows
        state.timestamps.append(now)
        self._evict(state.timestamps, 60, now)

        self._global_ts.append(now)
        self._evict(self._global_ts, 60, now)

        ip_rate = len(state.timestamps) / 60
        global_rate = len(self._global_ts) / 60

        # 2. Check error surge → tighten thresholds if needed
        if status >= 400:
            state.error_ts.append(now)
        self._evict(state.error_ts, 60, now)
        err_rate = len(state.error_ts) / 60

        z_thresh = 2.0 if state.tightened else 3.0
        m_thresh = 3.0 if state.tightened else 5.0

        # 3. Score and decide
        ip_z = (ip_rate - mean) / stddev if stddev > 0 else 0
        ip_anomaly = (ip_z > z_thresh) or (ip_rate > m_thresh * mean)

        # 4. Fire callback if anomalous (with 10-second cooldown)
        if ip_anomaly:
            last = self._last_fired.get(ip, 0)
            if now - last > 10:
                self._last_fired[ip] = now
                self.on_ip_anomaly(ip, {"ip_rate": ip_rate, "zscore": ip_z, ...})

        # 5. Check global anomaly separately
        g_z = (global_rate - mean) / stddev if stddev > 0 else 0
        if g_z > 3.0 or global_rate > 5.0 * mean:
            if now - self._global_last_fired > 30:
                self._global_last_fired = now
                self.on_global_anomaly({"global_rate": global_rate, ...})
```

When `on_ip_anomaly` fires, it calls the blocker. When `on_global_anomaly` fires, it calls the notifier directly (no ban — you can't ban the whole internet).

---

## Part 5: How iptables Blocks an IP

`iptables` is the Linux kernel's firewall. It processes every network packet that enters or leaves your machine and applies rules to decide what to do with each one.

Think of it like a bouncer at a club. The bouncer has a list of rules:
1. Allow anyone with a VIP pass (ACCEPT)
2. Drop anyone on the blacklist (DROP)
3. Default: let everyone in (ACCEPT)

When we detect an attack from IP `1.2.3.4`, we add a rule to the top of the `INPUT` chain (the chain that handles incoming packets):

```bash
iptables -I INPUT -s 1.2.3.4 -j DROP
```

Breaking this down:
- `-I INPUT` — Insert at the top of the INPUT chain (before other rules)
- `-s 1.2.3.4` — Match packets with source IP 1.2.3.4
- `-j DROP` — Silently drop matching packets (no response sent to attacker)

The `-I` (insert) rather than `-A` (append) is important. Rules are checked top-to-bottom. By inserting at the top, our DROP rule is checked before any ACCEPT rules — the attacker is blocked immediately.

You can verify the rule was added:

```bash
$ iptables -L INPUT -n -v
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  1.2.3.4             0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0           0.0.0.0/0  state RELATED,ESTABLISHED
...
```

Here's the Python code that issues this command:

```python
import subprocess

def _iptables_add(ip: str):
    """Add a DROP rule for this IP. Check first to avoid duplicates."""
    # Check if rule already exists
    check = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    if check.returncode == 0:
        return  # already banned, nothing to do

    # Add the rule
    subprocess.run(
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        check=True,
        capture_output=True
    )

def _iptables_remove(ip: str):
    """Remove the DROP rule. Loop in case it was added more than once."""
    while True:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if result.returncode != 0:
            break  # no more rules for this IP
```

### The backoff schedule

We don't ban forever on the first offence. The ban duration follows a backoff schedule:

| Offence | Duration |
|---------|----------|
| 1st ban | 10 minutes |
| 2nd ban | 30 minutes |
| 3rd ban | 2 hours |
| 4th+ ban | Permanent |

A background thread (the unbanner) wakes up every 30 seconds and checks whether any bans have expired:

```python
import threading
import time

class UnbannerThread(threading.Thread):
    def run(self):
        while not self._stop.wait(30):  # check every 30 seconds
            expired = self._blocker.get_expired_bans()
            for ip in expired:
                record = self._blocker.unban(ip)
                if record:
                    self._notifier.send_unban(record)  # Slack alert

def get_expired_bans(self) -> list[str]:
    now = datetime.utcnow()
    return [
        ip for ip, rec in self._bans.items()
        if rec.expires_at is not None and now >= rec.expires_at
    ]
```

When an IP is unbanned, `iptables -D INPUT -s <ip> -j DROP` removes the rule, and a Slack notification goes out so the team knows the ban was lifted.

---

## Part 6: Slack Alerts

Every ban, unban, and global anomaly sends a Slack message. We use Slack's Incoming Webhooks — a URL you POST JSON to, and it appears as a message in your channel.

```python
import requests
import json

def send_ban(ip: str, info: dict, record):
    text = (
        f":rotating_light: *IP BANNED* — `{ip}`\n"
        f"*Rate:* `{info['ip_rate']:.2f} req/s`  "
        f"*Baseline:* `{info['mean']:.2f}`  "
        f"*Z-score:* `{info['zscore']:.2f}`\n"
        f"*Duration:* `{record.duration_label}`  (ban #{record.ban_count})\n"
        f"*Time:* {timestamp}"
    )
    requests.post(
        webhook_url,
        data=json.dumps({"text": text}),
        headers={"Content-Type": "application/json"},
        timeout=5
    )
```

Critically, Slack calls happen in a **thread pool** — they never block the main detection loop. If Slack is slow or down, we don't miss detecting the next attack:

```python
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=4)

def send_ban_async(ip, info, record):
    executor.submit(_post_to_slack, ip, info, record)
```

---

## Part 7: The Live Dashboard

The dashboard is a Flask web app that serves a single HTML page which polls `/api/metrics` every 3 seconds via JavaScript `fetch()`.

```python
from flask import Flask, jsonify
import psutil

app = Flask(__name__)

@app.route("/api/metrics")
def metrics():
    snap = detector.get_snapshot()
    mean, stddev = baseline.get_baseline()
    banned = blocker.get_banned_ips()

    return jsonify({
        "uptime": get_uptime_string(),
        "global_rate": snap["global_rate"],
        "top_ips": snap["top_ips"],
        "mean": round(mean, 3),
        "stddev": round(stddev, 3),
        "banned": [{"ip": r.ip, "duration": r.duration_label, ...} for r in banned],
        "cpu_pct": psutil.cpu_percent(),
        "mem_pct": psutil.virtual_memory().percent,
        "audit_tail": read_last_20_audit_lines(),
    })
```

The frontend JavaScript refreshes this every 3 seconds and updates the DOM without a full page reload:

```javascript
async function refresh() {
    const r = await fetch('/api/metrics');
    const d = await r.json();

    document.getElementById('global-rate').textContent = d.global_rate.toFixed(2) + ' req/s';
    document.getElementById('mean').textContent = d.mean;

    // Color the rate red if it's approaching the anomaly threshold
    const rateEl = document.getElementById('global-rate');
    rateEl.style.color = d.global_rate > d.mean * 3 ? '#f87171' : '#4ade80';

    // Render banned IPs table
    const bannedRows = d.banned.map(b =>
        `<tr><td>${b.ip}</td><td>${b.duration}</td><td>${b.banned_at}</td></tr>`
    ).join('');
    document.getElementById('banned-table').innerHTML = bannedRows || '<tr><td colspan="3">No active bans ✓</td></tr>';
}

setInterval(refresh, 3000);
refresh(); // immediate first load
```

---

## Part 8: The Audit Log

Every significant event is written to a structured audit log in a format designed to be both human-readable and grep-able:

```
[2026-04-26T14:08:21Z] BAN ip=1.2.3.4 | condition=zscore=4.21 rate=87.3req/s mean=5.2 | rate=87.300 | baseline=5.200 | duration=10m
[2026-04-26T14:18:22Z] UNBAN ip=1.2.3.4 | condition=zscore=4.21 rate=87.3req/s mean=5.2 | rate=87.300 | baseline=5.200 | duration=10m
[2026-04-26T14:07:06Z] BASELINE_RECALC ip=N/A | condition=recalculation | rate=5.200 | baseline=1.100 | duration=N/A
```

You can search these logs:
```bash
# All bans today
grep "BAN " /var/log/detector/audit.log | grep "2026-04-26"

# All recalculations (to see baseline evolution)
grep "BASELINE_RECALC" /var/log/detector/audit.log

# How often was 1.2.3.4 banned?
grep "ip=1.2.3.4" /var/log/detector/audit.log | grep "^.*BAN "
```

---

## Putting It All Together

Here's `main.py` — the entry point that wires every component together:

```python
import queue
import signal
import threading

# 1. Build all components
log_queue = queue.Queue(maxsize=100_000)
monitor = LogMonitor(log_path, log_queue)
baseline = BaselineEngine(cfg)
blocker = BlockerEngine(cfg, audit_path)
notifier = NotifierEngine(cfg)
detector = DetectorEngine(cfg, baseline)

# 2. Wire the anomaly callbacks
def on_ip_anomaly(ip, info):
    if blocker.is_banned(ip):
        return  # already banned, skip
    record = blocker.ban(ip, condition=..., rate=info["ip_rate"], baseline=info["mean"])
    notifier.send_ban(ip, info, record)

def on_global_anomaly(info):
    notifier.send_global_anomaly(info)

detector.on_ip_anomaly = on_ip_anomaly
detector.on_global_anomaly = on_global_anomaly

# 3. Start background threads
monitor.start()
UnbannerThread(blocker, notifier).start()
run_dashboard(host="0.0.0.0", port=8080)

# 4. Main loop — drain queue, feed baseline and detector
while True:
    try:
        entry = log_queue.get(timeout=0.05)
        baseline.record(entry)   # update statistics
        detector.process(entry)  # check for anomalies
    except queue.Empty:
        pass  # no new log lines, loop again
```

The design is intentionally simple: one hot path (queue drain → baseline → detector) runs in the main thread. All I/O — Slack posts, iptables calls, dashboard requests — happens in separate threads and never blocks detection.

---

## What I Learned

Building this from scratch taught me things that using Fail2Ban never would have:

**Deques are the right tool for sliding windows.** The O(1) popleft makes a real difference when you're processing thousands of events per second. A list would have worked fine until the DDoS actually started — which is exactly when you need it to be fast.

**Baselines must have floors.** My first version had no floor values. It triggered constantly at night because the stddev got so low that normal morning traffic looked like an anomaly. One line of code (`mean = max(mean, 1.0)`) fixed it.

**Per-hour slots matter more than you'd think.** Without them, the 30-minute window picks up the tail of the previous hour's traffic and skews the baseline for the current hour. The hour slots give you a cleaner "what does this hour normally look like" answer.

**iptables rules apply to the host kernel, not the container.** The detector container has to run with `network_mode: host` and `CAP_NET_ADMIN`. If you run it in a bridge network and add iptables rules inside the container, those rules only affect traffic inside the container's network namespace — not the actual packets arriving at the server.

**Thread safety is non-negotiable.** The log monitor, the main loop, the Flask dashboard, the unbanner, and the Slack notifier all touch shared state. A `threading.Lock()` around every mutation took 20 minutes to add and saved hours of debugging mysterious state corruption.

---

## Running It Yourself

The full source code is on GitHub: [github.com/your-username/hng-detector](https://github.com/your-username/hng-detector)

To run it on a fresh Ubuntu VPS:

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone and configure
git clone https://github.com/your-username/hng-detector.git
cd hng-detector
cp .env.example .env
nano .env  # add your Slack webhook URL and server IP

# Launch everything
docker compose up -d --build

# Watch the detector work
docker logs -f hng-detector

# Test it with a traffic burst
apt install apache2-utils
ab -n 2000 -c 150 http://localhost/

# Check iptables for the ban
iptables -L INPUT -n -v
```

The dashboard will be live at `http://your-server-ip:8080`.

---

## Conclusion

Security tooling doesn't have to be a black box. The core ideas here — a deque-based sliding window, a rolling statistical baseline, z-score anomaly detection, and iptables for enforcement — are each individually simple. The power comes from wiring them together into a continuously running daemon that never sleeps.

If you're new to security tooling, I hope this post demystified what's happening under the hood of the tools you've always treated as magic. Go build something.

---

*Found this useful? Share it with someone learning DevSecOps. Questions? Drop them in the comments.*
