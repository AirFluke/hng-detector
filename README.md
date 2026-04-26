# HNG Anomaly Detection Engine

A real-time HTTP traffic anomaly detector and DDoS response daemon built alongside Nextcloud on Docker, using Python.

## Live Links

> Fill in after deployment:
- **Metrics Dashboard:** `http://your-domain.com:8080` or `http://dashboard.your-domain.com`
- **Server IP (Nextcloud):** `http://your.server.ip`
- **GitHub Repo:** `https://github.com/your-username/hng-detector`
- **Blog Post:** `https://dev.to/your-username/...`

---

## Language Choice

**Python** — chosen for:
- `collections.deque` gives O(1) append and popleft, which is exactly what a sliding window needs
- `threading` module is sufficient for I/O-bound daemon work
- `psutil` makes CPU/memory stats trivial
- Flask gives a zero-config dashboard server
- Readable for the blog post audience

---

## How the Sliding Window Works

Each IP and the global stream each have their own `collections.deque` of **raw timestamps** (floats from `time.time()`).

```
deque: [t₁, t₂, t₃, ... tₙ]   (no maxlen — we evict by age, not count)
```

**On every new request:**
1. `deque.append(now)` — O(1), adds to the right
2. `while deque[0] < now - 60: deque.popleft()` — O(k) where k is the number of entries older than 60 seconds (usually 0-1)
3. `rate = len(deque) / 60` — req/s over the last 60 seconds

This is a **true sliding window** — not a per-minute counter, not a leaky bucket. Every entry carries its exact timestamp, and the window boundary slides forward with real time. The deque stays compact because old entries are evicted immediately.

**Why deque and not a list?**
`list.pop(0)` is O(n) — it shifts every element left. `deque.popleft()` is O(1). Under a DDoS with thousands of IPs sending hundreds of requests per second, this matters.

---

## How the Baseline Works

**Window size:** 30 minutes (1800 per-second buckets)

**Per-second accumulation:**
The baseline engine counts requests per second by watching the clock. When the clock second changes, the completed bucket (`_current_count`) is appended to `_second_buckets` (a deque with `maxlen=1800`) and the counter resets.

**Recalculation interval:** Every 60 seconds, mean and stddev are computed from whatever is in `_second_buckets`:
```
mean   = sum(buckets) / n
stddev = sqrt(sum((x - mean)² for x in buckets) / (n - 1))
```

**Per-hour slots:** Each second's count is also filed into `_hour_slots[current_hour]`. When the current hour has ≥ 30 samples, we prefer its statistics over the 30-minute window — this captures diurnal patterns (quiet nights, busy afternoons).

**Floor values:**
- `floor_mean = 1.0` — baseline mean never falls below 1 req/s. Without this, a quiet night produces a near-zero mean and a z-score of 3 fires on 4 req/s — a false positive.
- `floor_stddev = 0.5` — prevents division by near-zero stddev

**Audit log entry on each recalc:**
```
[2024-01-15T14:30:00Z] BASELINE_RECALC ip=N/A | condition=recalculation | rate=12.450 | baseline=2.100 | duration=N/A
```

---

## Detection Logic

Two conditions, either fires the alert:

| Condition | Formula | Threshold |
|-----------|---------|-----------|
| Z-score | `(rate - mean) / stddev > 3.0` | zscore_threshold = 3.0 |
| Multiplier | `rate > 5.0 × mean` | multiplier_threshold = 5.0 |

**Error surge tightening:** If an IP's 4xx/5xx rate in the last 60 seconds exceeds `3× error_mean`, both thresholds tighten:
- Z-score threshold → 2.0
- Multiplier → 3.0

This catches slow credential-stuffing attacks that fly under normal rate thresholds.

**Per-IP vs global:** Both windows are checked on every request. Per-IP anomalies trigger an iptables ban. Global anomalies (distributed traffic from many IPs) trigger a Slack alert only.

**10-second cooldown:** An IP cannot trigger a second alert within 10 seconds of the first. This prevents the ban loop from firing hundreds of times during a burst.

---

## How iptables Blocking Works

When a per-IP anomaly fires:

1. `blocker.ban(ip, ...)` is called from the detector callback
2. The blocker runs:
   ```bash
   iptables -I INPUT -s <ip> -j DROP
   ```
   (`-I` inserts at the top of the chain, ahead of ACCEPT rules)
3. A `BanRecord` is stored in memory with the expiry time
4. The unbanner thread wakes every 30 seconds, finds expired bans, and runs:
   ```bash
   iptables -D INPUT -s <ip> -j DROP
   ```

**Backoff schedule** (ban_count determines slot):
| Ban # | Duration |
|-------|----------|
| 1st   | 10 minutes |
| 2nd   | 30 minutes |
| 3rd   | 2 hours |
| 4th+  | Permanent |

Permanent bans are never released by the unbanner. Manual intervention required:
```bash
iptables -D INPUT -s <ip> -j DROP
```

---

## Setup: Fresh VPS to Fully Running Stack

### 1. Provision a VPS

Minimum: 2 vCPU, 2 GB RAM. Ubuntu 22.04 LTS recommended.

### 2. Install Docker and Docker Compose

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Docker Compose v2 (comes with Docker Desktop / plugin)
docker compose version
```

### 3. Clone the repository

```bash
git clone https://github.com/your-username/hng-detector.git
cd hng-detector
```

### 4. Configure environment

```bash
cp .env.example .env
nano .env   # fill in SERVER_IP, passwords, SLACK_WEBHOOK_URL
```

### 5. Point a domain at your VPS (for the dashboard)

Add a DNS A record: `dashboard.yourdomain.com → your.server.ip`

Then set up a lightweight nginx vhost on the host (outside Docker) to proxy port 8080, or simply expose port 8080 directly and use `http://your.server.ip:8080`.

### 6. Start the stack

```bash
docker compose up -d --build
```

### 7. Verify everything is running

```bash
# All containers healthy?
docker compose ps

# Nginx writing JSON logs?
docker exec hng-nginx cat /var/log/nginx/hng-access.log | head -5

# Detector reading logs?
docker logs hng-detector --tail 50

# Dashboard reachable?
curl http://localhost:8080/api/metrics
```

### 8. Test anomaly detection locally

```bash
# Simulate a burst from a single IP using wrk or ab
wrk -t4 -c100 -d30s http://your.server.ip/

# Or with Apache Bench
ab -n 5000 -c 200 http://your.server.ip/

# Watch detector logs
docker logs -f hng-detector

# Check iptables
sudo iptables -L INPUT -n -v
```

---

## Repository Structure

```
hng-detector/
├── detector/
│   ├── main.py         Entry point; wires all components
│   ├── monitor.py      Tail + parse nginx JSON log
│   ├── baseline.py     Rolling 30-min baseline (mean/stddev)
│   ├── detector.py     Sliding window + z-score anomaly detection
│   ├── blocker.py      iptables DROP + audit log
│   ├── unbanner.py     Backoff unban schedule
│   ├── notifier.py     Slack webhook notifications
│   ├── dashboard.py    Flask live metrics UI
│   ├── config.yaml     All thresholds (no hardcoded values)
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   └── nginx.conf
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Configuration Reference (`detector/config.yaml`)

All detection thresholds are in `config.yaml`. No values are hardcoded in Python.

| Key | Default | Description |
|-----|---------|-------------|
| `sliding_window.ip_window_seconds` | 60 | Per-IP deque time window |
| `sliding_window.global_window_seconds` | 60 | Global deque time window |
| `baseline.rolling_window_minutes` | 30 | How far back the baseline looks |
| `baseline.recalculation_interval_seconds` | 60 | How often baseline is recomputed |
| `baseline.floor_mean` | 1.0 | Minimum effective mean |
| `detection.zscore_threshold` | 3.0 | Z-score anomaly trigger |
| `detection.multiplier_threshold` | 5.0 | Rate multiplier trigger |
| `detection.error_surge_multiplier` | 3.0 | Error surge detection |
| `blocking.ban_schedule_minutes` | [10,30,120,-1] | Backoff schedule |

---

## Blog Post

👉 [Read the beginner-friendly blog post here](https://dev.to/your-username/how-i-built-a-ddos-detection-engine-from-scratch)
