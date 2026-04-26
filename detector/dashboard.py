"""
dashboard.py
------------
Flask application serving the live metrics dashboard at port 8080.

The UI auto-refreshes every 3 seconds using a <meta http-equiv="refresh"> tag
and JavaScript fetch() against the /api/metrics JSON endpoint.

Metrics shown:
  - Uptime
  - Global req/s (current and baseline)
  - Effective mean / stddev
  - Top 10 source IPs
  - Banned IPs with duration and ban count
  - CPU / memory usage
  - Audit log tail (last 20 lines)
"""

import time
import os
import psutil
import threading
import logging
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger(__name__)

_START_TIME = time.time()

# Shared references — set by main.py after construction
_detector = None
_baseline = None
_blocker = None
_audit_path = ""


def init(detector, baseline, blocker, audit_path):
    global _detector, _baseline, _blocker, _audit_path
    _detector = detector
    _baseline = baseline
    _blocker = blocker
    _audit_path = audit_path


app = Flask(__name__)


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/metrics")
def metrics():
    snap = _detector.get_snapshot() if _detector else {}
    mean, stddev = _baseline.get_baseline() if _baseline else (0, 0)
    banned = _blocker.get_banned_ips() if _blocker else []

    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()

    uptime_sec = int(time.time() - _START_TIME)
    h, rem = divmod(uptime_sec, 3600)
    m, s = divmod(rem, 60)
    uptime = f"{h:02d}:{m:02d}:{s:02d}"

    banned_list = [
        {
            "ip": r.ip,
            "ban_count": r.ban_count,
            "duration": r.duration_label,
            "banned_at": r.banned_at.strftime("%H:%M:%S UTC"),
            "condition": r.condition,
        }
        for r in banned
    ]

    audit_tail = _tail_audit(20)

    return jsonify({
        "uptime": uptime,
        "global_rate": snap.get("global_rate", 0),
        "top_ips": snap.get("top_ips", []),
        "mean": round(mean, 3),
        "stddev": round(stddev, 3),
        "banned": banned_list,
        "cpu_pct": cpu,
        "mem_pct": round(mem.percent, 1),
        "mem_used_mb": round(mem.used / 1024 / 1024, 1),
        "audit_tail": audit_tail,
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    })


def _tail_audit(n: int) -> list[str]:
    if not _audit_path or not os.path.exists(_audit_path):
        return []
    try:
        with open(_audit_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        return [l.rstrip() for l in lines[-n:]]
    except OSError:
        return []


def run_dashboard(host: str, port: int):
    """Run Flask in a daemon thread."""
    t = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        name="Dashboard",
        daemon=True,
    )
    t.start()
    logger.info("Dashboard running at http://%s:%d", host, port)
    return t


# ---------------------------------------------------------------------------
# HTML template — single-file, auto-refreshing, dark/light responsive
# ---------------------------------------------------------------------------
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HNG Anomaly Detector — Live Metrics</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
    --danger: #f87171; --warn: #fbbf24; --ok: #4ade80;
    --mono: 'JetBrains Mono', 'Fira Mono', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif;
         font-size: 14px; line-height: 1.6; }
  header { background: var(--card); border-bottom: 1px solid var(--border);
           padding: 14px 24px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 18px; font-weight: 600; color: var(--accent); }
  header .pill { background: var(--ok); color: #052e16; border-radius: 999px;
                 padding: 2px 10px; font-size: 12px; font-weight: 600; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
          gap: 16px; padding: 20px 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
          padding: 16px; }
  .card h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em;
             color: var(--muted); margin-bottom: 8px; }
  .big { font-size: 36px; font-weight: 700; color: var(--accent); }
  .sub { font-size: 12px; color: var(--muted); margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; }
  th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
       color: var(--muted); padding: 4px 8px; text-align: left; border-bottom: 1px solid var(--border); }
  td { padding: 5px 8px; border-bottom: 1px solid var(--border); font-family: var(--mono);
       font-size: 12px; }
  tr:last-child td { border-bottom: none; }
  .banned-ip { color: var(--danger); }
  .ok-val { color: var(--ok); }
  .warn-val { color: var(--warn); }
  .audit { font-family: var(--mono); font-size: 11px; color: var(--muted);
           max-height: 220px; overflow-y: auto; white-space: pre; line-height: 1.5; }
  .audit .ban  { color: var(--danger); }
  .audit .unban { color: var(--ok); }
  .audit .recalc { color: var(--accent); }
  .full { grid-column: 1 / -1; }
  #ts { font-size: 11px; color: var(--muted); margin-left: auto; }
  .bar-wrap { background: var(--border); border-radius: 4px; height: 6px; margin-top: 6px; }
  .bar { height: 6px; border-radius: 4px; background: var(--accent); transition: width 0.4s; }
</style>
</head>
<body>
<header>
  <h1>&#9632; HNG Anomaly Detector</h1>
  <span class="pill" id="status">LIVE</span>
  <span id="ts">—</span>
</header>

<div class="grid" id="grid">
  <!-- Stat cards -->
  <div class="card"><h2>Global req/s</h2><div class="big" id="global-rate">—</div>
    <div class="sub" id="baseline-sub">mean — | stddev —</div></div>

  <div class="card"><h2>Uptime</h2><div class="big" id="uptime">—</div>
    <div class="sub">daemon running</div></div>

  <div class="card"><h2>CPU</h2><div class="big" id="cpu">—</div>
    <div class="bar-wrap"><div class="bar" id="cpu-bar" style="width:0%"></div></div></div>

  <div class="card"><h2>Memory</h2><div class="big" id="mem">—</div>
    <div class="bar-wrap"><div class="bar" id="mem-bar" style="width:0%"></div></div></div>

  <!-- Banned IPs -->
  <div class="card full"><h2>Banned IPs (<span id="ban-count">0</span>)</h2>
    <table><thead><tr><th>IP</th><th>Ban#</th><th>Duration</th><th>Banned at</th><th>Condition</th></tr></thead>
    <tbody id="ban-tbody"><tr><td colspan="5" style="color:var(--ok);text-align:center">No active bans</td></tr></tbody></table>
  </div>

  <!-- Top IPs -->
  <div class="card"><h2>Top 10 Source IPs (req/s, 60s window)</h2>
    <table><thead><tr><th>IP</th><th>Rate</th></tr></thead>
    <tbody id="top-tbody"></tbody></table>
  </div>

  <!-- Audit log -->
  <div class="card"><h2>Audit log (last 20 events)</h2>
    <div class="audit" id="audit">—</div>
  </div>
</div>

<script>
async function refresh() {
  try {
    const r = await fetch('/api/metrics');
    const d = await r.json();

    document.getElementById('ts').textContent = d.timestamp;
    document.getElementById('global-rate').textContent = d.global_rate.toFixed(2) + ' req/s';
    document.getElementById('baseline-sub').textContent =
      `mean ${d.mean} | stddev ${d.stddev}`;
    document.getElementById('uptime').textContent = d.uptime;
    document.getElementById('cpu').textContent = d.cpu_pct.toFixed(1) + '%';
    document.getElementById('mem').textContent = d.mem_pct.toFixed(1) + '%';
    document.getElementById('cpu-bar').style.width = d.cpu_pct + '%';
    document.getElementById('mem-bar').style.width = d.mem_pct + '%';

    // Banned IPs
    document.getElementById('ban-count').textContent = d.banned.length;
    const bt = document.getElementById('ban-tbody');
    if (d.banned.length === 0) {
      bt.innerHTML = '<tr><td colspan="5" style="color:var(--ok);text-align:center">No active bans ✓</td></tr>';
    } else {
      bt.innerHTML = d.banned.map(b =>
        `<tr><td class="banned-ip">${b.ip}</td><td>${b.ban_count}</td>
         <td class="warn-val">${b.duration}</td><td>${b.banned_at}</td>
         <td>${b.condition}</td></tr>`
      ).join('');
    }

    // Top IPs
    const tt = document.getElementById('top-tbody');
    tt.innerHTML = d.top_ips.map(([ip, rate]) =>
      `<tr><td>${ip}</td><td class="${rate > d.mean * 3 ? 'warn-val' : 'ok-val'}">${rate.toFixed(3)}</td></tr>`
    ).join('');

    // Audit log
    const auditDiv = document.getElementById('audit');
    const colored = d.audit_tail.map(line => {
      if (line.includes('] BAN '))   return `<span class="ban">${line}</span>`;
      if (line.includes('] UNBAN ')) return `<span class="unban">${line}</span>`;
      if (line.includes('BASELINE_RECALC')) return `<span class="recalc">${line}</span>`;
      return line;
    }).join('\n');
    auditDiv.innerHTML = colored || '(no events yet)';
    auditDiv.scrollTop = auditDiv.scrollHeight;

  } catch(e) {
    document.getElementById('status').textContent = 'DISCONNECTED';
    document.getElementById('status').style.background = 'var(--danger)';
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""
