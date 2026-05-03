"""
analytics_routes.py
-------------------
Add these routes to app.py (or import and register as a Blueprint).
Reads ids_data/raw_logs/cowrie_raw.jsonl directly — no upload needed.

Usage in app.py:
    from analytics_routes import analytics_bp
    app.register_blueprint(analytics_bp)
"""

from flask import Blueprint, jsonify, request
from collections import defaultdict
from datetime import datetime, timezone
import json, os, re

analytics_bp = Blueprint('analytics', __name__)

# LOG_PATH = os.path.join(os.getcwd(), "ids_data", "raw_logs", "cowrie_raw.jsonl")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_PATH = os.path.join(
    BASE_DIR,
    "ids_data",
    "raw_logs",
    "cowrie_raw.jsonl"
)
print("Resolved LOG_PATH:", LOG_PATH)
print("File exists:", os.path.exists(LOG_PATH))
# ─── Log Reader ───────────────────────────────────────────────────────────────

def read_logs(path=LOG_PATH):
    """Read and parse cowrie JSONL log file. Returns list of dicts."""
    events = []
    if not os.path.exists(path):
        return events
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


# ─── Analyser ─────────────────────────────────────────────────────────────────

def analyse(events):
    """Single-pass analysis of all cowrie events."""
    total = len(events)
    sessions = set()
    unique_ips = set()
    login_attempts = 0
    successful_logins = 0
    commands_run = 0

    # Per-IP intelligence
    ip_data = defaultdict(lambda: {
        "sessions": set(),
        "login_attempts": 0,
        "successes": 0,
        "commands": 0,
        "passwords": defaultdict(int),
        "usernames": defaultdict(int),
        "first_seen": None,
        "last_seen": None,
        "events": [],
    })

    # Time-series buckets (hourly)
    timeline = defaultdict(int)
    event_type_counts = defaultdict(int)

    for e in events:
        eid = e.get("eventid", "")
        src = e.get("src_ip", "unknown")
        sess = e.get("session", "")
        ts_raw = e.get("timestamp", "")

        unique_ips.add(src)
        if sess:
            sessions.add(sess)

        # Timestamp
        ts = None
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except Exception:
            pass

        # Update first/last seen
        if ts:
            d = ip_data[src]
            if d["first_seen"] is None or ts < d["first_seen"]:
                d["first_seen"] = ts
            if d["last_seen"] is None or ts > d["last_seen"]:
                d["last_seen"] = ts
            hour_key = ts.strftime("%Y-%m-%d %H:00")
            timeline[hour_key] += 1

        if sess:
            ip_data[src]["sessions"].add(sess)

        # Event-type breakdown
        short = eid.split(".")[-1] if "." in eid else eid
        event_type_counts[eid] += 1

        # Store abbreviated event for IP drilldown
        ip_data[src]["events"].append({
            "eventid": eid,
            "timestamp": ts_raw,
            "session": sess,
            "input": e.get("input"),
            "username": e.get("username"),
            "password": e.get("password"),
            "message": e.get("message", ""),
        })

        if eid in ("cowrie.login.failed", "cowrie.login.success"):
            login_attempts += 1
            ip_data[src]["login_attempts"] += 1
            pwd = e.get("password", "")
            usr = e.get("username", "")
            if pwd:
                ip_data[src]["passwords"][pwd] += 1
            if usr:
                ip_data[src]["usernames"][usr] += 1

        if eid == "cowrie.login.success":
            successful_logins += 1
            ip_data[src]["successes"] += 1

        if eid == "cowrie.command.input":
            commands_run += 1
            ip_data[src]["commands"] += 1

    # Build IP intelligence rows
    ip_table = []
    for ip, d in ip_data.items():
        sess_count = len(d["sessions"])
        la = d["login_attempts"]
        succ = d["successes"]
        cmds = d["commands"]
        top_pwds = sorted(d["passwords"].items(), key=lambda x: -x[1])[:5]

        # Threat level logic
        if succ > 0:
            threat = "BREACH"
        elif la >= 20 or cmds > 5:
            threat = "HIGH"
        elif la >= 5:
            threat = "MEDIUM"
        else:
            threat = "LOW"

        ip_table.append({
            "ip": ip,
            "sessions": sess_count,
            "login_attempts": la,
            "successes": succ,
            "commands": cmds,
            "threat": threat,
            "first_seen": d["first_seen"].isoformat() if d["first_seen"] else None,
            "last_seen": d["last_seen"].isoformat() if d["last_seen"] else None,
            "top_passwords": [{"pwd": p, "count": c} for p, c in top_pwds],
            "top_usernames": sorted(d["usernames"].items(), key=lambda x: -x[1])[:3],
        })

    ip_table.sort(key=lambda x: (x["threat"] == "BREACH", x["threat"] == "HIGH",
                                  x["login_attempts"] + x["commands"]), reverse=True)

    # Top attackers for bar chart
    top_ips = sorted(ip_table, key=lambda x: x["login_attempts"] + x["commands"], reverse=True)[:10]

    # Top passwords overall
    all_passwords = defaultdict(int)
    for d in ip_data.values():
        for p, c in d["passwords"].items():
            all_passwords[p] += c
    top_passwords = sorted(all_passwords.items(), key=lambda x: -x[1])[:10]

    # Event type breakdown for doughnut
    event_types_simplified = {
        "connect": 0, "login_failed": 0, "login_success": 0,
        "command": 0, "closed": 0, "other": 0
    }
    for eid, cnt in event_type_counts.items():
        if "session.connect" in eid:
            event_types_simplified["connect"] += cnt
        elif "login.failed" in eid:
            event_types_simplified["login_failed"] += cnt
        elif "login.success" in eid:
            event_types_simplified["login_success"] += cnt
        elif "command.input" in eid:
            event_types_simplified["command"] += cnt
        elif "session.closed" in eid:
            event_types_simplified["closed"] += cnt
        else:
            event_types_simplified["other"] += cnt

    return {
        "summary": {
            "total_events": total,
            "total_sessions": len(sessions),
            "login_attempts": login_attempts,
            "commands_run": commands_run,
            "unique_ips": len(unique_ips),
            "successful_logins": successful_logins,
        },
        "timeline": [{"time": k, "count": v} for k, v in sorted(timeline.items())],
        "event_types": [{"type": k, "count": v} for k, v in event_types_simplified.items() if v > 0],
        "top_ips": top_ips,
        "top_passwords": [{"password": p, "count": c} for p, c in top_passwords],
        "ip_table": ip_table,
        "raw_events": events,  # for raw log endpoint
    }


# ─── Cache (re-parse at most every 10 s) ─────────────────────────────────────

_cache = {"ts": 0, "data": None}

def get_analysis():
    import time
    now = time.time()
    if now - _cache["ts"] > 10 or _cache["data"] is None:
        events = read_logs()
        _cache["data"] = analyse(events)
        _cache["ts"] = now
    return _cache["data"]


# ─── API Endpoints ────────────────────────────────────────────────────────────

@analytics_bp.route("/api/analytics/summary")
def analytics_summary():
    return jsonify(get_analysis()["summary"])


@analytics_bp.route("/api/analytics/timeline")
def analytics_timeline():
    return jsonify(get_analysis()["timeline"])


@analytics_bp.route("/api/analytics/event_types")
def analytics_event_types():
    return jsonify(get_analysis()["event_types"])


@analytics_bp.route("/api/analytics/top_ips")
def analytics_top_ips():
    return jsonify(get_analysis()["top_ips"])


@analytics_bp.route("/api/analytics/top_passwords")
def analytics_top_passwords():
    return jsonify(get_analysis()["top_passwords"])


@analytics_bp.route("/api/analytics/ip_table")
def analytics_ip_table():
    return jsonify(get_analysis()["ip_table"])


@analytics_bp.route("/api/analytics/ip_detail")
def analytics_ip_detail():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "ip param required"}), 400
    data = get_analysis()
    for row in data["ip_table"]:
        if row["ip"] == ip:
            # attach session timeline
            events = [e for e in data["raw_events"] if e.get("src_ip") == ip]
            events.sort(key=lambda e: e.get("timestamp", ""))
            return jsonify({"info": row, "events": events})
    return jsonify({"error": "IP not found"}), 404


@analytics_bp.route("/api/analytics/raw_logs")
def analytics_raw_logs():
    limit = request.args.get("limit", 200, type=int)
    event_filter = request.args.get("event_type", "")
    search = request.args.get("search", "").lower()
    events = get_analysis()["raw_events"]
    if event_filter:
        events = [e for e in events if event_filter in e.get("eventid", "")]
    if search:
        events = [e for e in events if search in json.dumps(e).lower()]
    # newest first
    events = sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)
    return jsonify(events[:limit])