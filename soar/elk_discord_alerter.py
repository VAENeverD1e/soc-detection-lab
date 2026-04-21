#!/usr/bin/env python3
"""
ELK -> Discord SOAR Alerter
Polls Elastic Security for new High/Critical alerts
and forwards them to a Discord webhook.

Usage:
  python elk_discord_alerter.py          # run in polling mode
  python elk_discord_alerter.py --test   # test connections only

Environment variables required:
  DISCORD_WEBHOOK   your Discord webhook URL
  ELK_API_KEY       base64 API key from Kibana
  ELK_URL           Kibana base URL (default: http://192.168.31.130:5601)
"""

import os
import sys
import time
import re
import requests
from datetime import datetime, timezone, timedelta
from collections import deque

# ── Config ─────────────────────────────────────────────────────────────
DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK")
ELK_API_KEY     = os.environ.get("ELK_API_KEY")
ELK_URL         = os.environ.get("ELK_URL", "http://192.168.31.130:5601")
POLL_INTERVAL   = 60        # seconds between polls
SEVERITIES      = ["medium", "high", "critical"]
LOOK_BACK_MIN   = 2         # look back N minutes each poll cycle
SEEN_IDS_MAX    = 1000      # FIX #3: cap seen_ids to avoid unbounded memory growth

# Strict MITRE technique ID pattern: T followed by 4 digits, optional .NNN suffix
_MITRE_RE = re.compile(r'^T\d{4}(\.\d{3})?$')


# ── Validate env vars ──────────────────────────────────────────────────
def check_env():
    missing = []
    if not DISCORD_WEBHOOK: missing.append("DISCORD_WEBHOOK")
    if not ELK_API_KEY:     missing.append("ELK_API_KEY")
    if missing:
        print(f"[ERROR] Missing environment variables: {', '.join(missing)}")
        sys.exit(1)


# ── Query ELK for recent alerts ────────────────────────────────────────
def fetch_alerts(look_back_minutes=2):
    since = (
        datetime.now(timezone.utc) - timedelta(minutes=look_back_minutes)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = {
        "query": {
            "bool": {
                "filter": [
                    {"terms": {"kibana.alert.severity": SEVERITIES}},
                    {"range":  {"@timestamp": {"gte": since}}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 20
    }

    url = f"{ELK_URL}/api/detection_engine/signals/search"
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"ApiKey {ELK_API_KEY}",
        "kbn-xsrf":      "true"
    }

    try:
        resp = requests.post(url, headers=headers, json=query, timeout=10)
        resp.raise_for_status()
        return resp.json().get("hits", {}).get("hits", [])
    except requests.exceptions.ConnectionError:
        print(f"[{now()}] ERROR: Cannot reach ELK at {ELK_URL}")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"[{now()}] ELK HTTP error: {e}")
        return []


# ── Extract a field that may be flat ("a.b.c") or nested ({"a":{"b":{}}}) ──
def _get(src, dotted_key, default=None):
    """
    Try flat key first  → src["host.name"]
    Then nested access  → src["host"]["name"]
    Returns default if neither exists.
    """
    # 1. flat key (common in Kibana security alerts index)
    if dotted_key in src:
        return src[dotted_key]

    # 2. nested traversal
    parts = dotted_key.split(".")
    val = src
    for part in parts:
        if not isinstance(val, dict):
            return default
        val = val.get(part)
        if val is None:
            return default
    return val if val is not None else default


# ── Build Discord embed from an ELK alert ─────────────────────────────
def build_embed(alert):
    src = alert.get("_source", {})

    # ── Rule name ──────────────────────────────────────────────────────
    rule_name = (
        _get(src, "kibana.alert.rule.name")
        or _get(src, "signal.rule.name", "Unknown rule")
    )

    # ── Severity ───────────────────────────────────────────────────────
    severity = (
        _get(src, "kibana.alert.severity")
        or _get(src, "signal.rule.severity", "unknown")
    ).upper()

    # ── Hostname: FIX #1 — try flat key first, then nested dict ────────
    hostname = (
        _get(src, "host.name")          # flat: "host.name" → "desktop-thonlnr"
        or _get(src, "host.hostname")   # flat alternative
        or _get(src, "host.ip")         # flat IP fallback
        or "Unknown host"
    )

    timestamp = src.get("@timestamp", now())
    alert_id  = alert.get("_id", "")[:8]

    # ── MITRE: FIX #2 — try structured threat obj (flat + nested) then tags ──
    technique_id = "Unknown"

    # kibana.alert.rule.threat is a list of threat objects
    threats = _get(src, "kibana.alert.rule.threat") or _get(src, "signal.rule.threat") or []
    if isinstance(threats, list) and threats:
        techniques = threats[0].get("technique", [])
        if isinstance(techniques, list) and techniques:
            technique_id = techniques[0].get("id", "Unknown")

    # FIX #5 — strict regex fallback, not loose startswith + len check
    if technique_id == "Unknown":
        tags = _get(src, "kibana.alert.rule.tags") or _get(src, "signal.rule.tags") or []
        for tag in tags:
            if _MITRE_RE.match(tag):
                technique_id = tag
                break

    # ── Colours ────────────────────────────────────────────────────────
    colour_map = {
        "CRITICAL": 0x8B0000,
        "HIGH":     0xE24B4A,
        "MEDIUM":   0xEF9F27,
        "LOW":      0x378ADD,
    }
    colour = colour_map.get(severity, 0x888780)

    return {
        "title":       f"🚨 ELK Alert — {severity}",
        "description": f"**{rule_name}**",
        "color":       colour,
        "fields": [
            {"name": "MITRE Technique", "value": f"`{technique_id}`", "inline": True},
            {"name": "Severity",        "value": severity,            "inline": True},
            {"name": "Host",            "value": hostname,            "inline": True},
            {"name": "Timestamp",       "value": timestamp,           "inline": False},
            {"name": "Rule",            "value": rule_name,           "inline": False},
            {"name": "Alert ID",        "value": f"`{alert_id}...`",  "inline": True},
            {"name": "Kibana Alerts",
             "value": f"[View in Kibana]({ELK_URL}/app/security/alerts)",
             "inline": True},
        ],
        "footer":    {"text": "SOC Lab SOAR · ELK Discord Alerter"},
        "timestamp": timestamp,
    }


# ── Post embed to Discord ──────────────────────────────────────────────
def post_discord(embed):
    try:
        resp = requests.post(
            DISCORD_WEBHOOK, json={"embeds": [embed]}, timeout=10
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"[{now()}] Discord POST failed: {e}")
        return False


# ── Send a plain status message to Discord ────────────────────────────
def post_test_message():
    payload = {
        "content": (
            f"✅ **ELK Alerter is online and connected.**\n"
            f"Polling ELK at `{ELK_URL}` every `{POLL_INTERVAL}s`\n"
            f"Watching for: **{', '.join(s.upper() for s in SEVERITIES)}** alerts"
        )
    }
    resp = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
    resp.raise_for_status()


# ── Helpers ────────────────────────────────────────────────────────────
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Test mode ──────────────────────────────────────────────────────────
def run_test():
    print(f"[{now()}] Running connection test...")
    alerts = fetch_alerts(look_back_minutes=1440)   # last 24h
    print(f"[{now()}] ELK connection OK — {len(alerts)} alerts found in last 24h")

    # FIX #4: error handling for Discord test message
    print(f"[{now()}] Sending test message to Discord...")
    try:
        post_test_message()
        print(f"[{now()}] Done. Check your Discord server.")
    except Exception as e:
        print(f"[{now()}] ERROR: Failed to post to Discord — {e}")
        sys.exit(1)


# ── Main polling loop ──────────────────────────────────────────────────
def run_poller():
    # FIX #3: deque with maxlen caps memory at SEEN_IDS_MAX entries
    seen_ids = deque(maxlen=SEEN_IDS_MAX)
    seen_ids_set = set()

    print(f"[{now()}] ELK Alerter started. Polling every {POLL_INTERVAL}s...")
    print(f"[{now()}] Watching for: {', '.join(s.upper() for s in SEVERITIES)} alerts")
    print(f"[{now()}] ELK: {ELK_URL}")

    while True:
        alerts     = fetch_alerts(look_back_minutes=LOOK_BACK_MIN)
        new_alerts = [a for a in alerts if a["_id"] not in seen_ids_set]

        if new_alerts:
            print(f"[{now()}] {len(new_alerts)} new alert(s) — sending to Discord...")
            for alert in new_alerts:
                embed = build_embed(alert)
                if post_discord(embed):
                    aid = alert["_id"]
                    # evict oldest if at capacity
                    if len(seen_ids) == SEEN_IDS_MAX:
                        seen_ids_set.discard(seen_ids[0])
                    seen_ids.append(aid)
                    seen_ids_set.add(aid)
                    print(f"[{now()}] ✓ Posted alert {aid[:8]}...")
        else:
            print(f"[{now()}] 0 new alerts this cycle.")

        time.sleep(POLL_INTERVAL)


# ── Entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":
    check_env()
    if "--test" in sys.argv:
        run_test()
    else:
        run_poller()
