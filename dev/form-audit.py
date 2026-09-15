#!/usr/bin/env python3
"""Does pressing Apply keep the filter you arrived with?

A GET form submits its own fields and nothing else. Arriving at a list from a
chart and then narrowing it used to throw the chart's filter away silently and
answer a different question. This logs in, lands on each list the way a chart
would, rebuilds exactly what the browser would submit, and reports anything the
round trip loses.

    python3 dev/form-audit.py
"""
import os, re, subprocess, sys, urllib.parse
from pathlib import Path

BASE = "http://localhost:8093"
ROOT = Path(__file__).resolve().parent.parent
JAR  = "/tmp/vh-form-audit-jar"

subprocess.run(
    ["curl", "-s", "-c", JAR, "-b", JAR, "-d",
     f"log={os.environ.get('WP_ADMIN_USER','admin')}&pwd={(ROOT / '.admin_pass').read_text().strip()}"
     f"&wp-submit=Log+In&redirect_to={BASE}/wp-admin/&testcookie=1",
     "-o", "/dev/null", f"{BASE}/wp-login.php"],
    check=True,
)

def get(url):
    return subprocess.run(["curl", "-s", "-b", JAR, url],
                          capture_output=True, text=True).stdout

def filter_form(html):
    found = re.findall(r'<form class="vh-filters".*?</form>', html, re.S)
    return found[0] if found else ""

def total(html):
    m = re.search(r"<strong>([\d,]+)</strong>", html)
    return m.group(1) if m else "?"

# Each case: land here (as a chart would), then change this control.
CASES = [
    ("/vulnerabilities/?state=open_any&route=edge&poc=1",   "severity",   "critical"),
    ("/vulnerabilities/?state=open_any&route=user&poc=1",   "asset_type", "workstation"),
    ("/vulnerabilities/?state=open_any&patch_available=0",  "severity",   "high"),
    ("/assets/?coverage=gap&location_id=25",                "asset_type", "workstation"),
    ("/assets/?eol=win11-24h2",                             "asset_type", "workstation"),
    ("/assets/?coverage=gap&primary_source=cmdb",           "asset_type", "server"),
    ("/assets/?location_id=none&coverage=gap",              "asset_type", "workstation"),
    ("/assets/?location_id=25",                             "coverage",   "gap"),
    ("/assets/?life=retired_all",                           "asset_type", "workstation"),
    ("/tickets/?status_category=done",                      "search",     ""),
    ("/exceptions/?status=approved",                        "status",     "approved"),
]

failures = []

for start, field, value in CASES:
    html = get(BASE + start)
    form = filter_form(html)

    if not form:
        failures.append(f"{start}\n    no filter form on the page at all")
        continue

    submitted = dict(re.findall(
        r'<input type="hidden" name="([^"]+)" value="([^"]*)">', form))

    for name, body in re.findall(r'<select name="([^"]+)"[^>]*>(.*?)</select>', form, re.S):
        chosen = re.search(r'<option value="([^"]*)"[^>]*selected', body)
        submitted[name] = chosen.group(1) if chosen else ""

    for name, val in re.findall(r'<input type="search" name="([^"]+)" value="([^"]*)"', form):
        submitted[name] = val

    for name in re.findall(r'<input type="checkbox" name="([^"]+)"[^>]*checked', form):
        submitted[name] = "1"

    if value:
        submitted[field] = value

    # Only an empty value is "not submitted". "0" is a real answer here --
    # patch_available=0 means "no vendor fix exists", which is the single most
    # useful filter on the screen, and dropping it was this harness's own bug
    # before it was ever the app's. team_id=0 is the "all teams" sentinel.
    submitted = {k: v for k, v in submitted.items() if v != ""}
    submitted.pop("team_id", None) if submitted.get("team_id") == "0" else None

    arrived = urllib.parse.parse_qs(start.split("?", 1)[1])
    lost    = [k for k in arrived if k not in submitted]

    after = get(BASE + start.split("?")[0] + "?" + urllib.parse.urlencode(submitted))

    status = "ok " if not lost else "LOST"
    print(f"{status} {start}")
    print(f"     {total(html)} rows -> apply {field}={value or '(unchanged)'} -> {total(after)} rows")

    if lost:
        print(f"     dropped by the form: {', '.join(lost)}")
        failures.append(f"{start} drops {', '.join(lost)} on Apply")

print()

if failures:
    print("FAILURES")
    for f in failures:
        print("  " + f)
    sys.exit(1)

print("Every filter survives a round trip through the form.")
