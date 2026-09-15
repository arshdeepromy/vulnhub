#!/bin/bash
# Log in to WordPress with curl and fetch every VulnHub screen, reporting
# PHP errors, HTTP status and a content fingerprint for each.
#
# Usage: ./check-pages.sh [extra-path ...]

set -uo pipefail
cd "$(dirname "$0")"

BASE="${VULNHUB_URL:-http://localhost:8093}"
USER="${WP_ADMIN_USER:-admin}"
PASS="$(cat .admin_pass)"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# --- log in ---------------------------------------------------------------
login=$(curl -s -c "$JAR" -b "$JAR" \
  -d "log=${USER}&pwd=${PASS}&wp-submit=Log+In&redirect_to=${BASE}/wp-admin/&testcookie=1" \
  -o /dev/null -w '%{http_code}' \
  "${BASE}/wp-login.php")

if ! grep -q wordpress_logged_in "$JAR"; then
  echo "LOGIN FAILED (http $login)"
  exit 1
fi
echo "logged in as ${USER}"
echo

PAGES=(
  "/wp-admin/admin.php?page=vulnhub"
  "/wp-admin/admin.php?page=vulnhub-findings"
  "/wp-admin/admin.php?page=vulnhub-findings&severity=critical&state=open_any"
  "/wp-admin/admin.php?page=vulnhub-assets"
  "/wp-admin/admin.php?page=vulnhub-assets&needs_user=1"
  "/wp-admin/admin.php?page=vulnhub-ownership"
  "/wp-admin/admin.php?page=vulnhub-ownership&tab=unresolved"
  "/wp-admin/admin.php?page=vulnhub-ownership&tab=teams"
  "/wp-admin/admin.php?page=vulnhub-ownership&tab=people"
  "/wp-admin/admin.php?page=vulnhub-tickets"
  "/wp-admin/admin.php?page=vulnhub-exceptions"
  "/wp-admin/admin.php?page=vulnhub-exceptions&new=1"
  "/wp-admin/admin.php?page=vulnhub-integrations"
  "/wp-admin/admin.php?page=vulnhub-sync"
  "/wp-admin/admin.php?page=vulnhub-audit"
  "/wp-admin/admin.php?page=vulnhub-settings"
  "/wp-admin/plugins.php"
  "/"
)
PAGES+=("$@")

fail=0
for path in "${PAGES[@]}"; do
  body=$(curl -s -b "$JAR" -w '\n@@HTTP:%{http_code}' "${BASE}${path}")
  code=$(printf '%s' "$body" | tail -1 | sed 's/@@HTTP://')
  html=$(printf '%s' "$body" | sed '$d')
  bytes=${#html}

  errs=$(printf '%s' "$html" | grep -oE '(Fatal error|Parse error|Warning</b>|Notice</b>|Deprecated</b>|Uncaught [A-Za-z]+)[^<]{0,160}' | head -4)

  status="OK  "
  if [ "$code" != "200" ]; then status="HTTP"; fail=1; fi
  if [ -n "$errs" ]; then status="ERR "; fail=1; fi
  if [ "$bytes" -lt 800 ]; then status="THIN"; fail=1; fi

  printf '%s %-4s %6sB  %s\n' "$status" "$code" "$bytes" "$path"
  if [ -n "$errs" ]; then
    printf '%s\n' "$errs" | sed 's/^/       > /'
  fi
done

echo
if [ -s wp/wp-content/debug.log ]; then
  echo "--- debug.log (last 30) ---"
  tail -30 wp/wp-content/debug.log
else
  echo "debug.log clean"
fi

exit $fail

