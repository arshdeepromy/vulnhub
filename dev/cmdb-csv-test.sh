#!/bin/bash
# Exercise the vulnhub-cmdb CSV import through the real admin HTTP flow:
# log in, upload the sample file, read the dry-run preview, then import.
set -uo pipefail
cd "$(dirname "$0")/.."

BASE="http://localhost:8093"
USER="romy"
PASS="$(cat .admin_pass)"
JAR="$(mktemp)"
CSV="wp/wp-content/plugins/vulnhub-cmdb/data/sample-cmdb.csv"
trap 'rm -f "$JAR"' EXIT

curl -s -c "$JAR" -b "$JAR" \
  -d "log=${USER}&pwd=${PASS}&wp-submit=Log+In&redirect_to=${BASE}/wp-admin/&testcookie=1" \
  -o /dev/null "${BASE}/wp-login.php"
grep -q wordpress_logged_in "$JAR" || { echo "LOGIN FAILED"; exit 1; }
echo "logged in"

page=$(curl -s -b "$JAR" "${BASE}/wp-admin/admin.php?page=vulnhub-cmdb&tab=csv")
upload_nonce=$(printf '%s' "$page" | grep -o 'name="_wpnonce" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
[ -n "$upload_nonce" ] || { echo "NO UPLOAD NONCE"; exit 1; }
echo "upload nonce: ${upload_nonce:0:6}…"

echo "--- rejecting a bogus upload (binary content, .csv name) ---"
printf 'PK\x03\x04\x00\x00binary\x00junk' > /tmp/vh-bogus.csv
bogus=$(curl -s -L -b "$JAR" -c "$JAR" \
  -F "action=vulnhub_cmdb_upload" -F "_wpnonce=${upload_nonce}" \
  -F "vh_cmdb_file=@/tmp/vh-bogus.csv;type=text/csv" \
  "${BASE}/wp-admin/admin-post.php")
printf '%s' "$bogus" | grep -o 'notice-error[^<]*<p>[^<]*' | head -1 | sed 's/.*<p>/  rejected: /'
rm -f /tmp/vh-bogus.csv

echo "--- uploading the sample file ---"
page=$(curl -s -b "$JAR" "${BASE}/wp-admin/admin.php?page=vulnhub-cmdb&tab=csv")
upload_nonce=$(printf '%s' "$page" | grep -o 'name="_wpnonce" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')

out=$(curl -s -L -b "$JAR" -c "$JAR" -w '\n@@HTTP:%{http_code}\n@@URL:%{url_effective}' \
  -F "action=vulnhub_cmdb_upload" -F "_wpnonce=${upload_nonce}" \
  -F "vh_cmdb_file=@${CSV};type=text/csv" \
  "${BASE}/wp-admin/admin-post.php")

code=$(printf '%s' "$out" | grep '@@HTTP:' | sed 's/@@HTTP://')
url=$(printf '%s' "$out" | grep '@@URL:' | sed 's/@@URL://')
html=$(printf '%s' "$out" | sed '/@@HTTP:/,$d')
echo "  http ${code}"
echo "  landed on: ${url}"
printf '%s' "$html" | grep -oE '(Fatal error|Parse error|Warning</b>|Notice</b>|Deprecated</b>|Uncaught [A-Za-z]+)[^<]{0,140}' | head -3 | sed 's/^/  PHP: /'
printf '%s' "$html" | grep -o 'notice-success[^<]*<p>[^<]*' | head -1 | sed 's/.*<p>/  notice: /'

echo "--- dry run summary from the preview screen ---"
printf '%s' "$html" | grep -A3 -E '<h2>(Rows parsed|Would create|Would update|Rejected)</h2>' \
  | grep -oE '<h2>[^<]+</h2>|vh-card__value">[^<]+' \
  | sed 's/<h2>/  /;s/<\/h2>//;s/vh-card__value">/    = /'

token=$(printf '%s' "$html" | grep -o 'name="vh_cmdb_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
import_nonce=$(printf '%s' "$html" | grep -B4 'value="vulnhub_cmdb_import"' | grep -o 'name="_wpnonce" value="[^"]*"' | tail -1 | sed 's/.*value="//;s/"//')
if [ -z "$import_nonce" ]; then
  import_nonce=$(printf '%s' "$html" | grep -A6 'vulnhub_cmdb_import' | grep -o 'name="_wpnonce" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
fi
echo "  token: ${token:0:8}…  import nonce: ${import_nonce:0:6}…"
[ -n "$token" ] && [ -n "$import_nonce" ] || { echo "MISSING TOKEN/NONCE"; exit 1; }

echo "--- importing ---"
imported=$(curl -s -L -b "$JAR" -c "$JAR" \
  -d "action=vulnhub_cmdb_import" -d "_wpnonce=${import_nonce}" -d "vh_cmdb_token=${token}" \
  "${BASE}/wp-admin/admin-post.php")
printf '%s' "$imported" | grep -o 'notice-[a-z]*[^<]*<p>[^<]*' | head -1 | sed 's/.*<p>/  result: /'
printf '%s' "$imported" | grep -oE '(Fatal error|Parse error|Uncaught [A-Za-z]+)[^<]{0,140}' | head -3 | sed 's/^/  PHP: /'

echo "--- import without a nonce must be refused ---"
curl -s -o /dev/null -w '  http %{http_code}\n' -b "$JAR" \
  -d "action=vulnhub_cmdb_import" -d "vh_cmdb_token=${token}" \
  "${BASE}/wp-admin/admin-post.php"

echo "done"

