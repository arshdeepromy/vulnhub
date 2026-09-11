#!/bin/bash
# Lint every PHP file in the VulnHub plugins inside the WordPress container.
docker compose exec -T wordpress bash -c '
fail=0
for f in $(find /var/www/html/wp-content/plugins/vulnhub-* -name "*.php" -not -name "*.bak" 2>/dev/null); do
  out=$(php -l "$f" 2>&1)
  if [ $? -ne 0 ]; then
    echo "FAIL: ${f#/var/www/html/wp-content/plugins/}"
    echo "$out" | head -3
    fail=1
  fi
done
[ $fail -eq 0 ] && echo "ALL PHP FILES OK"
'
