#!/usr/bin/env bash
cd /home/romy/vulnhub
if docker compose ps --format '{{.Name}} {{.State}}' | grep -q 'wpcli running'; then
  docker compose exec -T wpcli wp "$@"
else
  # --entrypoint, because the service's own entrypoint is `tail -f /dev/null`
  # (it is meant to sit idle and be exec'd into). Without this the wp args are
  # appended to that tail and the container hangs until it is killed.
  docker compose run --rm -T --entrypoint wp wpcli "$@"
fi
