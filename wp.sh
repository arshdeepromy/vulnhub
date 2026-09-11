#!/usr/bin/env bash
cd "$( dirname "$( readlink -f "$0" )" )"
if docker compose ps --format '{{.Name}} {{.State}}' | grep -q 'wpcli running'; then
  docker compose exec -T wpcli wp "$@"
else
  docker compose run --rm -T wpcli wp "$@"
fi
