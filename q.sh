#!/usr/bin/env bash
"$( dirname "$( readlink -f "$0" )" )"/wp.sh db query 2>&1 | grep -v 'ssl-verify-server-cert'
