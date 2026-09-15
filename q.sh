#!/usr/bin/env bash
/home/romy/vulnhub/wp.sh db query 2>&1 | grep -v 'ssl-verify-server-cert'
