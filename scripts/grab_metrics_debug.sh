#!/bin/sh
apk add curl >/dev/null 2>&1
curl -s http://127.0.0.1:2019/metrics > /tmp/metrics.txt
grep -E "^caddy_http_requests" /tmp/metrics.txt | head -8
echo "----"
grep -E "^lazybalancer_security_requests_total" /tmp/metrics.txt | head -4
echo "----"
grep -cE "^caddy_" /tmp/metrics.txt
