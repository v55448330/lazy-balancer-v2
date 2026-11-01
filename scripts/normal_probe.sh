#!/bin/sh
# 向 443 测试规则发 3 个普通请求（Host: test.imlazy.app）
apk add curl >/dev/null 2>&1
for i in 1 2 3; do
  curl -sk -o /dev/null -w "%{http_code} " --resolve test.imlazy.app:443:127.0.0.1 "https://test.imlazy.app:443/?normaltest=$i" --max-time 5
done
echo ""
# 等 40s（30s 采集周期 + 余量）后读 overview
sleep 40
TOKEN=$(sqlite3 /app/data/lazy-balancer.db "SELECT 1" >/dev/null 2>&1 && echo "")
# 直接从 metrics 库核对 per-rule 差分与全局行
sqlite3 /app/data/lazy-balancer-metrics.db "SELECT rule_id, MAX(requests_total) FROM metrics_history WHERE timestamp >= datetime('now','-10 minutes') GROUP BY rule_id LIMIT 5;"
