#!/usr/bin/env bash
# 发布产物包含性验证（R-17）：构建推送后、宣告发布成功前，必须在运行容器内
# 逐项核验本批次每个用户可感知修复的特征串。任何一项零命中 = 发布失败。
# 用法: scripts/verify-release-artifacts.sh <容器名>
# 特征串清单随每批次更新（来源=该批次 diff 中用户可感知的改动）。
set -u
CONTAINER="${1:?usage: $0 <container>}"
fail=0

check_asset() { # $1=特征串 $2=说明
  if docker exec "$CONTAINER" sh -c "grep -rls '$1' /app/ui/assets/ 2>/dev/null" | grep -q .; then
    echo "  ✓ ui: $2"
  else
    echo "  ✗ ui 缺失: $2（特征串 $1）"; fail=1
  fi
}
check_bin() { # $1=特征串 $2=说明
  if docker exec "$CONTAINER" sh -c "grep -aq '$1' /app/lazy-balancer 2>/dev/null || grep -aq '$1' /usr/local/bin/lazy-balancer 2>/dev/null"; then
    echo "  ✓ bin: $2"
  else
    echo "  ✗ bin 缺失: $2（特征串 $1）"; fail=1
  fi
}

echo "R-17 发布产物包含性验证（${CONTAINER}）"
check_asset "today_detected_tcp" "总览检测列 TCP 拆分字段"
# 特征串选串规则：只允许产线构建幸存的字面量（API JSON 键、用户可见文案）；
# 压缩混淆会改写局部标识符（todayDetectedSplit/heatLegendTicks 即误选例）。
# 批次身份由 build-info.json 的 commit 字段承载（必须=本批次 commit）。

# 构建戳必须存在且非空（stale dist 探测：无 build-info = dist 未随批次重建）
if docker exec "$CONTAINER" sh -c 'test -s /app/ui/build-info.json'; then
  echo "  ✓ build-info.json 在场: $(docker exec "$CONTAINER" cat /app/ui/build-info.json | head -c 120)"
else
  echo "  ✗ build-info.json 缺失（dist 疑似过期/未构建）"; fail=1
fi

exit "$fail"
