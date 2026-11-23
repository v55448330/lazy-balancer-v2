#!/usr/bin/env bash
# 发布产物包含性验证（R-17）：构建推送后、宣告发布成功前，必须在运行容器内
# 逐项核验本批次每个用户可感知修复的特征串。任何一项零命中 = 发布失败。
# 用法: scripts/verify-release-artifacts.sh <容器名> [期望 commit]
# 期望 commit 缺省取当前仓库 HEAD（终验容器必须由该提交构建）；显式传入可用于
# 在异机核对（如 CI 产物）。特征串清单随每批次更新（来源=该批次 diff 中用户
# 可感知的改动）。
set -u
CONTAINER="${1:?usage: $0 <container> [expected-commit]}"
EXPECTED_COMMIT="${2:-$(git rev-parse HEAD 2>/dev/null || true)}"
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
# 二进制特征核验（R-17 第 2 条：UI 资产 + 二进制逐项 grep）：后端 JSON 键是
# 产线构建幸存的字面量（struct tag 不受压缩影响），与 UI 侧同一特征串互为印证。
check_bin "today_detected_tcp" "总览检测列 TCP 拆分字段（后端 struct tag）"
# 特征串选串规则：只允许产线构建幸存的字面量（API JSON 键、用户可见文案）；
# 压缩混淆会改写局部标识符（todayDetectedSplit/heatLegendTicks 即误选例）。
# 批次身份由 build-info.json 的 commit 字段承载（必须=本批次 commit）。

# 构建戳必须存在且非空（stale dist 探测：无 build-info = dist 未随批次重建）
if docker exec "$CONTAINER" sh -c 'test -s /app/ui/build-info.json'; then
  echo "  ✓ build-info.json 在场: $(docker exec "$CONTAINER" cat /app/ui/build-info.json | head -c 120)"
  # commit 必须等于期望提交（旧脚本只确认文件存在/非空：旧 dist 或错批次
  # 产物同样「在场」，R-17 批次身份核验形同虚设）。比较 12 位短 hash。
  ACTUAL_COMMIT="$(docker exec "$CONTAINER" cat /app/ui/build-info.json 2>/dev/null \
    | grep -o '"commit"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | grep -o '[0-9a-f]\{12\}' | head -1 || true)"
  if [[ -z "$EXPECTED_COMMIT" ]]; then
    echo "  ✗ 无法确定期望 commit（非 git 工作树且未显式传入），无法核对批次身份"; fail=1
  elif [[ "$ACTUAL_COMMIT" != "${EXPECTED_COMMIT:0:12}" ]]; then
    echo "  ✗ build-info commit=${ACTUAL_COMMIT:-MISSING} ≠ 期望 ${EXPECTED_COMMIT:0:12}（dist 非本批次构建）"; fail=1
  else
    echo "  ✓ build-info commit == ${EXPECTED_COMMIT:0:12}"
  fi
else
  echo "  ✗ build-info.json 缺失（dist 疑似过期/未构建）"; fail=1
fi

exit "$fail"
