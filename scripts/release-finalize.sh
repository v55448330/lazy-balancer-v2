#!/usr/bin/env bash
# release-finalize.sh — 发版/覆盖推送收尾统一对账脚本（结构性机制，替代记忆驱动收尾）
#
# 背景（2026-11-05 实证形态，每条都真实发生过）：
#   ① GC env 提交只推 git 漏推镜像 → Registry 落后 HEAD
#   ② npm build 在 commit 前跑 → dist 构建戳落后 HEAD 一档
#   ③ Dockerfile 注释误插无 # 前缀 → 解析失败 → 两次推送实为旧缓存层
#   ④ GOMEMLIMIT=6g 格式错（Go 只认 GiB/MiB 全称）→ 容器启动即崩
#   ⑤ 徽标主题与 versions.json 主题两处手工维护 → 漂移
#   ⑥ 半边修复（tools.go 修了 server.go 没修等）连续多轮 carried
#
# 用法：
#   ./scripts/release-finalize.sh --tag v2.4.2-beta --push-channel beta [--skip-cloud]
#   --tag           必填：本次发布的镜像 tag（如 v2.4.2-beta）
#   --push-channel  beta|stable：beta=只推测试 tag；stable=推正式 tag+latest
#   --skip-cloud    跳过 buildx 推送与远端断言（仅本地构建+容器对账）
#   --keep-bench    保留压测容器（默认清理）
#
# 每步产出机器可判定输出；任一步失败立即退出非零（set -e + 显式检查）。
set -euo pipefail

TAG="" CHANNEL="" SKIP_CLOUD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --push-channel) CHANNEL="$2"; shift 2;;
    --skip-cloud) SKIP_CLOUD=1; shift;;
    *) echo "未知参数: $1"; exit 2;;
  esac
done
[[ -n "$TAG" && -n "$CHANNEL" ]] || { echo "用法: --tag vX.Y.Z[-beta] --push-channel beta|stable [--skip-cloud]"; exit 2; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
FAILURES=()

step() { echo ""; echo "=== $1 ==="; }
pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; FAILURES+=("$1"); }

# ── ① 基线：HEAD 干净且 dist 构建戳 == HEAD ──
step "① 基线对账（HEAD/dist/tag）"
HEAD="$(git rev-parse HEAD)"
git diff --quiet HEAD || fail "工作树不干净：存在未提交变更"
DIST_STAMP="$(python3 -c "import json;print(json.load(open('web/dist/build-info.json'))['commit'])" 2>/dev/null || echo MISSING)"
if [[ "$DIST_STAMP" == "$HEAD" ]]; then
  pass "dist 构建戳 == HEAD ($HEAD)"
else
  fail "dist 构建戳=$DIST_STAMP ≠ HEAD=$HEAD（cd web && npm run build 后再跑本脚本）"
fi

# ── ② 前端构建（保证 dist 与 HEAD 一致）──
step "② 前端构建"
( cd web && npm run build > /tmp/finalize-fe.log 2>&1 ) && pass "npm run build 成功" || fail "npm run build 失败（见 /tmp/finalize-fe.log）"
DIST_STAMP2="$(python3 -c "import json;print(json.load(open('web/dist/build-info.json'))['commit'])" 2>/dev/null || echo MISSING)"
[[ "$DIST_STAMP2" == "$HEAD" ]] && pass "重建后 dist 构建戳 == HEAD" || fail "重建后 dist 构建戳=$DIST_STAMP2 ≠ HEAD"

# ── ③ Dockerfile 解析自检（注释误插/断链即红）──
step "③ Dockerfile 解析自检"
if command -v docker > /dev/null; then
  ( docker buildx build --check . > /tmp/finalize-dfcheck.log 2>&1 ) \
    && pass "docker buildx --check 通过" \
    || fail "Dockerfile 解析失败（见 /tmp/finalize-dfcheck.log）——检查误插入的无 # 注释行/断链"
else
  fail "docker 不可用"
fi

# ── ④ compose 本地构建+部署+env 抽查 ──
step "④ compose 本地构建+部署"
( docker compose build > /dev/null 2>&1 ) && pass "compose build 成功" || fail "compose build 失败"
( docker compose up -d > /dev/null 2>&1 ) && pass "compose up 成功" || fail "compose up 失败"
sleep 25
LOCAL_HEALTH="$(docker inspect lazy-balancer --format '{{.State.Health.Status}}' 2>/dev/null || echo down)"
[[ "$LOCAL_HEALTH" == "healthy" ]] && pass "主节点 healthy" || fail "主节点=$LOCAL_HEALTH"
LOCAL_GOGC="$(docker exec lazy-balancer sh -c 'echo $GOGC' 2>/dev/null || echo '')"
[[ "$LOCAL_GOGC" == "300" ]] && pass "GOGC=300 生效" || fail "GOGC='$LOCAL_GOGC' ≠ 300"
LOCAL_LIMIT="$(docker exec lazy-balancer sh -c 'echo $GOMEMLIMIT' 2>/dev/null || echo '')"
[[ "$LOCAL_LIMIT" == "1500MiB" ]] && pass "GOMEMLIMIT=1500MiB 生效" || fail "GOMEMLIMIT='$LOCAL_LIMIT' ≠ 1500MiB"
LOCAL_BI="$(docker exec lazy-balancer sh -c 'grep -o "\"commit\": \"[^\"]*\"" /app/ui/build-info.json' 2>/dev/null | head -1 | grep -o '[0-9a-f]\{12\}' || echo MISSING)"
[[ "$LOCAL_BI" == "${HEAD:0:12}" ]] && pass "本地构建戳 == HEAD" || fail "本地构建戳=$LOCAL_BI ≠ HEAD（dist 未随重建）"

# ── ⑤ buildx 双架构推送（--skip-cloud 跳过）──
if [[ "$SKIP_CLOUD" == "1" ]]; then
  step "⑤ buildx 推送（--skip-cloud 跳过）"
else
  step "⑤ buildx 双架构推送"
  PROXY_ARGS=""
  [[ -n "${HTTP_PROXY:-}" ]] && PROXY_ARGS="HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY"
  ( eval "$PROXY_ARGS docker buildx build --builder lazy-builder --platform linux/amd64,linux/arm64 --provenance=false --sbom=false --build-arg VERSION=\"${TAG%%-*}\" -t \"v55448330/lazy-balancer-v2:$TAG\" --push . > /tmp/finalize-push.log 2>&1" ) \
    && pass "buildx 推送成功" || fail "buildx 推送失败（见 /tmp/finalize-push.log）"
  # 推送后强拉对账（daemon 缓存可能 stale）
  ( $PROXY_ARGS docker pull -q "v55448330/lazy-balancer-v2:$TAG" > /dev/null 2>&1 )
fi

# ── ⑥ 一次性容器终验（env/构建戳/健康）──
step "⑥ 一次性容器终验"
( docker rm -f lb-finalize > /dev/null 2>&1; docker run -d --rm --name lb-finalize -p 18092:8000 "v55448330/lazy-balancer-v2:$TAG" > /dev/null ) \
  && pass "lb-finalize 启动" || fail "lb-finalize 启动失败"
sleep 40
V_HEALTH="$(docker inspect lb-finalize --format '{{.State.Health.Status}}' 2>/dev/null || echo down)"
[[ "$V_HEALTH" == "healthy" ]] && pass "终验容器 healthy" || fail "终验容器=$V_HEALTH"
V_GOGC="$(docker exec lb-finalize sh -c 'echo $GOGC' 2>/dev/null || echo '')"
V_LIMIT="$(docker exec lb-finalize sh -c 'echo $GOMEMLIMIT' 2>/dev/null || echo '')"
[[ "$V_GOGC" == "300" && "$V_LIMIT" == "1500MiB" ]] && pass "GOGC/GOMEMLIMIT env 生效" || fail "GC env=$V_GOGC/$V_LIMIT"
V_BI="$(docker exec lb-finalize sh -c 'grep -o "\"commit\": \"[^\"]*\"" /app/ui/build-info.json | head -1' 2>/dev/null | grep -o '[0-9a-f]\{12\}' || echo MISSING)"
[[ "$V_BI" == "${HEAD:0:12}" ]] && pass "终验构建戳 == HEAD" || fail "终验构建戳=$V_BI ≠ HEAD"
( docker rm -f lb-finalize > /dev/null 2>&1 )

# ── 汇总 ──
echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
  echo "FINALIZE: 全部通过（$TAG，channel=$CHANNEL）"
  exit 0
else
  echo "FINALIZE: ${#FAILURES[@]} 项失败"
  for f in "${FAILURES[@]}"; do echo "  ✗ $f"; done
  exit 1
fi
