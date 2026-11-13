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
#   --push-channel  beta|stable：beta=只推测试 tag（不更新 latest）；stable=推正式 tag+latest
#   --skip-cloud    跳过 buildx 推送与远端断言（仅本地构建+容器对账）
#   --keep-bench    保留压测容器（默认清理）
#
# 每步产出机器可判定输出；任一步失败立即退出非零（set -e + 显式检查）。
set -euo pipefail

TAG="" CHANNEL="" SKIP_CLOUD=0 DRY_RUN=0 SELF_TEST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --push-channel) CHANNEL="$2"; shift 2;;
    --skip-cloud) SKIP_CLOUD=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --self-test) SELF_TEST=1; shift;;
    *) echo "未知参数: $1"; exit 2;;
  esac
done
# release_image_tags 按通道产出镜像 tag 清单（latest 归属单源，供 --self-test 离线断言）。
# 2026-11-13 用户裁定：latest 恒指向最新正式版——stable 推 <tag>+latest；
# beta 只推 <tag>，绝不更新 latest（此前无条件双推，beta 会顶掉 latest，与
# README「latest 指向最近稳定版」承诺漂移）。
release_image_tags() {
  local tag="$1" channel="$2"
  local tags="v55448330/lazy-balancer-v2:$tag"
  if [[ "$channel" == "stable" ]]; then
    tags="$tags v55448330/lazy-balancer-v2:latest"
  fi
  printf '%s' "$tags"
}

# validate_release_channel 通道与 tag 形态一致性硬门：stable 必须无通道后缀
# （否则 beta tag 会被推成 latest）；beta 必须带 -beta 后缀（防正式版误走测试通道）。
validate_release_channel() {
  local tag="$1" channel="$2"
  case "$channel" in
    stable)
      [[ "$tag" == *-beta ]] && { echo "通道冲突：--push-channel stable 但 tag=$tag 带 -beta 后缀（会把测试版推成 latest）" >&2; return 1; }
      ;;
    beta)
      [[ "$tag" != *-beta ]] && { echo "通道冲突：--push-channel beta 但 tag=$tag 无 -beta 后缀" >&2; return 1; }
      ;;
    *) echo "未知通道：${channel}（仅 beta|stable）" >&2; return 1;;
  esac
  return 0
}

# self_test 离线断言 latest 通道门（不构建/不推送/不写盘）。
self_test() {
  local fail=0 out
  out="$(release_image_tags v2.4.5 stable)"
  [[ "$out" == "v55448330/lazy-balancer-v2:v2.4.5 v55448330/lazy-balancer-v2:latest" ]] || { echo "SELFTEST FAIL: stable 应推 tag+latest，got '$out'" >&2; fail=1; }
  out="$(release_image_tags v2.4.5-beta beta)"
  [[ "$out" == "v55448330/lazy-balancer-v2:v2.4.5-beta" ]] || { echo "SELFTEST FAIL: beta 不应推 latest，got '$out'" >&2; fail=1; }
  # 通道/tag 一致性门：stable 配 -beta、beta 配正式 tag 都必须拒绝。
  validate_release_channel v2.4.5 stable >/dev/null 2>&1 || { echo "SELFTEST FAIL: stable+正式 tag 应通过" >&2; fail=1; }
  validate_release_channel v2.4.5-beta beta >/dev/null 2>&1 || { echo "SELFTEST FAIL: beta+-beta tag 应通过" >&2; fail=1; }
  if validate_release_channel v2.4.5-beta stable >/dev/null 2>&1; then echo "SELFTEST FAIL: stable+-beta tag 应拒绝" >&2; fail=1; fi
  if validate_release_channel v2.4.5 beta >/dev/null 2>&1; then echo "SELFTEST FAIL: beta+正式 tag 应拒绝" >&2; fail=1; fi
  if [[ "$fail" == "0" ]]; then echo "SELFTEST: OK（latest 仅 stable 推送）"; fi
  return "$fail"
}
if [[ "$SELF_TEST" == "1" ]]; then self_test; exit $?; fi

# 通道/tag 一致性门先于 dry-run：预览也必须反映真实拒绝（stable+-beta 等冲突）。
if [[ -n "$TAG" && -n "$CHANNEL" ]]; then
  validate_release_channel "$TAG" "$CHANNEL" || exit 2
fi

# --dry-run 只读预览：仅打印将执行的步骤清单与当前基线读数，不构建/不部署/
# 不推送/不写盘（批量改写门禁要求遍历型脚本必须带只读模式）。
if [[ "$DRY_RUN" == "1" ]]; then
  echo "DRY-RUN 预览（未执行任何写操作）："
  echo "  tag=$TAG channel=$CHANNEL skip-cloud=$SKIP_CLOUD"
  echo "  镜像 tag 清单：$(release_image_tags "${TAG:-<tag>}" "${CHANNEL:-<channel>}")"
  echo "  步骤清单：①HEAD/dist 基线对账 → ②npm run build → ③Dockerfile 解析自检 → ④compose 本地构建+部署+env 抽查 → ⑤buildx 双架构推送(--skip-cloud 跳过) → ⑥一次性容器终验"
  echo "  当前 dist 戳：$(python3 -c "import json;print(json.load(open('web/dist/build-info.json'))['commit'][:12])" 2>/dev/null || echo MISSING)"
  echo "  当前 HEAD　：$(git rev-parse --short=12 HEAD 2>/dev/null || echo MISSING)"
  exit 0
fi
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
  fail "dist 构建戳=$DIST_STAMP ≠ HEAD=${HEAD}（cd web && npm run build 后再跑本脚本）"
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
LOCAL_BI="$(docker exec lazy-balancer sh -c 'grep -o "\"commit\": \"[^\"]*\"" /app/ui/build-info.json' 2>/dev/null | head -1 | grep -o '[0-9a-f]\{12\}' | head -1 || echo MISSING)"
[[ "$LOCAL_BI" == "${HEAD:0:12}" ]] && pass "本地构建戳 == HEAD" || fail "本地构建戳=$LOCAL_BI ≠ HEAD（dist 未随重建）"

# ── ⑤ buildx 双架构推送（--skip-cloud 跳过）──
if [[ "$SKIP_CLOUD" == "1" ]]; then
  step "⑤ buildx 推送（--skip-cloud 跳过）"
else
  step "⑤ buildx 双架构推送"
  PROXY_ARGS=""
  [[ -n "${HTTP_PROXY:-}" ]] && PROXY_ARGS="HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY"
  # latest 归属由 release_image_tags 单源决定（stable 才推 latest；beta 只推 tag）。
  IMAGE_TAGS="$(release_image_tags "$TAG" "$CHANNEL")"
  TAG_ARGS=""
  for t in $IMAGE_TAGS; do TAG_ARGS="$TAG_ARGS -t \"$t\""; done
  ( eval "$PROXY_ARGS docker buildx build --builder lazy-builder --platform linux/amd64,linux/arm64 --provenance=false --sbom=false --build-arg VERSION=\"${TAG%%-*}\" $TAG_ARGS --push . > /tmp/finalize-push.log 2>&1" ) \
    && pass "buildx 推送成功（${IMAGE_TAGS}）" || fail "buildx 推送失败（见 /tmp/finalize-push.log）"
  # 推送后强拉对账（daemon 缓存可能 stale）；拉取失败不终止——⑥ 一次性容器
  # 终验才是权威判据（无代理环境 pull 走直连可能失败）。
  ( $PROXY_ARGS docker pull -q "v55448330/lazy-balancer-v2:$TAG" > /dev/null 2>&1 ) || fail "强拉对账失败（不影响已推送镜像；⑥ 终验以本地 tag 为准）"
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
V_BI="$(docker exec lb-finalize sh -c 'grep -o "\"commit\": \"[^\"]*\"" /app/ui/build-info.json | head -1' 2>/dev/null | grep -o '[0-9a-f]\{12\}' | head -1 || echo MISSING)"
[[ "$V_BI" == "${HEAD:0:12}" ]] && pass "终验构建戳 == HEAD" || fail "终验构建戳=$V_BI ≠ HEAD"
( docker rm -f lb-finalize > /dev/null 2>&1 )

# ── 汇总 ──
echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
  echo "FINALIZE: 全部通过（${TAG:-<empty>}，channel=${CHANNEL:-<empty>}）"
  exit 0
else
  echo "FINALIZE: ${#FAILURES[@]} 项失败"
  for f in ${FAILURES[@]+"${FAILURES[@]}"}; do echo "  ✗ $f"; done
  exit 1
fi
