#!/usr/bin/env bash
# 启动链门禁自检（scripts/check-startup-chain.sh 的鉴别力）。
#
# 门禁本身也是代码：语法面 `sh -n` 与语义面（exec 目标 ∈ 镜像路径清单）都必须
# 在「注入缺陷后」判红，否则它会退化成永远打印 ok 的装饰。四个用例：
#   A) 基线：真实仓库文件 → rc=0（防门禁自己假红）
#   B) 语法错误（SH1 形态）→ rc≠0
#   C) exec 目标拼错（SH2 形态）→ rc≠0（`sh -n` 对此恒绿，是本门的存在理由）
#   D) 非 git 工作树（SH3 形态）→ rc≠0（清单来源失败必须 fail-closed，
#      旧实现在进程替换里静默得到空清单：0 检查 + rc=0）
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
gate="$repo_root/scripts/check-startup-chain.sh"

work="$(mktemp -d "${TMPDIR:-/tmp}/lb-startup-gate.XXXXXX")"
trap 'rm -rf "$work"' EXIT

baseline_entry="$work/docker-entrypoint.sh"
cp "$repo_root/docker-entrypoint.sh" "$baseline_entry"

fail() {
  echo "FAIL [startup gate selftest] $*" >&2
  exit 1
}

# ── A) 基线：不得假红 ───────────────────────────────────────────────
if ! bash "$gate" >/dev/null 2>"$work/a.err"; then
  cat "$work/a.err" >&2
  fail "基线（真实仓库文件）必须通过"
fi

# ── B) 语法错误必须判红 ─────────────────────────────────────────────
syntax_entry="$work/entrypoint-syntax.sh"
{ cat "$baseline_entry"; printf '\nif true; then\n'; } >"$syntax_entry"
if bash "$gate" "$syntax_entry" "$repo_root/Dockerfile" >/dev/null 2>&1; then
  fail "语法错误（未闭合 if）必须被门禁拒绝"
fi

# ── C) exec 目标拼错必须判红（sh -n 对该形态恒绿）──────────────────
typo_entry="$work/entrypoint-typo.sh"
sed 's|^exec /usr/local/bin/lazy-balancer$|exec /usr/local/bin/lazy-balancer-typo|' \
  "$baseline_entry" >"$typo_entry"
if ! grep -q 'lazy-balancer-typo' "$typo_entry"; then
  fail "变异注入失败（exec 目标未改写，用例会空转）"
fi
if sh -n "$typo_entry" 2>/dev/null; then
  : # 预期：纯语法门放行——这正是本门要补的缺口
else
  fail "对照前提不成立：拼错路径不该触发语法错误"
fi
if bash "$gate" "$typo_entry" "$repo_root/Dockerfile" >/dev/null 2>&1; then
  fail "exec 目标不在镜像路径清单中必须被门禁拒绝"
fi

# ── D) 非 git 工作树必须 fail-closed ───────────────────────────────
plain_tree="$work/plain-tree"
mkdir -p "$plain_tree/scripts"
cp "$repo_root/docker-entrypoint.sh" "$plain_tree/docker-entrypoint.sh"
cp "$repo_root/Dockerfile" "$plain_tree/Dockerfile"
# 复制一份脚本进去：清单来源失效时，若门禁退化为 find 兜底也必须被判红
# （本门选择 fail-closed，故这里只需证明「没有 .git 就不通过」）。
cp "$repo_root/scripts/check-startup-chain.sh" "$plain_tree/scripts/"
if STARTUP_CHAIN_REPO_ROOT="$plain_tree" bash "$gate" "$plain_tree/docker-entrypoint.sh" "$plain_tree/Dockerfile" >/dev/null 2>"$work/d.err"; then
  fail "非 git 工作树必须 fail-closed（git ls-files 失败被静默当成零检查）"
fi
grep -q '非 git 工作树' "$work/d.err" || {
  cat "$work/d.err" >&2
  fail "非 git 工作树的失败必须点名原因（清单来源不可确定）"
}

# ── E) 阶段作用域：exec 目标只在构建阶段 COPY 时必须判红 ─────────────
# 旧实现把整个 Dockerfile 的 COPY 目标并成一张清单（不跟踪 FROM 阶段），
# 「最终阶段漏 COPY、目标只在 builder 阶段存在」因此假绿——容器启动时才
# exec 失败（`sh -n` 对此恒绿，正是本门要补的缺口）。
stage_df="$work/Dockerfile.stages"
cat >"$stage_df" <<'DOCKERFILE'
FROM golang:1.24 AS builder
COPY docker-entrypoint.sh /usr/local/bin/lazy-balancer
FROM alpine:3.20
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
DOCKERFILE
if bash "$gate" "$baseline_entry" "$stage_df" >/dev/null 2>"$work/e.err"; then
  fail "exec 目标只在构建阶段 COPY 时必须被门禁拒绝（阶段并集 → 假绿）"
fi
grep -q '不在 Dockerfile 提供的镜像路径中' "$work/e.err" || {
  cat "$work/e.err" >&2
  fail "阶段作用域失败必须点名 exec 目标（失败原因不可混淆）"
}

# 对照：同一目标由**最终阶段** COPY 时仍须通过（防本用例把门禁改成恒红）。
cat >"$stage_df" <<'DOCKERFILE'
FROM golang:1.24 AS builder
COPY docker-entrypoint.sh /opt/builder-only-entry
FROM alpine:3.20
COPY docker-entrypoint.sh /usr/local/bin/lazy-balancer
COPY --from=builder /opt/builder-only-entry /app/builder-only-entry
DOCKERFILE
if ! bash "$gate" "$baseline_entry" "$stage_df" >/dev/null 2>"$work/e2.err"; then
  cat "$work/e2.err" >&2
  fail "最终阶段提供 exec 目标的 Dockerfile 必须通过（阶段切块不得恒红）"
fi

echo "startup chain gate selftest ok (baseline pass; syntax / exec-typo / non-git / stage-scope mutations rejected)"
