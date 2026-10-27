#!/usr/bin/env bash
# 启动链门禁：容器唯一入口（docker-entrypoint.sh）的「语法 + 语义」面。
#
# 为什么需要（两条实测缺口）：
#   1) 语义面：`sh -n` 只看语法。把 `exec /usr/local/bin/lazy-balancer` 拼成
#      不存在的路径仍然 rc=0 放行——面板起不来的形态只在容器启动时暴露。
#      本门用「Dockerfile 提供的镜像路径清单」对账每个 `exec <绝对路径>`。
#   2) 清单来源：脚本语法循环此前用进程替换 `done < <(git ls-files ...)`，
#      在无 .git 的工作树里 `git` 报 fatal、循环体 0 次、整体 rc=0（静默零覆盖）。
#      本门先取清单再判断：git 失败即失败（fail-closed），空清单同样失败。
#
# Dockerfile 侧只做**静态**解析（不跑 docker）：镜像路径清单由 COPY 的目标
# 路径派生（目录形式的目标按「目标 + 源码 basename」展开），与
# scripts/check-dockerfile-copy-manifest.sh 的「构建上下文源」清单互补——
# 后者保证源码目录被 COPY，本门保证 entrypoint 真正 exec 到的路径存在。
#
# 用法：bash scripts/check-startup-chain.sh [--self-test] [entrypoint] [dockerfile]
#   STARTUP_CHAIN_REPO_ROOT 可覆盖仓库根（自检用：验证非 git 工作树 fail-closed）。
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/startup-chain-gate-selftest.sh"
fi

repo_root="${STARTUP_CHAIN_REPO_ROOT:-$(cd "$script_dir/.." && pwd)}"
entrypoint="${1:-$repo_root/docker-entrypoint.sh}"
dockerfile="${2:-$repo_root/Dockerfile}"

if [[ ! -f "$entrypoint" ]]; then
  echo "FAIL: 找不到入口脚本: $entrypoint" >&2
  exit 1
fi
if [[ ! -f "$dockerfile" ]]; then
  echo "FAIL: 找不到 Dockerfile: $dockerfile" >&2
  exit 1
fi

# 1) 语法面：入口脚本按 sh 解析（镜像里由 tini+sh 启动），scripts/ 全部按 bash。
sh -n "$entrypoint"

if ! script_list="$(git -C "$repo_root" ls-files --cached --others --exclude-standard 'scripts/*.sh')"; then
  echo "FAIL: 无法从 $repo_root 列出 scripts/*.sh（非 git 工作树？）——脚本语法门的检查面无法确定" >&2
  exit 1
fi
if [[ -z "$script_list" ]]; then
  echo "FAIL: scripts/*.sh 清单为空（解析漂移或目录丢失）——零覆盖不得算通过" >&2
  exit 1
fi
script_count=0
while IFS= read -r script; do
  [[ -z "$script" ]] && continue
  bash -n "$repo_root/$script"
  script_count=$((script_count + 1))
done <<<"$script_list"

# 2) 语义面：entrypoint 的每个 `exec <绝对路径>` 必须由 Dockerfile 提供。
#    COPY 目标清单派生（含续行拼接）：末位是目标；以 / 结尾的目标是目录，落点
#    为「目标 + 源码 basename」，否则目标即文件路径。
image_paths="$(
  awk '
    BEGIN { buf = "" }
    {
      line = $0
      if (buf != "") {
        sub(/\\[ \t]*$/, "", line)
        buf = buf " " line
        if ($0 ~ /\\[ \t]*$/) next
        print buf
        buf = ""
        next
      }
      if (line ~ /^[ \t]*#/) next
      if (toupper(line) ~ /^[ \t]*COPY[ \t]/) {
        if (line ~ /\\[ \t]*$/) {
          sub(/\\[ \t]*$/, "", line)
          buf = line
          next
        }
        print line
      }
    }
    END { if (buf != "") print buf }
  ' "$dockerfile" \
  | while IFS= read -r instr; do
      read -r -a toks <<<"$instr"
      # 末位 = 目标；其前一位（跳过后缀标志）是源（判目录展开用）。
      target="${toks[$((${#toks[@]} - 1))]}"
      [[ -z "$target" || "$target" != /* ]] && continue
      if [[ "$target" == */ ]]; then
        src="${toks[$((${#toks[@]} - 2))]}"
        printf '%s%s\n' "$target" "$(basename "$src")"
      else
        printf '%s\n' "$target"
      fi
    done
)"

if [[ -z "$image_paths" ]]; then
  echo "FAIL: 未从 $dockerfile 解析到任何镜像内绝对路径（COPY 清单解析漂移）——exec 目标校验会空转" >&2
  exit 1
fi

exec_targets="$(grep -E '^[[:space:]]*exec[[:space:]]+' "$entrypoint" | awk '{print $2}')"
if [[ -z "$exec_targets" ]]; then
  echo "FAIL: 入口脚本没有可解析的 exec 目标（拼写/缩进漂移会让本门空转）: $entrypoint" >&2
  exit 1
fi
target_count=0
while IFS= read -r target; do
  [[ -z "$target" ]] && continue
  target_count=$((target_count + 1))
  case "$target" in
    /*) ;;
    *) continue ;;  # 相对路径/变量展开的 exec 不进入镜像路径对账面
  esac
  if ! printf '%s\n' "$image_paths" | grep -qxF "$target"; then
    echo "FAIL: 入口脚本 exec 的目标不在 Dockerfile 提供的镜像路径中: $target" >&2
    echo "镜像路径清单:" >&2
    printf '  %s\n' $image_paths >&2
    exit 1
  fi
done <<<"$exec_targets"

echo "startup chain ok (entrypoint syntax + ${script_count} scripts + ${target_count} exec targets against $(grep -c . <<<"$image_paths") image paths)"
