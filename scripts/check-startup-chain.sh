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
# Dockerfile 侧只做**静态**解析（不跑 docker）：镜像路径清单由 COPY 的落点派生
# （按 Docker 语义区分文件项与目录项：`COPY src/ /opt/` 记目录前缀、`COPY f /d/`
# 记 /d/f），与 scripts/check-dockerfile-copy-manifest.sh 的「构建上下文源 + 落点」
# 清单互补——后者保证源码目录被 COPY 到正确位置，本门保证 entrypoint 真正 exec
# 到的路径存在。
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
#    COPY 落点按 Docker 语义建模（清单条目带类型前缀，避免把目录当文件逐字对账）：
#      · 源带尾斜杠（`COPY src/ /opt/`）= 目录内容合并进目标 → 目标是目录，
#        落点为该目录下的子项，记目录项 `D/opt/`；
#      · 源是文件 + 目标带尾斜杠（`COPY foo.sh /usr/local/bin/`）→ `F/usr/local/bin/foo.sh`；
#      · 其余 → 目标即落点，记 `F<目标>`。
#    目录项按「exec 目标位于该目录之下」判定，文件项按全等判定：把目录当文件
#    会假红（旧启发式把 `COPY src/ /opt/` 记成 /opt/src），把文件当目录前缀又会
#    让任意路径都算「已提供」。边界（安全方向）：源不带尾斜杠的目录形态
#    （`COPY web/dist /app/ui`）静态不可判——源可能来自 --from 阶段，按目标即
#    落点记；该形态的 exec 目标会假红（阻断），不会假绿（逃逸）。
#
#    只取**最后一个 FROM 阶段**（最终镜像）的 COPY：构建阶段（xcaddy-builder /
#    backend）把文件放到 /app/... 与最终镜像的路径空间无关，混入同一张清单会
#    让「最终阶段漏 COPY、目标只在构建阶段存在」的形态假绿——容器启动才暴露
#    exec 失败（与 check-dockerfile-copy-manifest.sh 的阶段切块同理，该脚本
#    的头注释记录了「前一阶段满足断言 → 假绿」的事故形态）。
last_from_line="$(grep -nE '^[[:space:]]*FROM[[:space:]]' "$dockerfile" | tail -1 | cut -d: -f1)"
if [[ -z "$last_from_line" ]]; then
  echo "FAIL: $dockerfile 里没有 FROM 指令——最终镜像阶段无法确定，exec 目标校验会空转" >&2
  exit 1
fi
image_entries="$(
  awk -v last_from="$last_from_line" '
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
      if (FNR < last_from) next
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
      # 末位 = 目标；其前各位（跳过 --from/--chown 等标志）是源。
      # 标志过滤必须用 [[ ]] 而非 case：bash 3.2（macOS 系统 bash）扫描 $( )
      # 时不认 case 模式里的 `)`，`--*)` 会被当成替换结束 → 整脚本语法错误。
      srcs=()
      for ((i = 1; i < ${#toks[@]}; i++)); do
        tok="${toks[i]}"
        [[ "$tok" == --* ]] && continue
        srcs+=("$tok")
      done
      (( ${#srcs[@]} < 2 )) && continue  # 至少要有一个源 + 目标
      target="${srcs[$((${#srcs[@]} - 1))]}"
      [[ -z "$target" || "$target" != /* ]] && continue
      for ((i = 0; i < ${#srcs[@]} - 1; i++)); do
        src="${srcs[i]}"
        if [[ "$src" == */ ]]; then
          printf 'D%s/\n' "${target%/}"
        elif [[ "$target" == */ ]]; then
          printf 'F%s%s\n' "$target" "$(basename "${src%/}")"
        else
          printf 'F%s\n' "$target"
        fi
      done
    done | LC_ALL=C sort -u
)"

if [[ -z "$image_entries" ]]; then
  echo "FAIL: 未从 $dockerfile 解析到任何镜像内绝对路径（COPY 清单解析漂移）——exec 目标校验会空转" >&2
  exit 1
fi
image_files="$(printf '%s\n' "$image_entries" | sed -n 's/^F//p')"
image_dirs="$(printf '%s\n' "$image_entries" | sed -n 's/^D//p')"

# 镜像内提供判定：文件项全等；目录项按前缀（目标位于该目录之下即由镜像提供）。
image_provides() { # <abs path>
  local want="$1" entry
  while IFS= read -r entry; do
    [[ -n "$entry" && "$want" == "$entry" ]] && return 0
  done <<<"$image_files"
  while IFS= read -r entry; do
    [[ -n "$entry" && "$want" == "$entry"* ]] && return 0
  done <<<"$image_dirs"
  return 1
}

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
  if ! image_provides "$target"; then
    echo "FAIL: 入口脚本 exec 的目标不在 Dockerfile 提供的镜像路径中: $target" >&2
    echo "镜像路径清单:" >&2
    printf '%s\n' "$image_files" | sed 's/^/  /' >&2
    printf '%s\n' "$image_dirs" | sed 's/^/  /' >&2
    exit 1
  fi
done <<<"$exec_targets"

# 3) 裸命令语义面：exec 之外的启动依赖也必须由最终镜像提供。
# caddy 由 COPY 落到固定路径；sqlite3 来自 apk 的 sqlite 包；wget 来自 Alpine
# 自带 BusyBox。只检查 entrypoint 实际使用的命令，未使用时不强制安装。
final_stage="$(awk -v last_from="$last_from_line" 'FNR >= last_from { print }' "$dockerfile")"
command_count=0
if grep -Eq '(^|[;[:space:]])caddy([[:space:]]|$)' "$entrypoint"; then
  command_count=$((command_count + 1))
  if ! image_provides '/usr/local/bin/caddy'; then
    echo "FAIL: 入口脚本使用裸命令 caddy，但最终镜像缺少 /usr/local/bin/caddy" >&2
    exit 1
  fi
fi
if grep -Eq '(^|[;[:space:]])sqlite3([[:space:]]|$)' "$entrypoint"; then
  command_count=$((command_count + 1))
  if ! awk '/^[[:space:]]*#/ { next } { print }' <<<"$final_stage" | grep -Eq '(^|[[:space:]])sqlite([[:space:]]|$)'; then
    echo "FAIL: 入口脚本使用 sqlite3，但最终镜像阶段未安装 sqlite 包" >&2
    exit 1
  fi
fi
if grep -Eq '(^|[;[:space:]])wget([[:space:]]|$)' "$entrypoint"; then
  command_count=$((command_count + 1))
  if ! grep -Eq '^[[:space:]]*FROM[[:space:]]+alpine:' <<<"$final_stage"; then
    echo "FAIL: 入口脚本使用 wget，但最终镜像不是提供 BusyBox wget 的 Alpine 基线" >&2
    exit 1
  fi
fi

# 4) pause 标记跨 Shell/Go 三处必须逐字一致；注释里的同名文本不参与判定。
shell_pause="$(awk -F= '$1 == "CADDY_PAUSE_FILE" { print $2 }' "$entrypoint")"
handler_pause="$(awk -F\" '/^var caddyPauseFile = / { print $2 }' "$repo_root/internal/handlers/caddy.go")"
main_pause="$(awk -F\" '/^const caddyPauseFileDefaultPath = / { print $2 }' "$repo_root/cmd/server/main.go")"
if [[ -z "$shell_pause" || -z "$handler_pause" || -z "$main_pause" ]]; then
  echo "FAIL: pause 标记声明无法解析（Shell/handlers/main 任一缺失即零覆盖）" >&2
  exit 1
fi
if [[ "$shell_pause" != "$handler_pause" || "$shell_pause" != "$main_pause" ]]; then
  echo "FAIL: pause 标记跨进程漂移: entrypoint=$shell_pause handlers=$handler_pause main=$main_pause" >&2
  exit 1
fi

image_entry_count="$(printf '%s\n' "$image_entries" | grep -c . || true)"
echo "startup chain ok (entrypoint syntax + ${script_count} scripts + ${target_count} exec targets + ${command_count} bare commands + pause parity against ${image_entry_count} image paths/dirs)"
