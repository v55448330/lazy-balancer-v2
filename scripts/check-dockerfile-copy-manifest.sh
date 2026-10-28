#!/usr/bin/env bash
# Dockerfile「显式 COPY 清单」门禁（按阶段切块）。
#
# 为什么必须按阶段切块：xcaddy-builder 阶段同样 COPY caddygeoip/、caddydeps/、
# wafiplist/、geoipnames/（--with 载体）。若把整份 Dockerfile 的 COPY 源汇总成
# 一张清单，删掉 backend 阶段的同名 COPY 后断言仍被前一阶段满足——问题只在镜像
# 构建期（go mod download 解析 replace / go build 缺包）暴露，门禁给假绿。
# 本脚本按 `^FROM ... AS <stage>` 切块，每个阶段的 COPY 各自成清单。
#
# 断言：
#   A) backend 阶段（编译后端与最终二进制的阶段）：
#      1) 存在该阶段且块内至少一条 COPY（解析退化不许以空清单通过）；
#      2) go.mod / go.sum 在清单内（go build 必需；复制目录只带内容，模块文件必须显式）；
#      3) 顶层 Go 目录在清单内（新增顶层目录必须同步清单）。目录派生用
#         `git ls-files --cached --others --exclude-standard`——受控 + 未跟踪同扫，
#         与同仓 shell/gofmt 门同口径：新目录还没 git add 时就能红，而不是等到
#         提交后才红、真正漏 COPY 只在镜像构建期报缺包；
#      4) 落点正确（源对、目标错同样只在镜像构建期暴露）：目录源必须落到同名
#         目录、文件源必须落到其所在目录（根模块文件 → `.`，嵌套模块文件 →
#         `<模块>/`）。`COPY go.mod go.sum ./` 被改成 `./wafiplist/` 时源名仍在
#         清单里，靠这条才红。
#   B) xcaddy-builder 阶段（插件编译）：
#      本阶段 COPY 源必须覆盖所有 `--with lazy-balancer-v2/<mod>=./<mod>` 的
#      `<mod>/`。此前该阶段完全没有门：新增顶层插件模块、只补 backend 的 COPY
#      时门禁给绿，问题只在镜像构建期以「--with 路径不存在」暴露（构建耗时
#      数分钟到数十分钟）。--with 清单同时是「本阶段该有哪些目录」的单源。
#
# 用法：bash scripts/check-dockerfile-copy-manifest.sh [--self-test] [Dockerfile]
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/dockerfile-copy-gate-selftest.sh"
fi

cd "$script_dir/.."
dockerfile="${1:-Dockerfile}"
if [[ ! -f "$dockerfile" ]]; then
  echo "ERROR: Dockerfile not found: $dockerfile" >&2
  exit 1
fi

backend_stage=backend
xcaddy_stage=xcaddy-builder

# 阶段切块解析：输出指定阶段内（不含后续 FROM 之后）的 COPY 指令，续行已拼接。
stage_copy_lines() {
  awk -v target="$1" '
    BEGIN { in_stage = 0; buf = "" }
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
      if (toupper(line) ~ /^[ \t]*FROM[ \t]/) {
        n = split(line, tok, /[ \t]+/)
        alias = ""
        for (i = 1; i <= n; i++) {
          if (toupper(tok[i]) == "AS") alias = tok[i + 1]
        }
        in_stage = (alias == target)
        next
      }
      if (!in_stage) next
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
  ' "$dockerfile"
}

# 把 COPY 指令转成「构建上下文的源 <TAB> 目标」对（跳过 --from 的跨阶段源与
# 标志位），每行一对。目标校验需要成对信息：只比源名会让「源正确、落点错误」
# 的形态（`COPY go.mod go.sum ./` → `./wafiplist/`）继续判绿——根模块在镜像里
# 缺 go.mod/go.sum，只在镜像构建期 go build 才暴露。
stage_copy_pairs() {
  stage_copy_lines "$1" | while IFS= read -r instr; do
    [[ -z "$instr" ]] && continue
    read -r -a toks <<<"$instr"
    srcs=()
    is_from=0
    skip_next=0
    # 标志过滤用 [[ ]] 而非 case：bash 3.2（macOS 系统 bash）扫描 $( ) 时不认
    # case 模式里的 `)`，`--*)` 会被当成替换结束 → 整脚本语法错误。
    for ((i = 1; i < ${#toks[@]}; i++)); do
      tok="${toks[i]}"
      if ((skip_next)); then
        skip_next=0
        continue
      fi
      if [[ "$tok" == "--from" ]]; then
        is_from=1
        skip_next=1
        continue
      fi
      [[ "$tok" == "--from="* ]] && { is_from=1; continue; }
      [[ "$tok" == "--"* ]] && continue   # --chown / --chmod / --link 等标志
      srcs+=("$tok")
    done
    # --from 的源来自其它阶段/镜像，不是构建上下文里的清单项。
    ((is_from)) && continue
    (( ${#srcs[@]} < 2 )) && continue  # 末位是目标路径，不计入源
    target="${srcs[$((${#srcs[@]} - 1))]}"
    # 源保留原样（含尾斜杠）：尾斜杠是「目录内容合并」的唯一静态信号。
    for ((i = 0; i < ${#srcs[@]} - 1; i++)); do
      printf '%s\t%s\n' "${srcs[i]}" "$target"
    done
  done
}

# 源目录清单（从成对信息派生，单一解析器）：跳过空源与构建上下文根 `.`。
stage_copy_dirs() {
  stage_copy_pairs "$1" | while IFS=$'\t' read -r src target; do
    dir="${src%/}"
    [[ -z "$dir" || "$dir" == "." ]] && continue
    printf '%s\n' "$dir"
  done
}

copy_dirs=()
while IFS= read -r dir; do
  [[ -n "$dir" ]] && copy_dirs+=("$dir")
done < <(stage_copy_dirs "$backend_stage")

if (( ${#copy_dirs[@]} == 0 )); then
  echo "ERROR: 未解析到 backend 阶段的显式 COPY 清单（需要 'FROM ... AS $backend_stage' 且块内有 COPY）" >&2
  exit 1
fi

for required in go.mod go.sum; do
  printf '%s\n' "${copy_dirs[@]}" | grep -qxF "$required" || {
    echo "ERROR: Dockerfile backend COPY 清单缺少 $required" >&2
    echo "清单=[${copy_dirs[*]}]" >&2
    exit 1
  }
done

# 落点校验（源对、目标错同样只在镜像构建期暴露）：按 Docker 落点语义反推每个
# 源应有的目标，逐对比较。
#   · 目录源（带尾斜杠，或工作树里确实是目录）→ 内容是「合并进目标」，目标必须
#     就是该目录本身（`COPY cmd/ ./cmd/`）；
#   · 文件源 → 目标是其所在目录（根模块文件 go.mod/go.sum → `.`；嵌套模块的
#     wafiplist/go.mod → `wafiplist`）。
# 反例（旧实现的假绿形态）：`COPY go.mod go.sum ./` 改成 `./wafiplist/` 后源名
# 仍在清单内 → 门禁绿，而根模块在镜像里没有 go.mod/go.sum，`go mod download` /
# `go build` 在镜像构建期才失败。
normalize_target_dir() { # 去 ./ 前缀与尾斜杠；空/点统一为 .
  local p="$1"
  p="${p#./}"
  p="${p%/}"
  [[ -z "$p" ]] && p="."
  printf '%s' "$p"
}

branch_target_mismatch=""
while IFS=$'\t' read -r src target; do
  [[ -z "$src" ]] && continue
  if [[ "$src" == */ || -d "${src%/}" ]]; then
    expected="$(normalize_target_dir "${src%/}")"
  else
    expected="$(normalize_target_dir "$(dirname "$src")")"
  fi
  actual="$(normalize_target_dir "$target")"
  [[ "$actual" == "$expected" ]] && continue
  branch_target_mismatch+="${src} → ${target}（应为 ${expected}）; "
done < <(stage_copy_pairs "$backend_stage")
if [[ -n "$branch_target_mismatch" ]]; then
  echo "ERROR: Dockerfile backend COPY 落点与源不匹配（源在清单里但目标放错同样会漏构件）:" >&2
  echo "  $branch_target_mismatch" >&2
  echo "清单=[$(stage_copy_pairs "$backend_stage" | tr '\t' '>')]" >&2
  exit 1
fi

top_go_dirs="$(git ls-files --cached --others --exclude-standard '*.go' | awk -F/ 'NF>1{print $1}' | LC_ALL=C sort -u)"
missing_dirs=""
while IFS= read -r dir; do
  [[ -z "$dir" ]] && continue
  printf '%s\n' "${copy_dirs[@]}" | grep -qxF "$dir" || missing_dirs+="$dir "
done <<<"$top_go_dirs"
if [[ -n "$missing_dirs" ]]; then
  echo "ERROR: Dockerfile backend COPY 清单缺少顶层 Go 目录：$missing_dirs" >&2
  echo "清单=[${copy_dirs[*]}] 顶层 Go 目录=[${top_go_dirs//$'\n'/ }]" >&2
  exit 1
fi

xcaddy_dirs=()
while IFS= read -r dir; do
  [[ -n "$dir" ]] && xcaddy_dirs+=("$dir")
done < <(stage_copy_dirs "$xcaddy_stage")

if (( ${#xcaddy_dirs[@]} == 0 )); then
  echo "ERROR: 未解析到 $xcaddy_stage 阶段的显式 COPY 清单（需要 'FROM ... AS $xcaddy_stage' 且块内有 COPY）" >&2
  exit 1
fi

# 本地插件模块清单取自 --with 声明（单源）：`--with lazy-balancer-v2/<mod>=./<mod>`。
with_modules="$(grep -oE -- '--with[[:space:]]+lazy-balancer-v2/[A-Za-z0-9._-]+=\./[A-Za-z0-9._-]+' "$dockerfile" \
  | sed -E 's|.*=\./||' | LC_ALL=C sort -u)"
if [[ -z "$with_modules" ]]; then
  echo "ERROR: Dockerfile 未声明 --with lazy-balancer-v2/<mod>=./<mod> 本地插件模块（解析漂移会让本阶段门空转）" >&2
  exit 1
fi

missing_modules=""
while IFS= read -r module; do
  [[ -z "$module" ]] && continue
  printf '%s\n' "${xcaddy_dirs[@]}" | grep -qxF "$module" || missing_modules+="$module/ "
done <<<"$with_modules"
if [[ -n "$missing_modules" ]]; then
  echo "ERROR: Dockerfile $xcaddy_stage COPY 清单缺少 --with 本地插件模块：$missing_modules" >&2
  echo "清单=[${xcaddy_dirs[*]}] --with 模块=[${with_modules//$'\n'/ }]" >&2
  exit 1
fi

with_module_count="$(grep -c . <<<"$with_modules")"
echo "Dockerfile COPY manifest ok (backend ${#copy_dirs[@]} sources; $xcaddy_stage ${#xcaddy_dirs[@]} sources covering $with_module_count --with modules)"
