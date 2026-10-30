#!/usr/bin/env bash
# Full repository verification gate.
# Root `go test ./...` does NOT descend into nested modules, so this script
# must run every module. 模块清单由 git 跟踪的 go.mod 派生（不手写——新增嵌套
# 模块会静默漏测），并与显式基线逐项比对：新增/删除模块必须在此处显式确认，
# 否则脚本失败（parity guard）。
set -euo pipefail

cd "$(dirname "$0")/.."

# 档位（互斥）：默认=全量（提交前/发版判据）；--fast=合并树快检（变更面 +
# 反向依赖闭包，跳过 race/交叉编译/覆盖率与 vite build）；--full 等价于
# FULL=1（发版/夜间：不接受 SKIP、追加乱序轮）。
FAST=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    --fast-deep) FAST=2 ;;
    --full) FULL=1 ;;
    -h|--help)
      # 只打印文件头的注释段（遇到第一行非注释即停），不泄漏内部实现。
      awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
      echo
      echo "用法: $0 [--fast|--fast-deep|--full]"
      echo "  默认        全量门禁（提交前/发版判据，含 -race/交叉编译/覆盖率/vite build）"
      echo "  --fast      快检：变更包测试 + 全模块依赖面编译/静态检查 + 前端快速环（数十秒）"
      echo "  --fast-deep 深检：变更包 + 反向依赖闭包测试（跨域断言级回归，根模块改动约 4 分钟）"
      echo "  --full      等同 FULL=1：不接受跳过的门禁，再加乱序轮"
      exit 0
      ;;
    *)
      echo "未知参数: ${arg}（可用 --fast / --full / --help）" >&2
      exit 2
      ;;
  esac
done
if [[ "$FAST" != "0" && "${FULL:-0}" == "1" ]]; then
  echo "--fast/--fast-deep 与 --full 互斥：快检不能作为发版判据" >&2
  exit 2
fi

# 临时根目录由门禁自己创建并持有：沙箱/CI 在运行中回收 TMPDIR 会让
# t.TempDir() 级联报 stat/no such file（数十用例同时红，把真正的回归埋掉——
# 实测形态）。固定到本进程创建的目录后，退出时统一清理。
if [[ -z "${LB_GATE_KEEP_TMPDIR:-}" ]]; then
  tmp_base="${TMPDIR:-/tmp}"; tmp_base="${tmp_base%/}"
  gate_tmp="$(mktemp -d "$tmp_base/lb-gate.XXXXXX")"
  export TMPDIR="$gate_tmp"
  trap 'chmod -R u+rwX "$gate_tmp" 2>/dev/null || true; rm -rf "$gate_tmp"' EXIT
fi

# 守卫本体 + 守卫自检（审计产物/批量编辑两个守卫的自检在临时夹具仓里验证命中面
# 与误报边界——守卫的模式退化必须在这里先红，而不是等到审计产物真的混进公网仓库）。
./scripts/check-no-audit-artifacts.sh
./scripts/check-bulk-edit-safety.sh
./scripts/tests/guard-selftest.sh
./scripts/tests/bulk-edit-safety-selftest.sh
./scripts/tests/shuffle-gate-selftest.sh
./scripts/tests/race-gate-selftest.sh
# --fast 档判据本体（变更面 -> 包 + 反向依赖闭包）自检：映射退化表现为
# 「快检恒绿」（少测），必须在这里先红，而不是等到跨域断裂回流到合并树。
./scripts/tests/affected-packages-selftest.sh
# 修复声称反向核对（R-4b）：台账 -> 代码/测试事实。自检常开；带台账时
# （FIX_LEDGER=<file> [FIX_COMMIT=<rev>] ./scripts/test-all.sh）逐条验证
# code:path:line:token 与 test:Name 仍存在，并核对提交 message 的 Fixes: 声明。
./scripts/check-fix-claims.sh --self-test
if [ -n "${FIX_LEDGER:-}" ]; then
  if [ -n "${FIX_COMMIT:-}" ]; then
    ./scripts/check-fix-claims.sh --ledger "$FIX_LEDGER" --commit "$FIX_COMMIT"
  else
    ./scripts/check-fix-claims.sh --ledger "$FIX_LEDGER"
  fi
fi

# 启动链工件：docker-entrypoint.sh 是每次部署的唯一入口（语法/exec 目标错误 =
# 面板不可用，且只在容器启动时暴露）。门禁本体在 scripts/check-startup-chain.sh
# ——两件事它比此前的内联 `sh -n` 多做：
#   ① 语义面：entrypoint 的每个 `exec <绝对路径>` 必须由 Dockerfile 提供
#      （拼错二进制名时 sh -n 恒绿）；
#   ② 清单来源 fail-closed：`git ls-files` 失败（无 .git）或清单为空即失败，
#      不再在进程替换里静默得到「0 个脚本 + rc=0」。
# 未跟踪脚本同样入面：「先写脚本 → 跑门禁 → 再 git add」是常见顺序。
echo "== startup chain (entrypoint syntax + exec targets + scripts syntax) =="
./scripts/check-startup-chain.sh
./scripts/tests/startup-chain-gate-selftest.sh

# 出厂引导 Caddyfile 的引擎级校验：内容与 entrypoint heredoc 的同构性由
# cmd/server 的钉测试机械比对（下方 go test 覆盖）；此处校验引擎是否接受。
# caddy 不可用时显式 SKIP（不静默通过），结构比对仍在跑。
#
# SKIP 必须进入结构化统计：末尾的「全部门禁通过」若把 SKIP 当作已校验，结论
# 覆盖的门禁面就宽于字面承诺（无 caddy 的机器没校验引擎可接受性、无 compose
# 的机器没校验 YAML 锚点/键名）。故 SKIP 既打印也计数，并在末尾汇总行里显式
# 列出；FULL=1（发版/夜间）把 SKIP 升级为失败——发布前不得带着未校验的门禁
# 宣告通过。
skipped_gates=""
skip_gate() {
  skipped_gates+="${skipped_gates:+, }$1"
}
echo "== bootstrap Caddyfile engine validation =="
if command -v caddy >/dev/null 2>&1; then
  caddy validate --config config/Caddyfile --adapter caddyfile
else
  echo "SKIP: caddy 不可用——结构同构由 cmd/server/bootstrap_caddyfile_test.go 覆盖，引擎校验未执行"
  skip_gate "caddy-config-validation"
fi

# 部署工件静态校验：compose 的锚点引用/键名拼错只在 compose up 时暴露
# （logging/ulimits/healthcheck 走 YAML 锚点，extra_hosts 等键名同理）。
# docker 或 compose 子命令不可用时显式 SKIP（不静默通过）。
echo "== compose config validation =="
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose config --quiet
else
  echo "SKIP: docker/compose 不可用——compose 锚点与键名未校验"
  skip_gate "compose-config"
fi

# 基线（评审点）：与 git ls-files 派生结果不一致即失败。
baseline_modules=(
  "."
  "caddydeps"
  "caddygeoip"
  "caddyl4sec"
  "geoipnames"
  "wafiplist"
)

modules=()
while IFS= read -r module; do
  modules+=("$module")
done < <(
  git ls-files 'go.mod' '*/go.mod' \
    | sed -e 's|/go.mod$||' -e 's|^go.mod$|.|' \
    | sort -u
)

# 两侧各自排序后比较：模块清单顺序不承载语义（新增字典序在前的模块不应被
# 报成 drift），集合不同才是真 drift。
if [[ "$(printf '%s\n' "${modules[@]}" | LC_ALL=C sort)" != "$(printf '%s\n' "${baseline_modules[@]}" | LC_ALL=C sort)" ]]; then
  echo "module list drift: git-derived=[${modules[*]}] baseline=[${baseline_modules[*]}]" >&2
  echo "add/remove the module in baseline_modules (and gofmt targets) explicitly" >&2
  exit 1
fi

# 目录发现 parity：文件系统里任何含 go.mod 的目录都必须入列——git 未跟踪的
# 模块不得静默存在（否则 go vet/go test 漏跑而脚本仍绿）。VCS 元数据、依赖目录、
# 本地工具目录与工作树副本一律剪掉。
discovered_modules="$(
  find . \
    \( -name .git -o -name node_modules -o -name .worktrees -o -name .omp \
       -o -name .agent -o -name .superpowers -o -name .omo -o -name .sisyphus \
       -o -name .opencode -o -name dist \) -prune \
    -o -name go.mod -print \
    | sed -e 's|^\./||' -e 's|/go.mod$||' -e 's|^go.mod$|.|' | LC_ALL=C sort -u
)"
git_modules="$(printf '%s\n' "${modules[@]}" | LC_ALL=C sort -u)"
if [[ "$discovered_modules" != "$git_modules" ]]; then
  echo "module discovery drift: filesystem=[$discovered_modules] git=[$git_modules]" >&2
  echo "untracked module directories must be added to git (or removed)" >&2
  exit 1
fi

# Dockerfile 后端阶段用显式 COPY 清单（避免 web/docs/scripts 等非 Go 变更 bust
# Go 编译层）——清单漏项只会在镜像构建时才暴露（go build 缺包），故在此比对：
# 受控 + 未跟踪（未被 .gitignore 忽略）的顶层 Go 目录必须全部在清单内。
# 门禁本体按 `^FROM ... AS <stage>` 切块，只断言 backend 阶段：xcaddy-builder
# 阶段也 COPY 同名模块目录（--with 载体），整文件汇总会掩盖 backend 侧的漏项。
# 自检在临时夹具仓里验证该边界（删 backend 的 wafiplist/geoipnames 必红）。
echo "== Dockerfile backend COPY manifest =="
./scripts/check-dockerfile-copy-manifest.sh
./scripts/tests/dockerfile-copy-gate-selftest.sh

for module in "${modules[@]}"; do
  echo "== go vet ./... ($module) =="
  (cd "$module" && go vet ./...)
done

# gofmt 目标由模块清单派生：根模块的 Go 包目录取自 git 跟踪 + 未跟踪（未被
# .gitignore 忽略）的 .go 文件（排除嵌套模块前缀），嵌套模块直接扫模块目录本身。
# 含未跟踪文件是刻意的——「先写新文件 → 跑门禁 → 再 git add」是常见顺序，
# 只看受控文件会让格式门在该顺序下给假绿。新增嵌套模块自动入列——不再维护
# 硬编码目录清单（漏列模块会让格式检查静默失效）。
nested_re=""
for module in "${modules[@]}"; do
  [[ "$module" == "." ]] && continue
  nested_re+="${nested_re:+|}${module}"
done

gofmt_targets=()
root_targets=()
if [[ -n "$nested_re" ]]; then
  go_files="$(git ls-files --cached --others --exclude-standard '*.go' | grep -Ev "^(${nested_re})/" || true)"
else
  go_files="$(git ls-files --cached --others --exclude-standard '*.go')"
fi
if [[ -n "$go_files" ]]; then
  while IFS= read -r dir; do
    root_targets+=("$dir")
    gofmt_targets+=("$dir")
  done < <(printf '%s\n' "$go_files" | awk -F/ 'NF>1{print $1} NF==1{print "."}' | LC_ALL=C sort -u)
fi
for module in "${modules[@]}"; do
  [[ "$module" == "." ]] && continue
  # 嵌套模块的目标按「该模块确实有 Go 文件」派生，不再无条件 append：无条件
  # append 让下面的 parity 断言恒真（目标由模块清单本身产出，断言再也挡不住
  # 「模块漏入格式面」）。此处用未跟踪文件同样入面的口径（与根模块一致），
  # 新增嵌套模块在文件尚未 git add 时也进面。
  if [[ -n "$(git ls-files --cached --others --exclude-standard -- "$module" | grep -E '\.go$' || true)" ]]; then
    gofmt_targets+=("$module")
  fi
done

# 派生结果与模块清单 parity：每个模块必须至少贡献一个 gofmt 目标。嵌套模块
# 无 Go 文件时上面不会 append —— 该形态要么是模块退化成空壳，要么路径规则与
# git 输出漂移，两者都需要人工确认，故 fail-closed（不再是一条恒真的断言）。
for module in "${modules[@]}"; do
  if [[ "$module" == "." ]]; then
    if [[ ${#root_targets[@]} -eq 0 ]]; then
      echo "gofmt parity: 根模块未派生任何 Go 包目录（git ls-files '*.go' 为空？）" >&2
      exit 1
    fi
  elif ! printf '%s\n' "${gofmt_targets[@]}" | grep -qxF "$module"; then
    echo "gofmt parity: 模块 $module 未进入 gofmt 目录清单（该模块没有任何 .go 文件？）" >&2
    exit 1
  fi
done

echo "== gofmt (${gofmt_targets[*]}) =="
unformatted="$(gofmt -l "${gofmt_targets[@]}")"
if [[ -n "$unformatted" ]]; then
  echo "gofmt required:" >&2
  echo "$unformatted" >&2
  exit 1
fi

# 全量测试本身即以固定 shuffle seed 运行：文件声明顺序只是一个任意排列，
# 用固定 seed 的乱序跑同时承担「全量通过」与「固定排列通过」两件事，避免
# 先顺序跑一遍、再用同一个 seed 重复跑一遍的重复计算。seed 固定=失败可复放。
canonical_shuffle_seed="${CANONICAL_SHUFFLE_SEED:-1}"

# 快检两档（域内定向 -> **这一层** -> 全量）：
#
#   --fast       变更包测试 + 依赖面静态检查（本脚本上方已对**所有模块**跑过
#                go vet ./...，即依赖方的类型/API 面）+ 前端快速环。
#                实测（本机）：web-only 改动约 50s；根模块单文件改动约 60s
#                （只跑该包）；纯文档/配置改动只跑静态门禁约 10s。
#   --fast-deep  变更包 + **反向依赖闭包**测试：改 services 会带出 handlers/
#                middleware/cmd 的断言级回归。根模块单文件改动实测约 4 分钟，
#                与全量相当——这是正确性代价，不是性能优化点。
#
# 为什么默认快检不含闭包：本仓依赖图极密（几乎全包依赖 services/handlers），
# 闭包等于全量。跨域**断言级**漂移（本轮 handlers 陈旧断言）只有全量/深检能抓，
# 因此：迭代用 --fast，合并树收口用 --fast-deep 或默认全量，发版用默认全量。
#
# 明确的取舍（写清楚，避免被当成等价替代）：
#   * 依赖图位移（go.mod/go.sum 变更）一律按**整模块全量**处理：按包裁剪在
#     依赖图变化时没有意义。
#   * 不做 -race / cross-build / npm run build：快检绿 **不能** 作为提交/发版
#     判据，提交前与发布前仍须跑默认档（无参数）。
#   * Go 测试缓存：本仓用例大量使用 t.Setenv/TMPDIR 切换，Go 的测试缓存基本
#     失效（实测二次运行仅快约 8%），故仍显式 -count=1，不制造「缓存命中」的
#     假象。
#   * 未归属到任何模块的 .go 文件直接失败（新增顶层目录时给出显式清单）。
if [[ "${FAST:-0}" != "0" ]]; then
  # shellcheck source=lib/affected-packages.sh
  . ./scripts/lib/affected-packages.sh
  module_list=("${modules[@]}")

  fast_changed=()
  while IFS= read -r line; do
    if [[ -n "$line" ]]; then fast_changed+=("$line"); fi
  done < <(affected_changed_files)
  if [[ ${#fast_changed[@]} -eq 0 ]]; then
    echo "fast gate: 工作树无变更（相对 HEAD 且无未跟踪文件），只跑了静态门禁"
    echo "all verification gates passed (fast scope: no changes)"
    exit 0
  fi

  unattributed=""
  fast_scope=""
  ran_any_go=0
  for module in "${modules[@]}"; do
    module_files=()
    while IFS= read -r line; do
      if [[ -n "$line" ]]; then module_files+=("$line"); fi
    done < <(affected_module_changed_files "$module" "${fast_changed[@]}")
    [[ ${#module_files[@]} -eq 0 ]] && continue
    if affected_module_dependency_changed "$module" "${fast_changed[@]}"; then
      # 依赖图位移：整模块全量（--fast 最贵的一档，但正确性优先）。
      echo "== [fast] go test ./... ($module, go.mod/go.sum changed) =="
      (cd "$module" && go test ./... -count=1 -shuffle="$canonical_shuffle_seed")
      fast_scope+=" $module(全量)"
      ran_any_go=1
      continue
    fi
    targets=()
    while IFS= read -r line; do
      if [[ -n "$line" ]]; then targets+=("$line"); fi
    done < <(
      if [[ "$FAST" == "2" ]]; then
        affected_go_targets "$module" "${module_files[@]}"
      else
        affected_module_changed_packages "$module" "${module_files[@]}"
      fi | LC_ALL=C sort -u
    )
    if [[ ${#targets[@]} -eq 0 ]]; then
      unattributed+=" $module:[${module_files[*]}]"
      continue
    fi
    echo "== [fast] go test ${targets[*]} ($module) =="
    (cd "$module" && go test -count=1 -shuffle="$canonical_shuffle_seed" "${targets[@]}")
    fast_scope+=" $module(${#targets[@]} 包)"
    ran_any_go=1
  done

  if [[ -n "$unattributed" ]]; then
    echo "fast gate: 以下 Go 变更无法映射到任何包（新增目录/构建标签排除？）：$unattributed" >&2
    echo "            请显式补映射或改跑默认全量档" >&2
    exit 1
  fi

  web_changed=0
  for file in "${fast_changed[@]}"; do
    case "$file" in
      web/*) web_changed=1 ;;
    esac
  done
  if [[ "$web_changed" == "1" ]]; then
    echo "== [fast] npm test (web) =="
    (cd web && npm test)
    fast_scope+=" web(npm test)"
  fi

  if [[ "$ran_any_go" == "0" && "$web_changed" == "0" ]]; then
    echo "fast gate: 变更面不含 Go/前端代码（仅文档/配置），只跑了静态门禁"
  fi
  echo "all verification gates passed (scope:${fast_scope:- 静态面})"
  exit 0
fi

for module in "${modules[@]}"; do
  echo "== go test ./... -count=1 -shuffle=${canonical_shuffle_seed} ($module) =="
  (cd "$module" && go test ./... -count=1 -shuffle="$canonical_shuffle_seed")
done

# 额外排列面：默认 0 轮（上面的固定 seed 已覆盖乱序）；FULL=1（发版/夜间）
# 追加 1 个随机 seed，SHUFFLE_GATE_SEEDS 可显式指定多轮。五个持有进程级全局
# 态的包共用 900s 超时；自测用「声明顺序安全、乱序失败」的夹具包验证鉴别力。
if [[ "${FULL:-0}" == "1" || -n "${SHUFFLE_GATE_SEEDS:-}" ]]; then
  ./scripts/test-shuffle.sh
fi

# 声明序盲区：internal/handlers 的 suite 级全局态守卫**只比较终态**——「某用例
# 泄漏 → 后续用例顺手修回」在固定 seed 下判绿，只有把两者顺序打乱才暴露。
# 补偿分两层：①写侧隔离（withIsolatedGlobal + 静态门，已常开）；②排列面仍走
# 上面的 test-shuffle.sh（FULL=1/SHUFFLE_GATE_SEEDS）。默认**不**再加随机轮：
# 实测 seed 7/11 下该包已有与本轮无关的顺序依赖用例，默认轮会先红在那些用例上，
# 需要单独收敛后再并入默认门禁（复放：go test ./internal/handlers -shuffle=<seed>）。

# 交叉编译等价性（不是「镜像构建等价性」）：验证 GOOS=linux CGO_ENABLED=0
# 这组构建参数下代码可编译——平台/cgo 相关代码路径不进本地测试面，四个嵌套
# 模块由 xcaddy 在镜像内以同一组参数编译插件，其 linux-only 编译错误（构建
# 标签/syscall/cgo 分支）此前只在发版构建暴露。
# 注意工具链版本面未被本门覆盖：镜像两个阶段都是 golang:1.26.10-alpine +
# GOTOOLCHAIN=local（Dockerfile 带 go1.26.10 构建期断言），本门用宿主 go（可能
# 更新）。误用新版 stdlib API 只会在发版构建暴露——发版前置步骤须以镜像工具链
# 跑一次 go build（见发布流程）。
# 根模块是 main 包，产物丢 /dev/null；嵌套模块用 go install 配临时 GOBIN，
# 不落仓库（库模块本不产二进制，未来出现 main 包也不会污染工作树）。
echo "== cross-build equivalence (GOOS=linux CGO_ENABLED=0 go build) =="
cross_base="${TMPDIR:-/tmp}"; cross_base="${cross_base%/}"
cross_bin="$(mktemp -d "$cross_base/lb-crossbuild.XXXXXX")"
for module in "${modules[@]}"; do
  case "$module" in
    .) CGO_ENABLED=0 GOOS=linux go build -o /dev/null ./cmd/server ;;
    *) (cd "$module" && GOBIN="$cross_bin" CGO_ENABLED=0 GOOS=linux go install ./...) ;;
  esac
done
rm -rf "$cross_bin"

# 模块图一致性：go.mod/go.sum 必须与实际 import 集合一致（只读，-diff 不写盘）。
# 注意 go.mod 有两处本地 replace（./wafiplist、./geoipnames），本地模块不在
# 模块缓存中，`go mod verify` 对本仓恒报 missing ziphash——不要把它加进门禁，
# tidy -diff 才是等价且可用的检查。
# caddydeps 刻意排除：该模块不提供功能代码，其 go.mod 的注释块记录 MVS floor
# 理由，tidy 会把注释整块剥掉（差异恒存在且无害，不代表依赖漂移）。
echo "== go mod tidy -diff (module graph consistency) =="
for module in "${modules[@]}"; do
  # caddydeps 的注释型 MVS floor 同上排除；其余嵌套模块自动入列。
  [[ "$module" == "caddydeps" ]] && continue
  (cd "$module" && go mod tidy -diff)
done

# 竞态门：并发核心（任务引擎 + 中间件限流/白名单缓存 + 进程内 Caddy 协作/
# 监督器探测）此前只在本地手工跑 -race，且 middleware 不在覆盖内——限流桶
# （双层锁 + 换代计数）、API Key 白名单缓存、认证审计限流、MCP 响应缓冲都在
# 这个包里。全量 -race 会把门禁时长成倍拉长，故只覆盖并发密集入口。
#
# internal/services 同样纳入（并发密集面：单飞加载器、ip2region 100 goroutine
# Reload、downloadintegrity 共享写入、全局句柄 seam 十余处），此前从未在竞态
# 检测器下运行——数据竞争可在门禁内逃逸。
#
# 该包按 -run 定向取「并发面」而非全包：全包在 -race 下超过 20 分钟（数百个
# 用例各自跑一遍 DB 迁移，与并发无关；TestRDBCompile_200kAggregates 的 20 万行
# 编译基准更是纯算力），门禁时长不可接受。未进 -race 面的是「单线程夹具 + DB
# 迁移」类用例，仍由上方全量非 -race 运行覆盖；新增并发用例请按同一口径加进
# 本 -run 清单（前缀汇总，避免逐条漂移）。
#
# 嵌套模块同样纳入：wafiplist（@ipListFast 热路径——每请求二分判定、并发重建、
# 按路径锁表退役、窗口边界 CAS 单飞）与 caddygeoip（审计写插件常驻 sweeper、
# 流量租约/环、共享 GeoIP searcher、爬虫缓存）此前只在主循环的非 -race 运行
# 里跑；两个模块的测试注释与设计（`wafiplist/iplistfast_hardening_test.go`、
# `caddygeoip/auditwriter.go` 的「-race 下才是数据竞争」说明）都按存在竞态门
# 写。两个叶子模块全包 -race 可接受，故不裁剪。
echo "== go test -race (concurrency cores) =="
go test -race -count=1 ./internal/taskengine ./internal/middleware ./cmd/...
# -run 是手写前缀清单：用例改名后「匹配 0 个」仍以 0 退出，该门会静默空转。
# 逐前缀断言至少匹配到一个用例（go test -list 只列出名字，不执行）。
race_run_prefixes=(
  Test_Lookup_concurrent_with_Reload
  TestRecordDownloadIntegrity_
  TestScrapeRateLimitBlocks_
  TestTrustedProxyDegradation_
  TestApplyConfigWithOptions_callsIPListGCOnlyAfterSuccessfulApply
  TestInitTaskEngine_
  TestStartRoleReconciler_
  Test_GetSetIP2RegionVersion_roundtrip
)
for prefix in "${race_run_prefixes[@]}"; do
  # 先取全量名字再 grep：`go test -list | grep -q` 在 pipefail 下会因 grep 提前
  # 退出让 go test 收到 SIGPIPE（141），把「匹配到了」误判成失败。
  race_listed="$(go test -list "^${prefix}" ./internal/services)"
  if ! grep -q "^${prefix}" <<<"$race_listed"; then
    echo "FAIL: -race 定向前缀 ${prefix} 未匹配到任何用例（改名后竞态门会静默空转）" >&2
    exit 1
  fi
done
race_run_filter="$(IFS='|'; echo "${race_run_prefixes[*]}")"
go test -race -timeout=10m -count=1 -run "${race_run_filter}" ./internal/services
for module in wafiplist caddygeoip; do
  echo "-- -race ${module}"
  (cd "$module" && go test -race -count=1 -timeout=10m ./...)
done

echo "== frontend coverage/tests/typecheck/build =="
# 单一入口 npm run build = test:coverage + typecheck:src + typecheck:test + vite build。
# 此前拆跑 npm test + typecheck:test + build:vite，漏掉更严的 typecheck:src
# （src 基线 tsconfig.json 与测试基线的 lib 阈值不同：用 ES2021+ lib API 时
# 本门绿、npm run build 红）。vue-tsc 看不到模板编译期错误，发布契约要求
# 真实 vite build，故整条 build 链都在门内。
#
# test:coverage 用 node 内建门限：阈值 80/91/88（行/分支/函数），分母是
# `src/**/*.ts` 全量（tests/** 已排除），且由 tests/coverageLoadSentinel.spec.ts
# 逐个装载把「未被行为用例 import 的模块」也拉进分母（此前它们完全不进表，
# 新增零测试源文件不会拉低任何指标）。函数面因此从 93 下调到 88：装载哨兵把
# api.ts / highlight.ts / restart.ts 等未被覆盖的导出计为 0%。
# 实测水位贴阈值（余量不足 1pp，实测值见 `npm run test:coverage` 的表尾），故
# 改动分母/删 spec 必须同步复核阈值，不要再引用含 tests/** 分母时期的历史口径
# （那组数字已退役）。
# 唯一事实源是
# web/package.json 的 test:coverage 参数，本注释只是说明；两者一致性由
# web/tests/coverageThresholdSource.spec.ts 的阈值口径钉双向对账。
# 可见口径的覆盖率没有门限时只能靠人工审查发现静默下滑，前轮遗留的
# 「无覆盖率门禁」由此收口。纯 `npm test` 仍保留为快速环。
(cd web && npm run build)

# 汇总行必须与实际校验面一致：有 SKIP 时不得打印无条件的「全部门禁通过」。
# FULL=1 轮次（发版/夜间）不接受 SKIP——发布前必须先把缺失工具补齐重跑。
if [[ -n "$skipped_gates" ]]; then
  skipped_count="$(printf '%s\n' "$skipped_gates" | tr ',' '\n' | grep -c . || true)"
  if [[ "${FULL:-0}" == "1" ]]; then
    echo "ERROR: 发版/夜间轮次（FULL=1）不接受跳过的门禁：${skipped_gates}" >&2
    echo "       安装缺失工具（caddy / docker compose）后重跑。" >&2
    exit 1
  fi
  echo "all verification gates passed (${skipped_count} skipped: ${skipped_gates})"
else
  echo "all verification gates passed"
fi
