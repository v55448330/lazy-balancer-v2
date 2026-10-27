#!/usr/bin/env bash
# 顺序依赖门：扩大排列面。全量测试已用固定 seed 跑过一遍（见 test-all.sh
# 的 canonical_shuffle_seed），本脚本只负责「额外轮次」：默认 1 个随机 seed；
# SHUFFLE_GATE_SEEDS 显式指定多轮（夜间/发版）；SHUFFLE_GATE_RANDOM_SEED=0
# 可关闭随机轮。每次失败都打印含 seed 与超时的完整复放命令。
set -euo pipefail

cd "$(dirname "$0")/.."

# 同 test-all.sh：临时根目录由本进程持有，避免沙箱回收 TMPDIR 造成级联假红。
# 直接调用本脚本时也要成立。
if [[ -z "${LB_GATE_KEEP_TMPDIR:-}" ]]; then
  tmp_base="${TMPDIR:-/tmp}"; tmp_base="${tmp_base%/}"
  gate_tmp="$(mktemp -d "$tmp_base/lb-shuffle-gate.XXXXXX")"
  export TMPDIR="$gate_tmp"
  trap 'chmod -R u+rwX "$gate_tmp" 2>/dev/null || true; rm -rf "$gate_tmp"' EXIT
fi

packages=("$@")
if [[ ${#packages[@]} -eq 0 ]]; then
  packages=(./internal/handlers ./internal/services ./internal/middleware ./internal/db ./internal/taskengine)
fi

seeds=()
if [[ -n "${SHUFFLE_GATE_SEEDS:-}" ]]; then
  read -r -a seeds <<<"$SHUFFLE_GATE_SEEDS"
fi
random_seed="${SHUFFLE_GATE_RANDOM_SEED:-$(date +%s)}"
if [[ "$random_seed" != "0" ]]; then
  seeds+=("$random_seed")
fi
shuffle_timeout=900s

echo "== go test -shuffle (seeds: ${seeds[*]}, timeout: ${shuffle_timeout}) =="
for seed in "${seeds[@]}"; do
  echo "-- -shuffle=${seed} ${packages[*]}"
  set +e
  go test -count=1 -shuffle="$seed" -timeout="$shuffle_timeout" "${packages[@]}"
  shuffle_rc=$?
  set -e
  if [[ $shuffle_rc -ne 0 ]]; then
    echo "顺序依赖门失败（rc=${shuffle_rc}）：按同一 seed 复放——" >&2
    echo "  go test -count=1 -shuffle=${seed} -timeout=${shuffle_timeout} ${packages[*]}" >&2
    echo "先查共享全局态（包级缓存/测试 seam/健康位）的写侧与清理侧配对，勿改 seed 绕过。" >&2
    exit "$shuffle_rc"
  fi
done
