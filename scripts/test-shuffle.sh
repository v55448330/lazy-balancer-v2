#!/usr/bin/env bash
# 顺序依赖门：扩大排列面。全量测试已用固定 seed 跑过一遍（见 test-all.sh
# 的 canonical_shuffle_seed），本脚本只负责「额外轮次」：默认 1 个随机 seed；
# SHUFFLE_GATE_SEEDS 显式指定多轮（夜间/发版）；SHUFFLE_GATE_RANDOM_SEED=0
# 可关闭随机轮（此时必须由 SHUFFLE_GATE_SEEDS 给出至少一个显式 seed——两者都空
# 是配置错误，脚本以非零退出，不得零轮通过）。每次失败都打印含 seed 与超时的
# 完整复放命令。
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

# fail-closed：SHUFFLE_GATE_SEEDS 为空且随机轮被关闭（SHUFFLE_GATE_RANDOM_SEED=0）
# 时 seeds 为空，下面的循环执行 0 次、脚本以 0 退出——门禁「一轮没跑却宣告通过」，
# 与全仓守卫的 fail-closed 取向相反（且 bash <4.4 下 `${seeds[*]}` 在 set -u 里
# 直接报 unbound，报错形态取决于宿主 bash 版本）。关随机轮的正当用法是「只跑
# 显式 seed」，因此该组合必然是配置错误。${#seeds[@]} 在 bash 3.2 下对空数组安全。
if [[ ${#seeds[@]} -eq 0 ]]; then
  echo "ERROR: 未产生任何 seed（SHUFFLE_GATE_SEEDS 为空且随机轮被关闭）——拒绝零轮通过；" >&2
  echo "       关随机轮时必须用 SHUFFLE_GATE_SEEDS 指定至少一个显式 seed。" >&2
  exit 1
fi

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
