#!/usr/bin/env bash
# 用真实 Go 测试证明顺序依赖门能杀死「写侧在清理前」的全局态泄漏，并核对
# 固定 seed 复放、900s 余量、随机 seed 与 test-all 接线均未退化。
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
gate_source="$repo_root/scripts/test-shuffle.sh"
check_test_all_wiring() {
  local source="$1"
  grep -F 'canonical_shuffle_seed="${CANONICAL_SHUFFLE_SEED:-1}"' "$source" >/dev/null &&
    grep -F '(cd "$module" && go test ./... -count=1 -shuffle="$canonical_shuffle_seed")' "$source" >/dev/null &&
    grep -F './scripts/test-shuffle.sh' "$source" >/dev/null
}
if ! check_test_all_wiring "$repo_root/scripts/test-all.sh"; then
  echo "FAIL [shuffle gate wiring] test-all main loop must use CANONICAL_SHUFFLE_SEED and invoke the shuffle gate" >&2
  exit 1
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/shuffle-gate-selftest.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT
mkdir -p "$tmp_root/scripts" "$tmp_root/order" "$tmp_root/clean"
cp "$gate_source" "$tmp_root/scripts/test-shuffle.sh"
# 反例必须走同一个检查函数：主循环删掉 -shuffle 后，自测自身必须判红。
mutated_test_all="$tmp_root/test-all-no-shuffle.sh"
while IFS= read -r line; do
  printf '%s\n' "${line/ -shuffle=\"\$canonical_shuffle_seed\"/}"
done <"$repo_root/scripts/test-all.sh" >"$mutated_test_all"
if cmp -s "$repo_root/scripts/test-all.sh" "$mutated_test_all"; then
  echo "FAIL [shuffle wiring mutation] fixture did not remove the main-loop shuffle argument" >&2
  exit 1
fi
if check_test_all_wiring "$mutated_test_all"; then
  echo "FAIL [shuffle wiring mutation] main loop without -shuffle survived" >&2
  exit 1
fi
printf 'module example.com/shufflegate\n\ngo 1.26\n' >"$tmp_root/go.mod"
cat >"$tmp_root/order/order_test.go" <<'EOF'
package order

import "testing"

var leaked int

func TestAStateMustStartClean(t *testing.T) {
	if leaked != 0 {
		t.Fatal("observed state left by a later-declared test")
	}
}

func TestZStateWriter(t *testing.T) {
	leaked = 1
}
EOF
cat >"$tmp_root/clean/clean_test.go" <<'EOF'
package clean

import "testing"

func TestOne(t *testing.T) {}
func TestTwo(t *testing.T) {}
EOF

# 声明顺序本身安全，确保后续 RED 来自 -shuffle 而不是夹具本来就失败。
(
  cd "$tmp_root"
  go test -count=1 ./order
)

run_gate() {
  local seeds="$1" random_seed="$2" package="$3"
  set +e
  gate_output="$(
    cd "$tmp_root"
    SHUFFLE_GATE_SEEDS="$seeds" SHUFFLE_GATE_RANDOM_SEED="$random_seed" \
      bash scripts/test-shuffle.sh "$package" 2>&1
  )"
  gate_rc=$?
  set -e
}

# seed 2 会把写侧排到读侧之前；同一条打印命令必须能稳定复放这次失败。
run_gate 2 0 ./order
if [[ $gate_rc -eq 0 ]]; then
  echo "FAIL [order leak mutation] shuffled state leak survived" >&2
  echo "$gate_output" >&2
  exit 1
fi
if [[ "$gate_output" != *"go test -count=1 -shuffle=2 -timeout=900s ./order"* ]]; then
  echo "FAIL [fixed seed replay] output lacks the exact seed/timeout replay command" >&2
  echo "$gate_output" >&2
  exit 1
fi

# 同一固定 seed 再跑一次，RED 必须可复现而不是一次性环境失败。
run_gate 2 0 ./order
if [[ $gate_rc -eq 0 ]]; then
  echo "FAIL [fixed seed replay] identical seed did not reproduce the failure" >&2
  echo "$gate_output" >&2
  exit 1
fi

# 反向对照：把泄漏写侧移除后同一 seed 必须通过，证明不是夹具/命令恒红。
mv "$tmp_root/order/order_test.go" "$tmp_root/order/order_test.go.disabled"
cat >"$tmp_root/order/order_test.go" <<'EOF'
package order

import "testing"

func TestAStateMustStartClean(t *testing.T) {}
func TestZStateWriter(t *testing.T)       {}
EOF
run_gate 1 0 ./order
if [[ $gate_rc -ne 0 ]]; then
  echo "FAIL [fixed seed control] clean fixture failed" >&2
  echo "$gate_output" >&2
  exit 1
fi

# 不指定随机 seed 时必须走默认随机通道，不得只剩固定回归样本。
run_gate 1 "" ./clean
if [[ $gate_rc -ne 0 ]]; then
  echo "FAIL [random seed control] clean fixture failed" >&2
  echo "$gate_output" >&2
  exit 1
fi
random_runs="$(printf '%s\n' "$gate_output" | grep -c '^-- -shuffle=')"
if [[ "$random_runs" -ne 2 || "$gate_output" == *"seeds: 1)"* ]]; then
  echo "FAIL [random seed coverage] default random seed was not executed" >&2
  echo "$gate_output" >&2
  exit 1
fi

# 默认（无显式 seed）只补一个随机轮：固定 seed 的全量已在 test-all 主循环跑过，
# 这里再来一遍即重复计算。
run_gate "" "" ./clean
if [[ $gate_rc -ne 0 ]]; then
  echo "FAIL [default single random round] clean fixture failed" >&2
  echo "$gate_output" >&2
  exit 1
fi
default_runs="$(printf '%s\n' "$gate_output" | grep -c '^-- -shuffle=')"
if [[ "$default_runs" -ne 1 ]]; then
  echo "FAIL [default single random round] expected exactly 1 run, got ${default_runs}" >&2
  echo "$gate_output" >&2
  exit 1
fi

# 零轮配置必须 fail-closed：显式 seed 为空 + 随机轮关闭时 seeds 为空，旧实现
# 让 for 循环执行 0 次并以 0 退出——门禁一轮没跑却宣告通过（与全仓守卫的
# fail-closed 取向相反，且 bash <4.4 下报的是 unbound variable 而非明确原因）。
run_gate "" 0 ./clean
if [[ $gate_rc -eq 0 ]]; then
  echo "FAIL [empty seed set] 关闭随机轮且无显式 seed 时脚本仍以 0 退出（零轮通过）" >&2
  echo "$gate_output" >&2
  exit 1
fi
if [[ "$gate_output" != *"未产生任何 seed"* ]]; then
  echo "FAIL [empty seed set] 失败原因未指明 seed 集合为空" >&2
  echo "$gate_output" >&2
  exit 1
fi
if printf '%s\n' "$gate_output" | grep -q '^-- -shuffle='; then
  echo "FAIL [empty seed set] 空 seed 集合下仍执行了轮次" >&2
  echo "$gate_output" >&2
  exit 1
fi

echo "shuffle gate selftest: order-leak RED, fixed-seed replay, timeout, random seed, default single round, empty-seed fail-closed and wiring ok"
