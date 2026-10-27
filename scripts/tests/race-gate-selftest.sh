#!/usr/bin/env bash
# 竞态门接线自检：test-all.sh 的 -race 段必须同时覆盖
#   ① 根模块并发核心（taskengine/middleware/cmd）；
#   ② internal/services 的定向并发面（-run 前缀清单）；
#   ③ 两个嵌套叶子模块 wafiplist / caddygeoip 全包；
# 并且 -run 前缀清单必须带「至少匹配到一个用例」断言——用例改名后
# `go test -run` 匹配 0 个仍以 0 退出，竞态门就会静默空转。
# 接线被删、被改窄或断言消失时本自检必须变红；两条变异体各自验证一个缺口。
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
source_file="$repo_root/scripts/test-all.sh"

check_race_gate_wiring() {
  local source="$1"
  grep -F 'go test -race -count=1 ./internal/taskengine ./internal/middleware ./cmd/...' "$source" >/dev/null &&
    grep -F 'for module in wafiplist caddygeoip; do' "$source" >/dev/null &&
    grep -F '(cd "$module" && go test -race -count=1 -timeout=10m ./...)' "$source" >/dev/null &&
    grep -F 'race_listed="$(go test -list "^${prefix}" ./internal/services)"' "$source" >/dev/null &&
    grep -F 'grep -q "^${prefix}" <<<"$race_listed"' "$source" >/dev/null &&
    grep -F 'race_run_filter="$(IFS=' "$source" >/dev/null &&
    grep -F -- '-run "${race_run_filter}" ./internal/services' "$source" >/dev/null
}

if ! check_race_gate_wiring "$source_file"; then
  echo "FAIL [race gate wiring] test-all.sh 必须覆盖根模块并发核心、嵌套模块 wafiplist/caddygeoip，并按前缀断言 -run 清单非空" >&2
  exit 1
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/race-gate-selftest.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

# 变异体 A：删掉嵌套模块的 -race 循环（wafiplist/caddygeoip 退回非竞态运行）。
mutated_nested="$tmp_root/test-all-no-nested-race.sh"
grep -vF 'for module in wafiplist caddygeoip; do' "$source_file" \
  | grep -vF '(cd "$module" && go test -race -count=1 -timeout=10m ./...)' \
  >"$mutated_nested"
if cmp -s "$source_file" "$mutated_nested"; then
  echo "FAIL [nested race mutation] fixture did not remove the nested-module race loop" >&2
  exit 1
fi
if check_race_gate_wiring "$mutated_nested"; then
  echo "FAIL [nested race mutation] 删掉嵌套模块 -race 循环后接线检查仍为绿" >&2
  exit 1
fi

# 变异体 B：删掉 -run 前缀的匹配断言（保留 -run 调用本身）——静默空转形态。
mutated_list="$tmp_root/test-all-no-list-assert.sh"
grep -vF 'race_listed="$(go test -list "^${prefix}" ./internal/services)"' "$source_file" \
  | grep -vF 'grep -q "^${prefix}" <<<"$race_listed"' \
  >"$mutated_list"
if cmp -s "$source_file" "$mutated_list"; then
  echo "FAIL [run-list assertion mutation] fixture did not remove the -list assertion" >&2
  exit 1
fi
if check_race_gate_wiring "$mutated_list"; then
  echo "FAIL [run-list assertion mutation] 删掉 -list 匹配断言后接线检查仍为绿" >&2
  exit 1
fi

# 机制验证：用真实 go test -list 证明「前缀匹配 0 个」可被检出（夹具模块极小，
# 只编译一个空测试包）。这正是 -run 清单断言要杀掉的静默空转形态。
printf 'module example.com/racegate\n\ngo 1.26\n' >"$tmp_root/go.mod"
mkdir -p "$tmp_root/pkg"
cat >"$tmp_root/pkg/pkg_test.go" <<'EOF'
package pkg

import "testing"

func TestAlphaConcurrent(t *testing.T) {}
func TestBeta(t *testing.T)            {}
EOF

listed_names="$(cd "$tmp_root/pkg" && go test -list '^TestAlphaConcurrent' .)"
if ! grep -q '^TestAlphaConcurrent' <<<"$listed_names"; then
  echo "FAIL [list mechanism] 现存用例的前缀未匹配到名字" >&2
  exit 1
fi
renamed_names="$(cd "$tmp_root/pkg" && go test -list '^TestRenamedAway' .)"
if grep -q '^TestRenamedAway' <<<"$renamed_names"; then
  echo "FAIL [list mechanism] 改名后的前缀不应匹配到任何用例" >&2
  exit 1
fi

echo "race gate selftest: wiring ok (root cores + services -run prefixes + nested modules), -list assertion and mutation fixtures ok"
