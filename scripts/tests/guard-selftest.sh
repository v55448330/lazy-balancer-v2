#!/usr/bin/env bash
# scripts/check-no-audit-artifacts.sh 的自检。
#
# 在临时 git 夹具仓里逐形态验证守卫的命中面与误报边界：
#   • 命中面：未跟踪文件、受控文件、各扩展名（Go/TS/MD/SH/YML/SQL/go.mod/
#     Python/Dockerfile/docker-entrypoint.sh/.dockerignore/Caddyfile、JSON/HTML/
#     conf 的字符串与文本节点）、扩展名大小写、
#     无扩展名约定文件（.gitignore/.gitattributes）的注释块、
#     扫描面声明集合与期望集合的镜像断言（含逐扩展名/逐文件名的行为探针）、
#     含 NUL 字节的文本文件（报错而非整文件跳过）、下划线/小写/
#     连写形态、审计产物文件名（含 audit_96/audit-round-96/round-96 等分隔符
#     型轮次命名）、.gitignore 双向校验（含重复模式行）、轮次引用的
#     各书写形态（裸轮次＋审计动作、斜杠并列、中文数字归属、注释头截断残骸、
#     跨行拆字含续行注释前缀）、依赖/构建缓存通道（node_modules 内外两种缓存
#     目录、正则在各 grep 实现下可执行、非法正则必须 fail-closed）；
#   • 误报面：npm 生成物（package-lock.json 内容面豁免）、百分位、版本串、
#     十六进制摘要/哈希算法名、协议与产品 token、
#     容量边界常量、合法测试函数名、中文“轮播/轮询”、循环轮次表述（心跳/共识/
#     降频/区间/并列打点）、IPv6-only 等网络口径、日志轮转文件名骨架、
#     Windows-1252/Chrome-120 等产品词。
#
# 本文件按设计被守卫的内容扫描豁免（其内容即被测样本），豁免面在
# scripts/check-no-audit-artifacts.sh 中显式限定为这一个路径。
#
# 用法：bash scripts/tests/guard-selftest.sh（或守卫的 --self-test）
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
guard="$repo_root/scripts/check-no-audit-artifacts.sh"

if ! command -v perl >/dev/null 2>&1; then
  echo "SKIP: 需要 perl 才能运行守卫自检" >&2
  exit 1
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/audit-guard-selftest.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

pass=0
fail=0

# 每个用例一套全新夹具：仓库骨架只有守卫脚本与 .gitignore（后者取自真实仓库，
# 这样 .gitignore 双向校验在“一致”基线上成立）。
reset_fixture() {
  rm -rf "$tmp_root"
  mkdir -p "$tmp_root/scripts"
  cp "$guard" "$tmp_root/scripts/check-no-audit-artifacts.sh"
  cp "$repo_root/.gitignore" "$tmp_root/.gitignore"
  git init -q "$tmp_root"
}

run_guard() {
  ( cd "$tmp_root" && bash scripts/check-no-audit-artifacts.sh )
}

run_guard_with_tmpdir() {
  ( cd "$tmp_root" && TMPDIR="$tmp_root/tmp" bash scripts/check-no-audit-artifacts.sh )
}

# assert_bad <用例名> <输出中必须出现的片段>
assert_bad() {
  local name="$1" needle="$2" out rc
  set +e
  out="$(run_guard 2>&1)"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "FAIL [$name] 守卫本应失败但通过了" >&2
    fail=$((fail + 1))
    return
  fi
  if [[ -n "$needle" && "$out" != *"$needle"* ]]; then
    echo "FAIL [$name] 守卫失败但输出未提及 ${needle}：" >&2
    echo "$out" >&2
    fail=$((fail + 1))
    return
  fi
  echo "ok   [$name] hit: $(printf '%s\n' "$out" | grep -v '^ERROR' | head -1)"
  pass=$((pass + 1))
}

# assert_good <用例名>：守卫必须通过（误报对照）
assert_good() {
  local name="$1" out rc
  set +e
  out="$(run_guard 2>&1)"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "FAIL [$name] 误报：守卫不该失败" >&2
    echo "$out" >&2
    fail=$((fail + 1))
    return
  fi
  echo "ok   [$name] no false positive"
  pass=$((pass + 1))
}

mkdir_in() { mkdir -p "$tmp_root/$(dirname "$1")"; }

# ===========================================================================
# 命中面
# ===========================================================================

# 0) 依赖/构建缓存被跟踪：.gitignore 只挡「未跟踪」，已在索引里的一律由通道 0
#    拦下（根 node_modules 的 vitest 转译缓存曾随一次全量暂存入库）。
reset_fixture
mkdir_in node_modules/.vitest-cache/_metadata.json
printf '{"web/tests/apiErrorContract.spec.ts":{"failed":true}}\n' >"$tmp_root/node_modules/.vitest-cache/_metadata.json"
mkdir_in node_modules/.vite/vitest/CACHEDIR.TAG
: >"$tmp_root/node_modules/.vite/vitest/CACHEDIR.TAG"
git -C "$tmp_root" add -f node_modules
assert_bad "tracked node_modules cache" "不得入库"

# 0b) 同一目录仅存在于工作区（未跟踪）时不构成缺陷——忽略规则生效即不误报。
reset_fixture
mkdir_in node_modules/.vitest-cache/_metadata.json
printf '{"failed":true}\n' >"$tmp_root/node_modules/.vitest-cache/_metadata.json"
assert_good "untracked node_modules cache is ignored"

# 0c) 缓存目录本身（不在 node_modules 下）同样不得入库——通道正则的第二分支
#     （.vite/.vitest-cache）必须独立生效，只测 node_modules 形态会漏掉整支。
reset_fixture
mkdir_in web/.vitest-cache/_metadata.json
printf '{"failed":true}\n' >"$tmp_root/web/.vitest-cache/_metadata.json"
git -C "$tmp_root" add -f web/.vitest-cache
assert_bad "tracked .vitest-cache outside node_modules" "不得入库"

# 0c2) `.vite/` 分支必须单独可见：0) 的 .vite 样例带 node_modules 前缀，只靠第一
#      分支就能命中，第二分支里的 .vite 项整支失效也看不出来。故造一条完全不含
#      node_modules 的仓根 .vite 缓存。
reset_fixture
mkdir_in .vite/vitest/CACHEDIR.TAG
: >"$tmp_root/.vite/vitest/CACHEDIR.TAG"
git -C "$tmp_root" add -f .vite
assert_bad "tracked .vite outside node_modules" "不得入库"

# 0d) 缓存通道的正则形态必须在每一种 grep 实现下都可执行：命中样例返回 0、
#     未命中样例返回 1，绝不出现 2（正则错误）。PCRE 的 (?:…) 在 GNU grep -E
#     下会被当成无关字符吞掉，其中的 `.vite/` 分支静默失效（macOS 基线只有
#     BSD grep，看不到这个形态），任何实现报错时配合 `|| true` 又会被当成
#     「无命中」，通道永远假绿。故此处先拒 PCRE 形态，再逐个实现实跑命中/未
#     命中样例，最后用 awk 的 POSIX ERE 引擎做严格模拟（它对非 ERE 语法直接
#     报 illegal primary 并 rc=2，正好复现「整支失效」）。
cache_re="$(sed -n "s/^tracked_cache_re='\(.*\)'$/\1/p" "$guard")"
if [[ -z "$cache_re" ]]; then
  echo "FAIL [cache regex form] 无法从守卫源码取出 tracked_cache_re" >&2
  fail=$((fail + 1))
elif [[ "$cache_re" == *'(?:'* ]]; then
  echo "FAIL [cache regex form] 正则是 PCRE 形态（含 (?:…)，GNU grep -E 会静默丢分支）：$cache_re" >&2
  fail=$((fail + 1))
else
  # 三个命中样例各自锚定一条分支：第一分支（node_modules）、第二分支的
  # .vitest-cache 项、第二分支的 .vite 项（不带 node_modules 前缀，只有整支
  # 有效才可能命中）。少任何一个，对应分支失效都看不出来。
  cache_hit_samples=(
    'node_modules/.vite/vitest/CACHEDIR.TAG'
    'web/.vitest-cache/_metadata.json'
    '.vite/vitest/CACHEDIR.TAG'
  )
  cache_miss_sample='internal/handlers/rules.go'
  cache_impls=()
  for cand in "$(type -P grep || true)" /usr/bin/grep /bin/grep \
              "$(command -v ggrep || true)" /opt/homebrew/bin/ggrep /usr/local/bin/ggrep \
              /opt/homebrew/bin/grep /usr/local/bin/grep; do
    [[ -n "$cand" && -x "$cand" ]] || continue
    # 同一个二进制经多条候选路径命中时只测一次，计数才反映真实实现数。
    dup=0
    for seen in ${cache_impls[@]+"${cache_impls[@]}"}; do
      if [[ "$seen" == "$cand" ]]; then
        dup=1
        break
      fi
    done
    if [[ $dup -eq 1 ]]; then
      continue
    fi
    cache_impls+=("$cand")
  done
  cache_form_bad=0
  for impl in "${cache_impls[@]}"; do
    for sample in "${cache_hit_samples[@]}"; do
      set +e
      printf '%s\n' "$sample" | "$impl" -E "$cache_re" >/dev/null 2>&1
      rc_hit=$?
      set -e
      if [[ ${rc_hit} -ne 0 ]]; then
        echo "FAIL [cache regex form] $impl 未命中应命中样例（rc=${rc_hit}，期望 0）：$sample" >&2
        cache_form_bad=1
      fi
    done
    set +e
    printf '%s\n' "$cache_miss_sample" | "$impl" -E "$cache_re" >/dev/null 2>&1
    rc_miss=$?
    set -e
    if [[ ${rc_miss} -ne 1 ]]; then
      echo "FAIL [cache regex form] $impl 未命中样例返回 rc=${rc_miss}（期望 1，2 表示正则错误）：$cache_re" >&2
      cache_form_bad=1
    fi
  done
  # POSIX ERE 严格模拟：走 awk 的 ERE 引擎而不是独立实现，绕开「同一实现自证
  # 自身」的自洽陷阱。ENVIRON 传值避免 -v 的反斜杠转义改写正则。
  for sample in "${cache_hit_samples[@]}"; do
    if ! printf '%s\n' "$sample" | CACHE_RE="$cache_re" awk \
        'BEGIN { re = ENVIRON["CACHE_RE"] } $0 ~ re { hit = 1 } END { exit(hit ? 0 : 1) }' >/dev/null 2>&1; then
      echo "FAIL [cache regex form] POSIX ERE 严格模拟（awk）未命中应命中样例：$sample" >&2
      cache_form_bad=1
    fi
  done
  if ! printf '%s\n' "$cache_miss_sample" | CACHE_RE="$cache_re" awk \
      'BEGIN { re = ENVIRON["CACHE_RE"] } $0 ~ re { hit = 1 } END { exit(hit ? 1 : 0) }' >/dev/null 2>&1; then
    echo "FAIL [cache regex form] POSIX ERE 严格模拟（awk）命中未命中样例或无法执行：$cache_re" >&2
    cache_form_bad=1
  fi
  if [[ $cache_form_bad -eq 0 ]]; then
    echo "ok   [cache regex form] ${#cache_impls[@]} 种 grep 实现 + POSIX ERE 严格模拟下分支齐全：$cache_re"
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
  fi
fi

# 0e) 正则不可执行时必须硬失败——把夹具副本换成任何 grep 都拒绝的形态（括号
#     不配对），守卫必须红且把原因说成 fail-closed；吞错实现会在此给假绿。
reset_fixture
bad_cache_line="tracked_cache_re='(^|/)node_modules/|('"
awk -v line="$bad_cache_line" '/^tracked_cache_re=/ { print line; next } { print }' \
  "$tmp_root/scripts/check-no-audit-artifacts.sh" >"$tmp_root/scripts/guard.tmp"
mv "$tmp_root/scripts/guard.tmp" "$tmp_root/scripts/check-no-audit-artifacts.sh"
assert_bad "invalid cache regex fails closed" "fail-closed"

# 0f) 扫描器临时文件必须在 macOS/BSD mktemp 下也真正随机：历史后缀模板会退化为
#     固定路径，残留文件与并发进程互相阻断。先预置旧字面残留验证不再误伤，再以
#     8 路并发跑同一夹具；成功退出后本次创建的扫描器/清单临时文件均须清理。
reset_fixture
mkdir -p "$tmp_root/tmp"
stale_scan="$tmp_root/tmp/audit-guard-scan.XXXXXX.pl"
printf 'stale\n' >"$stale_scan"
set +e
residual_out="$(run_guard_with_tmpdir 2>&1)"
residual_rc=$?
set -e
if [[ $residual_rc -ne 0 ]]; then
  echo "FAIL [stale scanner temp does not block guard] rc=$residual_rc" >&2
  echo "$residual_out" >&2
  fail=$((fail + 1))
else
  echo "ok   [stale scanner temp does not block guard]"
  pass=$((pass + 1))
fi
rm -f "$stale_scan"
concurrent_pids=()
for i in 1 2 3 4 5 6 7 8; do
  run_guard_with_tmpdir >"$tmp_root/concurrent.$i.out" 2>&1 &
  concurrent_pids+=("$!")
done
concurrent_failed=0
for pid in "${concurrent_pids[@]}"; do
  if ! wait "$pid"; then
    concurrent_failed=$((concurrent_failed + 1))
  fi
done
if [[ $concurrent_failed -ne 0 ]]; then
  echo "FAIL [concurrent scanner temps] $concurrent_failed/8 guards failed" >&2
  for i in 1 2 3 4 5 6 7 8; do
    printf '%s\n' "--- concurrent.$i ---" >&2
    cat "$tmp_root/concurrent.$i.out" >&2
  done
  fail=$((fail + 1))
elif compgen -G "$tmp_root/tmp/audit-guard-scan.*" >/dev/null || compgen -G "$tmp_root/tmp/audit-guard-files.*" >/dev/null; then
  echo "FAIL [scanner temp cleanup] temporary files remain after concurrent guards" >&2
  fail=$((fail + 1))
else
  echo "ok   [8 concurrent guards and scanner temp cleanup]"
  pass=$((pass + 1))
fi

# 1) 未跟踪文件同样入扫描面（不 git add，直接写）
reset_fixture
mkdir_in internal/handlers/untracked_behavior_test.go
cat >"$tmp_root/internal/handlers/untracked_behavior_test.go" <<'EOF'
package handlers

func Test87_P2_01_nodesImportValidatesAccessURL(t *testing.T) {
}
EOF
assert_bad "untracked file content scan" "untracked_behavior_test.go"

# 2) 下划线/小驼峰测试名形态（受控文件）
reset_fixture
mkdir_in internal/services/conflict_matrix_test.go
cat >"$tmp_root/internal/services/conflict_matrix_test.go" <<'EOF'
package services

func TestP1_1_conflictMatrixDisablesPlaintextSideOfMixedTLSPort(t *testing.T) {
}

func TestU7_P5_2_checkManualCertExpiration_expiryReadFailureLogsAtErrorLevel(t *testing.T) {
}
EOF
git -C "$tmp_root" add -f internal/services/conflict_matrix_test.go
assert_bad "TestP1_/TestU7_ test names" "conflict_matrix_test.go"

# 3) 小写轮次形态（注释行）
reset_fixture
mkdir_in internal/services/round_refs.go
cat >"$tmp_root/internal/services/round_refs.go" <<'EOF'
package services

// 门钉测：r75b 起覆盖；r76 / r77 / r78 追加；r41 与 r53-56 同形态。
func noop() {}
EOF
assert_bad "lowercase rNN forms" "round_refs.go"

# 4) 轮次测试文件名（.ts spec）
reset_fixture
mkdir_in web/src/views/round40_latency.spec.ts
cat >"$tmp_root/web/src/views/round40_latency.spec.ts" <<'EOF'
import { describe } from 'vitest'
describe('latency', () => {})
EOF
git -C "$tmp_root" add -f web/src/views/round40_latency.spec.ts
assert_bad "roundNN spec filename" "round40_latency.spec.ts"

# 5) 审计报告文件名（docs/audit 目录 + 报告文件）
reset_fixture
mkdir_in docs/audit/keep.md
echo "x" >"$tmp_root/docs/audit/keep.md"
git -C "$tmp_root" add -f docs/audit/keep.md
assert_bad "docs/audit/ directory" "docs/audit/keep.md"

reset_fixture
mkdir_in audit89-summary.md
echo "x" >"$tmp_root/audit89-summary.md"
git -C "$tmp_root" add -f audit89-summary.md
assert_bad "auditNN report filename" "audit89-summary.md"

reset_fixture
mkdir -p "$tmp_root/reports/audit85"
echo "x" >"$tmp_root/reports/audit85/notes.md"
git -C "$tmp_root" add -f reports/audit85/notes.md
assert_bad "auditNN directory" "reports/audit85/notes.md"

# 5b) 分隔符型轮次命名（audit_96 / audit-round-96 / round-96）——路径规则必须
#     是「分隔符可选」而非「紧跟数字」：只认紧邻形态时这类目录/文件名能正常
#     git add 入库，而守卫仍宣告通过（审计产物逃逸公网仓）。
for round_dir in audit_96 audit-round-96 round-96; do
  reset_fixture
  mkdir -p "$tmp_root/reports/$round_dir"
  echo "x" >"$tmp_root/reports/$round_dir/notes.md"
  git -C "$tmp_root" add -f "reports/$round_dir/notes.md"
  assert_bad "separator round dir ($round_dir)" "reports/$round_dir/notes.md"
done

reset_fixture
mkdir_in docs/round-96-notes.md
echo "x" >"$tmp_root/docs/round-96-notes.md"
git -C "$tmp_root" add -f docs/round-96-notes.md
assert_bad "separator round filename" "docs/round-96-notes.md"

# 6) 连写形态（无短横线）
reset_fixture
mkdir_in scripts/deploy.sh
cat >"$tmp_root/scripts/deploy.sh" <<'EOF'
#!/usr/bin/env bash
# 平台口径（A83H）：主节点固定 host 网络。
echo ok
EOF
assert_bad "bare concat id form" "scripts/deploy.sh"

# 7) 各扩展名的注释面（Dockerfile/.yml/.sql/.mod/entrypoint/Caddyfile/.dockerignore）
reset_fixture
cat >"$tmp_root/Dockerfile" <<'EOF'
FROM scratch
# 版本号硬编码点之一（FE-8）
EOF
assert_bad "Dockerfile comment" "Dockerfile"

reset_fixture
mkdir_in docker-compose.yml
cat >"$tmp_root/docker-compose.yml" <<'EOF'
# 主从共用配置锚点（INFRA-4）
services: {}
EOF
assert_bad "yaml comment" "docker-compose.yml"

reset_fixture
mkdir_in internal/db/migrate.sql
cat >"$tmp_root/internal/db/migrate.sql" <<'EOF'
-- 索引收敛（PD-01）
SELECT 1;
EOF
assert_bad "sql comment" "internal/db/migrate.sql"

reset_fixture
cat >"$tmp_root/caddydeps-go.mod" <<'EOF'
// placeholder
EOF
mv "$tmp_root/caddydeps-go.mod" "$tmp_root/extra.mod"
cat >"$tmp_root/extra.mod" <<'EOF'
module extra

// 零依赖共享表库（PLUG-N3）
EOF
assert_bad "go.mod comment" "extra.mod"

reset_fixture
cat >"$tmp_root/docker-entrypoint.sh" <<'EOF'
#!/bin/sh
# supervisor pid 标记（U8b-2）
echo ok
EOF
assert_bad "entrypoint comment" "docker-entrypoint.sh"

reset_fixture
mkdir_in config/Caddyfile
cat >"$tmp_root/config/Caddyfile" <<'EOF'
# 两段重试循环合并（INFRA-R1）
{
	admin 127.0.0.1:2019
}
EOF
assert_bad "Caddyfile comment" "config/Caddyfile"

reset_fixture
cat >"$tmp_root/.dockerignore" <<'EOF'
# 本地工具会话目录（U8b-1）
.omp/
EOF
assert_bad ".dockerignore comment" ".dockerignore"

# 8) 跨行拆字：编号被换行拆开
reset_fixture
mkdir_in docs/notes.md
printf '沿革：第 83\n轮引入该行为。\n' >"$tmp_root/docs/notes.md"
assert_bad "cross-line 第 N 轮" "docs/notes.md"

# 9) 裸轮次 + 审计动作（无「第」）
reset_fixture
mkdir_in internal/handlers/stored_rule_gate.go
cat >"$tmp_root/internal/handlers/stored_rule_gate.go" <<'EOF'
package handlers

// 保存门拦新载荷，此门兜直改 DB/69 轮修复前落库的存量。
func noop() {}
EOF
assert_bad "bare N 轮 + audit verb" "internal/handlers/stored_rule_gate.go"

# 10) 斜杠并列轮次
reset_fixture
mkdir_in internal/services/version_triggers_test.go
cat >"$tmp_root/internal/services/version_triggers_test.go" <<'EOF'
package services

// 簿记列不 bump 集群版本（第 25/26 轮审计）——语义列真实变化才 bump。
func TestBookkeepingDoesNotBump(t *testing.T) {}
EOF
assert_bad "slash-parallel 第 N/N 轮" "internal/services/version_triggers_test.go"

# 11) 跨行拆字 + 续行注释前缀
reset_fixture
mkdir_in internal/services/update_round_test.go
printf '// 中止口径镜像另一侧（第\n// 66 轮漏收敛本侧）——须落 skipped 终态。\n' \
  >"$tmp_root/internal/services/update_round_test.go"
assert_bad "cross-line with comment prefix" "internal/services/update_round_test.go"

# 12) 注释头截断残骸：裸轮次收尾于全角标点
reset_fixture
mkdir_in cmd/notes.go
cat >"$tmp_root/cmd/notes.go" <<'EOF'
package main

// 71 轮）：中置空格同族——畸形 Host 不得反射。
func noop() {}
EOF
assert_bad "comment-head round residue" "cmd/notes.go"

# 13) 中文数字轮次 + 审计归属
reset_fixture
mkdir_in internal/services/deny_attribution.go
cat >"$tmp_root/internal/services/deny_attribution.go" <<'EOF'
package services

// 审计 （第五轮）：deny 归因应含 refs 合并集。
func noop() {}
EOF
assert_bad "audit + chinese-numeral round" "internal/services/deny_attribution.go"

# 13a) 被清洗截断的注释残骸：历史 问题:
reset_fixture
mkdir_in internal/handlers/residue.go
cat >"$tmp_root/internal/handlers/residue.go" <<'EOF'
package handlers

// 历史 问题: 限制请求体大小防止 OOM。
func noop() {}
EOF
assert_bad "truncated audit residue comment" "internal/handlers/residue.go"

# 13b) 扩展名大小写：.MD / .Go 与 .md / .go 同等入扫描面
reset_fixture
mkdir_in docs/NOTES.MD
cat >"$tmp_root/docs/NOTES.MD" <<'EOF'
版本号硬编码点之一（FE-8）
EOF
git -C "$tmp_root" add -f docs/NOTES.MD
assert_bad "uppercase extension scanned" "NOTES.MD"

reset_fixture
mkdir_in internal/x/CONV.GO
cat >"$tmp_root/internal/x/CONV.GO" <<'EOF'
package x

// 版本号硬编码点之一（FE-8）
func noop() {}
EOF
git -C "$tmp_root" add -f internal/x/CONV.GO
assert_bad "uppercase .GO scanned" "CONV.GO"

# 13c) 含 NUL 的文本扩展名文件不得整文件跳过（跳过即逃逸面）——直接红
reset_fixture
mkdir_in docs/payload.md
printf '正常首行\n\x00\n版本号硬编码点之一（FE-8）\n' >"$tmp_root/docs/payload.md"
git -C "$tmp_root" add -f docs/payload.md
assert_bad "NUL-containing text file is not skipped" "NUL"

# 13d) JSON/HTML/conf 内容面：夹具字符串与模板文案里的审计编号必须命中
# （JSON 字符串值没有注释前缀——内容面按全文扫描，否则这里会假绿）。
reset_fixture
mkdir_in web/src/fixtures/cases.json
cat >"$tmp_root/web/src/fixtures/cases.json" <<'EOF'
{
  "note": "第 83 轮修复：夹具口径"
}
EOF
assert_bad "json fixture string scanned" "cases.json"

reset_fixture
mkdir_in web/src/components/notice.html
cat >"$tmp_root/web/src/components/notice.html" <<'EOF'
<!-- 组件说明 -->
<p>第 83 轮修复说明</p>
EOF
assert_bad "html text node scanned" "notice.html"

reset_fixture
mkdir_in deploy/site.conf
cat >"$tmp_root/deploy/site.conf" <<'EOF'
# 第 83 轮修复：监听口径
listen 443 ssl;
EOF
assert_bad "conf comment scanned" "deploy/site.conf"

# 13e) npm 生成物豁免：package-lock.json 的 integrity 是混合大小写 base64，
# 全量入面会产生噪声且人工审计标注不会写进生成物——内容面显式豁免该单一路径。
reset_fixture
mkdir_in web/package-lock.json
cat >"$tmp_root/web/package-lock.json" <<'EOF'
{
  "name": "lazy-balancer-web",
  "packages": {
    "node_modules/example": {
      "integrity": "sha512-AbCdEf0123GhIjKlMnOpQrStUvWxYz+/0123456789ABCDEF=="
    }
  }
}
EOF
assert_good "package-lock.json content exempt"

# 14) .gitignore 双向校验：少一行 / 多一行都失败
reset_fixture
grep -v '^\*\*/r\[0-9\]\*_test\.go$' "$tmp_root/.gitignore" >"$tmp_root/.gitignore.tmp"
mv "$tmp_root/.gitignore.tmp" "$tmp_root/.gitignore"
assert_bad "gitignore missing pattern" "模式表不一致"

reset_fixture
sed -i.bak 's|^\*\*/audit\[0-9\]\*_test\.go$|**/audit[0-9]*_test.go\n**/legacy[0-9]*_test.go|' "$tmp_root/.gitignore"
rm -f "$tmp_root/.gitignore.bak"
assert_bad "gitignore extra pattern" "模式表不一致"

# 14b) 重复同一模式行必须失败：比较口径不得先去重（sort -u 会把重复行折叠，
# 两侧相等后「逐行一致」契约失效）。
reset_fixture
sed -i.bak 's|^\*\*/audit\[0-9\]\*_test\.go$|**/audit[0-9]*_test.go\n**/audit[0-9]*_test.go|' "$tmp_root/.gitignore"
rm -f "$tmp_root/.gitignore.bak"
assert_bad "gitignore duplicate pattern" "重复模式行"

# 14c) 作业面扩展：Python 批量脚本与无扩展名约定文件（.gitignore/.gitattributes）
# 的注释块同样是审计编号的真实混入面（scripts/check-bulk-edit-safety.sh 已把
# scripts/*.py 计为作业面，两条守卫口径必须一致）。
reset_fixture
mkdir_in scripts/oneoff_merge.py
cat >"$tmp_root/scripts/oneoff_merge.py" <<'EOF'
# 版本号硬编码点之一（FE-8）
print("ok")
EOF
assert_bad "python script comment" "oneoff_merge.py"

reset_fixture
printf '\n# 版本号硬编码点之一（FE-8）\n' >>"$tmp_root/.gitignore"
assert_bad "gitignore comment" ".gitignore"

reset_fixture
cat >"$tmp_root/.gitattributes" <<'EOF'
# 版本号硬编码点之一（FE-8）
* text=auto
EOF
assert_bad "gitattributes comment" ".gitattributes"

# 14d) 扫描面正向集合：守卫声明的扩展名/无扩展名文件集合必须与自检期望集合
# 互为镜像（漏登记或悄悄加面都红），并逐项造夹具证明真的入面——只比声明文本
# 证明不了正则生效，只跑行为发现不了「声明加了、期望清单没跟」。
expected_scan_exts=(go ts vue js css md markdown txt sh yml yaml sql mod json html htm toml conf py)
expected_scan_names=(Dockerfile docker-entrypoint.sh .dockerignore .gitignore .gitattributes Caddyfile)
decl_exts="$(sed -n 's/^content_scan_exts=(\(.*\))$/\1/p' "$guard")"
decl_names="$(sed -n 's/^content_scan_basenames=(\(.*\))$/\1/p' "$guard")"
if [[ -z "$decl_exts" || -z "$decl_names" ]]; then
  echo "FAIL [scan surface declaration] 守卫未声明 content_scan_exts/content_scan_basenames" >&2
  fail=$((fail + 1))
else
  read -r -a got_scan_exts <<<"$decl_exts"
  read -r -a got_scan_names <<<"$decl_names"
  if [[ "$(printf '%s\n' "${expected_scan_exts[@]}" | LC_ALL=C sort)" \
      != "$(printf '%s\n' "${got_scan_exts[@]}" | LC_ALL=C sort)" ]]; then
    echo "FAIL [scan surface exts] 声明集合与期望集合不一致：" >&2
    diff <(printf '%s\n' "${expected_scan_exts[@]}" | LC_ALL=C sort) \
         <(printf '%s\n' "${got_scan_exts[@]}" | LC_ALL=C sort) | sed 's/^/  /' >&2 || true
    fail=$((fail + 1))
  elif [[ "$(printf '%s\n' "${expected_scan_names[@]}" | LC_ALL=C sort)" \
      != "$(printf '%s\n' "${got_scan_names[@]}" | LC_ALL=C sort)" ]]; then
    echo "FAIL [scan surface names] 声明集合与期望集合不一致：" >&2
    diff <(printf '%s\n' "${expected_scan_names[@]}" | LC_ALL=C sort) \
         <(printf '%s\n' "${got_scan_names[@]}" | LC_ALL=C sort) | sed 's/^/  /' >&2 || true
    fail=$((fail + 1))
  else
    echo "ok   [scan surface sets] declaration mirrors expectation"
    pass=$((pass + 1))
  fi
fi

# 逐项行为探针：每个声明形态都要真的把审计编号扫出来（按各自注释语法造样本；
# 文档/JSON/HTML 走全文扫描，故直接写文本）。
for ext in "${expected_scan_exts[@]}"; do
  reset_fixture
  mkdir_in "docs/probe_surface.$ext"
  case "$ext" in
    go|ts|vue|js|mod) probe_body="// 版本号硬编码点之一（FE-8）" ;;
    css) probe_body="/* 版本号硬编码点之一（FE-8） */" ;;
    sql) probe_body="-- 版本号硬编码点之一（FE-8）" ;;
    md|markdown|txt|json|html|htm) probe_body="版本号硬编码点之一（FE-8）" ;;
    *) probe_body="# 版本号硬编码点之一（FE-8）" ;;
  esac
  printf '%s\n' "$probe_body" >"$tmp_root/docs/probe_surface.$ext"
  assert_bad "scan surface .$ext" "probe_surface.$ext"
done

for name in "${expected_scan_names[@]}"; do
  reset_fixture
  mkdir_in "probe/$name"
  if [[ "$name" == "Dockerfile" ]]; then
    # 派生文件名（Dockerfile.dev）与主文件同族入面。
    printf '# 版本号硬编码点之一（FE-8）\nFROM scratch\n' >"$tmp_root/probe/Dockerfile.dev"
    assert_bad "scan surface Dockerfile family" "Dockerfile.dev"
  else
    printf '# 版本号硬编码点之一（FE-8）\n' >"$tmp_root/probe/$name"
    assert_bad "scan surface $name" "$name"
  fi
done


# 1) 百分位
reset_fixture
mkdir_in docs/metrics.md
cat >"$tmp_root/docs/metrics.md" <<'EOF'
延迟展示 P50 / P95 / P99，面板按 P50-P99 分位聚合；latencyP50 与 latencyP99 均取自同一次采样。
EOF
assert_good "percentiles"

# 2) 版本串
reset_fixture
mkdir_in README.md
cat >"$tmp_root/README.md" <<'EOF'
当前版本 v2.3.8，接口示例里的 version 形如 v2.3.x / v2.3.8-beta。
EOF
assert_good "version strings"

# 3) 十六进制与哈希算法名
reset_fixture
mkdir_in docs/integrity.md
cat >"$tmp_root/docs/integrity.md" <<'EOF'
校验和 6307a9696f5711f84bcb8b25f07894de68a64a0ed4a1cc7e990562dd3084f210，
算法 SHA-256 / HMAC-SHA256，掩码 0xAB12CD，摘要 d8acc96f25ad07c8e3a595a23c797324。
EOF
assert_good "hex digests and hash names"

# 4) 协议与产品 token
reset_fixture
mkdir_in internal/x/tokens.go
cat >"$tmp_root/internal/x/tokens.go" <<'EOF'
package x

// HTTP/3 与 QUIC、TLS 1.3、IPV6 监听、PID1 进程、X509 证书链、ED25519 密钥、
// HS256 签名、UTF-8 编码、DNS-01 质询、AES-256-GCM、X-LB-GeoIP-Country-Code、
// REQUEST-942 规则、LBF1 文件魔数、SHA256 摘要；容量边界 MAX-1 与 MIN-1。
func noop() {}
EOF
assert_good "protocol and product tokens"

# 4b) 时间格式骨架（日志文件名/时间戳布局注释）不误判
reset_fixture
mkdir_in internal/services/rotation.go
cat >"$tmp_root/internal/services/rotation.go" <<'EOF'
package services

// 轮转副本尾部形态 `-<yyyyMMdd>T<HH-mm-ss>.<毫秒>-size.log`；
// 展示口径 HH:mm:ss，导出文件名 yyyyMMdd-HHmmss（时间格式骨架，非编号）。
func noop() {}
EOF
assert_good "time format skeleton"

# 5) 合法测试函数名（不含编号形态）
reset_fixture
mkdir_in internal/services/legit_test.go
cat >"$tmp_root/internal/services/legit_test.go" <<'EOF'
package services

func TestApplyConfigFromTx(t *testing.T) {}
func TestTLSRuleWithoutCertIsNotPublished(t *testing.T) {}
func TestParseIPv6Address(t *testing.T) {}
func TestWatchdogMatchesTLSCertificateRenderGate(t *testing.T) {}
EOF
assert_good "legit test names"

# 6) 中文“轮播/轮询”不误判
reset_fixture
mkdir_in docs/ui.md
cat >"$tmp_root/docs/ui.md" <<'EOF'
首页轮播与后端轮询相互独立；第 1 轮播位与第 3 轮询间隔都在设置页可调。
EOF
assert_good "carousel and polling wording"

# 7) 循环轮次表述（心跳/共识/降频/并列打点/区间）不误判
reset_fixture
mkdir_in internal/services/loop_rounds.go
cat >"$tmp_root/internal/services/loop_rounds.go" <<'EOF'
package services

// 心跳：小时级一条（60 轮×60s）；连续 2 轮共识即放行；失败 5 轮后降频为
// 每 10 轮一次；有界循环（最多 3 轮）补采尾部；第 0/6 轮打点。
// 第 61-119 轮静默；单次保存最多 3 轮 → 3R；9 轮内应只在第 0/6 轮打点。
func noop() {}
EOF
assert_good "loop round wording"

# 8) 注释头以循环轮次开头也不误判
reset_fixture
mkdir_in internal/services/loop_head_test.go
cat >"$tmp_root/internal/services/loop_head_test.go" <<'EOF'
package services

// 3 轮渲染 → 3R）。批次级一次求值后透传。
func TestLoopHeadComment(t *testing.T) {
	// When 从节点连打两轮心跳窗口（120 轮）
	_ = 0
}
EOF
assert_good "loop round wording at comment head"

# 8c) 词元边界误报面：合法文件名里含 round<digit>/audit<digit> 连写片段
#     （backg|round2、ground2）不是审计产物——宽名族正则若不带边界会阻断
#     合法提交，并把排查方向误导到「审计记录不得提交」。
reset_fixture
mkdir_in web/src/assets/background2.png
printf 'PNG' >"$tmp_root/web/src/assets/background2.png"
git -C "$tmp_root" add -f web/src/assets/background2.png
mkdir_in docs/ground2.md
printf '地面层说明\n' >"$tmp_root/docs/ground2.md"
git -C "$tmp_root" add -f docs/ground2.md
assert_good "word-boundary round/audit tokens in legit file names"

# 8d) 反向控制：带边界的真实审计产物仍须命中（收紧不得把门变成恒绿）。
reset_fixture
mkdir_in reports/round106-notes.md
printf 'x\n' >"$tmp_root/reports/round106-notes.md"
git -C "$tmp_root" add -f reports/round106-notes.md
assert_bad "boundary roundNN artifact still hits" "reports/round106-notes.md"

reset_fixture
mkdir_in docs/audit106-summary.md
printf 'x\n' >"$tmp_root/docs/audit106-summary.md"
git -C "$tmp_root" add -f docs/audit106-summary.md
assert_bad "boundary auditNN artifact still hits" "docs/audit106-summary.md"

# ===========================================================================
# 9) 网络口径与日志文件名骨架（IPv6-only、YYYYMMDD-HHMMSS）不误判
reset_fixture
mkdir_in internal/handlers/ip_family.go
cat >"$tmp_root/internal/handlers/ip_family.go" <<'EOF'
package handlers

// IPv4 优先（页面展示口径不变）；接口只有 IPv6（IPv6-only 主机/容器）。
// 第一个非 link-local/未指定的 IPv6（IPv6-only 主机不再显示为空）。
// rotationCopyTimberjack：<stem>-YYYYMMDD-HHMMSS-size.log[.gz]
func noop() {}
EOF
assert_good "IPv6-only and log filename skeleton"

# 10) 产品词 + 版本号形态（Windows-1252 / Chrome-120）不误判
reset_fixture
mkdir_in docs/charset.md
cat >"$tmp_root/docs/charset.md" <<'EOF'
Charset Windows-1252 与 UA 片段 Chrome-120 均按字节处理，不做转码。
EOF
assert_good "Windows-1252 and Chrome-120"

# 11) PATH 中无 perl：内容扫描依赖 perl，缺失必须 fail-closed（非零退出、
#     原因含 perl、且不得宣告通过）——该分支是守卫的安全底线，此前零覆盖。
#     与 bulk 守卫的「缺 python3」用例同法：裁出只含基础工具的 PATH。
reset_fixture
mkdir_in internal/handlers/needs_perl.go
cat >"$tmp_root/internal/handlers/needs_perl.go" <<'EOF'
package handlers

func noop() {}
EOF
noperl_bin="$tmp_root/bin-noperl"
mkdir -p "$noperl_bin"
# 以系统 bin 目录为基线逐项软链、仅剔除 perl*：裁到「最小工具集」会让守卫在
# 别的缺失上先行失败，掩盖「缺 perl」这一被测分支。
for bin_dir in /bin /usr/bin /usr/local/bin; do
  [[ -d "$bin_dir" ]] || continue
  for tool_path in "$bin_dir"/*; do
    tool_name="${tool_path##*/}"
    case "$tool_name" in
      perl|perl[0-9.]*) continue ;;
    esac
    [[ -e "$noperl_bin/$tool_name" ]] || ln -sf "$tool_path" "$noperl_bin/$tool_name"
  done
done
if [[ -e "$noperl_bin/perl" ]]; then
  echo "FAIL [missing perl] 夹具 PATH 仍含 perl" >&2
  fail=$((fail + 1))
else
  set +e
  out="$( cd "$tmp_root" && env -i PATH="$noperl_bin" HOME="${HOME:-/tmp}" /bin/bash scripts/check-no-audit-artifacts.sh 2>&1 )"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "FAIL [missing perl] 缺 perl 时守卫静默放行（RC=0）" >&2
    echo "$out" >&2
    fail=$((fail + 1))
  elif [[ "$out" != *perl* ]]; then
    echo "FAIL [missing perl] 失败原因未指明依赖 perl" >&2
    echo "$out" >&2
    fail=$((fail + 1))
  elif [[ "$out" == *"no audit artifacts tracked"* ]]; then
    echo "FAIL [missing perl] 缺 perl 时仍宣告守卫通过" >&2
    fail=$((fail + 1))
  else
    echo "ok   [missing perl] fail-closed: $(printf '%s\n' "$out" | grep -m1 'ERROR')"
    pass=$((pass + 1))
  fi
fi

echo "selftest: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
