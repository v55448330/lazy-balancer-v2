#!/usr/bin/env bash
# check-bulk-edit-safety 自测：事故形态必红、正常形态必绿、无 dry-run 脚本必红。
#
# 诊断输出一律落在本次运行的 mktemp 目录内（${work}/bulk-*.out，随 trap 删除）：
# 固定 /tmp 文件名在同机并行跑、或多工作树同时跑自检时互相覆盖——读到别轮或
# 上一轮的旧文件会把错因指到错误的方向（旧文件残留还会让 grep 假命中）。
set -euo pipefail
src_script="$(cd "$(dirname "$0")/.." && pwd)/check-bulk-edit-safety.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/bulk-guard.XXXXXX")"
trap 'rm -rf "$work"' EXIT

mk_repo() {
  local d="$1"; mkdir -p "$d"; cd "$d"
  git init -q; git config user.email t@example.com; git config user.name t
  mkdir -p scripts
  cp "$src_script" scripts/check-bulk-edit-safety.sh
  chmod +x scripts/check-bulk-edit-safety.sh
}

# 1) 事故形态：一次删除大量 () -> 必须失败
mk_repo "$work/fail"
python3 - <<'PY'
lines = [f"func f{i}() {{ return g{i}() }}" for i in range(200)]
open('a.go','w').write("\n".join(lines)+"\n")
PY
git add -A && git commit -qm base
python3 - <<'PY'
s=open('a.go').read().replace('()','')
open('a.go','w').write(s)
PY
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk1.out" 2>&1; then
  echo "SELFTEST FAIL: 事故形态未拦截"; cat "${work}/bulk1.out"; exit 1
fi

# 2) 正常形态：少量新增/删除 -> 必须通过
mk_repo "$work/ok"
printf 'package x\nfunc A() {}\n' > a.go
git add -A && git commit -qm base
printf 'package x\nfunc A() {}\nfunc B() {}\n' > a.go
if ! bash scripts/check-bulk-edit-safety.sh >"${work}/bulk2.out" 2>&1; then
  echo "SELFTEST FAIL: 正常形态被拦截"; cat "${work}/bulk2.out"; exit 1
fi

# 3) 无 dry-run 的遍历写盘脚本 -> 必须失败
mk_repo "$work/script"
cat > scripts/rewrite.py <<'PY'
import os, re
for dp, _, fs in os.walk('.'):
    for f in fs:
        if f.endswith('.go'):
            p=os.path.join(dp,f)
            open(p,'w').write(re.sub(r'\\s+$','',open(p).read()))
PY
git add -A && git commit -qm base
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk3.out" 2>&1; then
  echo "SELFTEST FAIL: 无 dry-run 脚本未拦截"; cat "${work}/bulk3.out"; exit 1
fi

# 4) 写盘特征的非紧邻 -i 形态（sed -E -i / sed -e … -i / perl -pi -e /
#    python -c）带遍历但无 dry-run -> 必须失败。紧邻 sed -i 匹配漏掉这些形态，
#    而它们正是「全仓正则改写」事故的实际作业形态。
expect_write_shape_blocked() {
  local label="$1" body="$2"
  mk_repo "$work/$3"
  printf '%s\n' "$body" > scripts/rewrite.sh
  chmod +x scripts/rewrite.sh
  git add -A && git commit -qm base
  if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-shape.out" 2>&1; then
    echo "SELFTEST FAIL: $label 形态未拦截"; cat "${work}/bulk-shape.out"; exit 1
  fi
  if ! grep -q '缺少 --dry-run' "${work}/bulk-shape.out"; then
    echo "SELFTEST FAIL: $label 形态命中原因错误（应为缺 dry-run 的批量改写脚本）"; cat "${work}/bulk-shape.out"; exit 1
  fi
}

expect_write_shape_blocked 'sed -E -i' \
  "find . -name '*.go' | xargs sed -E -i 's/[[:space:]]+\$//'" sed-E-i
expect_write_shape_blocked 'sed -e … -i' \
  "find . -name '*.go' -exec sed -e 's/a/b/' -i {} +" sed-e-i
expect_write_shape_blocked 'perl -pi -e' \
  "for f in *.go; do perl -pi -e 's/a/b/' \"\$f\"; done" perl-pi

# python -c 直接批量写（无 dry-run）——匹配 python[0-9.]* -c
mk_repo "$work/python-c"
cat > scripts/rewrite.sh <<'SH'
for f in *.go; do python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().rstrip())' "$f"; done
SH
git add -A && git commit -qm base
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-pyc.out" 2>&1; then
  echo "SELFTEST FAIL: python -c 批量写形态未拦截"; cat "${work}/bulk-pyc.out"; exit 1
fi
# 与其余 7 种形态同口径断原因：只断 rc 时「因别的原因失败」（例如脚本根本没被
# 识别为批量写）也算通过，无法区分拦截点。
if ! grep -q '缺少 --dry-run' "${work}/bulk-pyc.out"; then
  echo "SELFTEST FAIL: python -c 形态命中原因错误（应为缺 dry-run 的批量改写脚本）"; cat "${work}/bulk-pyc.out"; exit 1
fi

# 5) 同一批写盘形态但显式声明只读模式 -> 必须放行（收窄误报面）
mk_repo "$work/dryrun"
cat > scripts/rewrite.sh <<'SH'
#!/usr/bin/env bash
# 支持 --dry-run：只打印将改写的文件，不写盘
set -euo pipefail
for f in *.go; do
  if [[ "${1:-}" == "--dry-run" ]]; then echo "would rewrite $f"; continue; fi
  sed -E -i 's/a/b/' "$f"
done
SH
git add -A && git commit -qm base
if ! bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-dry.out" 2>&1; then
  echo "SELFTEST FAIL: 带 --dry-run 的批量脚本被误拦"; cat "${work}/bulk-dry.out"; exit 1
fi

# 6) PATH 中无 python3：通道 B 必须 fail-closed（不得打印「变更形态正常」）。
# 事故形态已就绪（与用例 1 同形），守卫必须以非零退出并把「需要 python3」
# 作为原因——旧实现让 read 拿到空值、阈值按 0 处理，静默放行 RC=0。
mk_repo "$work/nopython"
for i in $(seq 1 200); do printf 'func f%s() { return g%s() }\n' "$i" "$i"; done > a.go
git add -A && git commit -qm base
sed -e 's/()//g' a.go > a.go.tmp && mv a.go.tmp a.go
bin="$work/bin-nopython"; mkdir -p "$bin"
for tool in bash sh git grep dirname cat sed awk uname mktemp; do
  p="$(type -P "$tool" || true)"
  [[ -n "$p" ]] && ln -sf "$p" "$bin/$tool"
done
if [[ -e "$bin/python3" ]]; then
  echo "SELFTEST FAIL: 夹具 PATH 仍含 python3"; exit 1
fi
set +e
env -i PATH="$bin" HOME="${HOME:-/tmp}" /bin/bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-nopy.out" 2>&1
rc=$?
set -e
if (( rc == 0 )); then
  echo "SELFTEST FAIL: 缺 python3 时通道 B 静默放行（RC=0）"; cat "${work}/bulk-nopy.out"; exit 1
fi
if ! grep -q 'python3' "${work}/bulk-nopy.out"; then
  echo "SELFTEST FAIL: 缺 python3 的失败原因未指明依赖"; cat "${work}/bulk-nopy.out"; exit 1
fi
if grep -q '变更形态正常' "${work}/bulk-nopy.out"; then
  echo "SELFTEST FAIL: 缺 python3 时仍宣告「变更形态正常」"; cat "${work}/bulk-nopy.out"; exit 1
fi

# 7) 部分暂存：暂存区有正常改动时，未暂存的事故形态仍必须被检查。
# 旧实现按 staged > worktree 互斥取值，staged 非空即让未暂存改动完全跳过
# 通道 B——而第二段改动往往正是批量变换。
mk_repo "$work/partial"
printf 'package x\nfunc A() {}\n' > a.go
for i in $(seq 1 200); do printf 'func f%s() { return g%s() }\n' "$i" "$i"; done > b.go
git add -A && git commit -qm base
# 暂存区：a.go 的正常改动（不会触发通道 B）
printf 'package x\nfunc A() {}\nfunc B() {}\n' > a.go
git add a.go
# 未暂存：b.go 的一次性批量删括号（事故形态）
sed -e 's/()//g' b.go > b.go.tmp && mv b.go.tmp b.go
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-partial.out" 2>&1; then
  echo "SELFTEST FAIL: 部分暂存时未暂存事故形态未拦截"; cat "${work}/bulk-partial.out"; exit 1
fi

# 8) 遍历特征不含 find/for 的等价事故写法：git ls-files | xargs + 写盘 -i
#    （无 dry-run）必须同样拦下——只认 find/for 会让第一道闸门漏检该形态。
mk_repo "$work/xargs-ls-files"
cat > scripts/rewrite.sh <<'SH'
git ls-files -z '*.go' | xargs -0 perl -pi -e 's/\(\)//g'
SH
chmod +x scripts/rewrite.sh
git add -A && git commit -qm base
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-lsfiles.out" 2>&1; then
  echo "SELFTEST FAIL: git ls-files | xargs 批量写形态未拦截"; cat "${work}/bulk-lsfiles.out"; exit 1
fi
if ! grep -q '缺少 --dry-run' "${work}/bulk-lsfiles.out"; then
  echo "SELFTEST FAIL: git ls-files | xargs 形态命中原因错误"; cat "${work}/bulk-lsfiles.out"; exit 1
fi

# 9) 多提交变更集：中段提交做批量删括号、末段提交只加注释。干净树默认只看
#    HEAD^..HEAD（假绿），必须能由 BULK_EDIT_RANGE 显式指定范围抓到。
mk_repo "$work/range"
for i in $(seq 1 200); do printf 'func f%s() { return g%s() }\n' "$i" "$i"; done > a.go
git add -A && git commit -qm base
sed -e 's/()//g' a.go > a.go.tmp && mv a.go.tmp a.go
git add -A && git commit -qm "batch delete parens"
printf '// trailing comment\n' >> a.go
git add -A && git commit -qm "comment only"
if ! bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-range-default.out" 2>&1; then
  echo "SELFTEST FAIL: 干净树默认只看末条提交时不应命中（夹具前提不成立）"; cat "${work}/bulk-range-default.out"; exit 1
fi
if ! grep -q '仅检查最近一条提交' "${work}/bulk-range-default.out"; then
  echo "SELFTEST FAIL: 干净树未明示「仅检查最近一条提交」的边界"; cat "${work}/bulk-range-default.out"; exit 1
fi
if BULK_EDIT_RANGE=HEAD~2..HEAD bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-range-out.out" 2>&1; then
  echo "SELFTEST FAIL: BULK_EDIT_RANGE 指定的中段批量删括号未拦截"; cat "${work}/bulk-range-out.out"; exit 1
fi
if ! grep -q 'BULK_EDIT_RANGE 显式范围' "${work}/bulk-range-out.out"; then
  echo "SELFTEST FAIL: 显式范围命中原因未标注范围来源"; cat "${work}/bulk-range-out.out"; exit 1
fi

# 10) 未跟踪的无 dry-run 批量脚本必须拦下：事故作业序是「写脚本 → 跑门禁 →
#     提交」，通道 A 用 git ls-files（仅受控文件）枚举时，脚本尚未 git add
#     的窗口里守卫假绿——恰是最需要它的时间窗。
mk_repo "$work/untracked"
printf 'base\n' > .gitkeep
git add -A && git commit -qm base
cat > scripts/rewrite.py <<'PY'
import os, re
for dp, _, fs in os.walk('.'):
    for f in fs:
        if f.endswith('.go'):
            p=os.path.join(dp,f)
            open(p,'w').write(re.sub(r'\\s+$','',open(p).read()))
PY
# 刻意不 git add：脚本处于未跟踪状态
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-untracked.out" 2>&1; then
  echo "SELFTEST FAIL: 未跟踪的无 dry-run 脚本未拦截"; cat "${work}/bulk-untracked.out"; exit 1
fi
if ! grep -q '缺少 --dry-run' "${work}/bulk-untracked.out"; then
  echo "SELFTEST FAIL: 未跟踪脚本命中原因错误（应为缺 dry-run）"; cat "${work}/bulk-untracked.out"; exit 1
fi

# 11) 仓内 scripts/ 之外的批量脚本同样受检：放在仓根（tools/hack 同理）的无
#     dry-run 遍历写盘脚本必须红。枚举面写死 scripts/ 时它对第一道闸门完全
#     不可见——历史事故形态正是「临时脚本 + 全仓正则」。
mk_repo "$work/repo-root-script"
printf 'base\n' > .gitkeep
git add -A && git commit -qm base
cat > rewrite.py <<'PY'
import os, re
for dp, _, fs in os.walk('internal'):
    for f in fs:
        if not f.endswith('.go'):
            continue
        p = os.path.join(dp, f)
        open(p, 'w').write(re.sub(r'\s+$', '', open(p).read()))
PY
git add -A && git commit -qm script
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-root-script.out" 2>&1; then
  echo "SELFTEST FAIL: 仓根的无 dry-run 批量脚本未拦截"; cat "${work}/bulk-root-script.out"; exit 1
fi
if ! grep -q '缺少 --dry-run' "${work}/bulk-root-script.out"; then
  echo "SELFTEST FAIL: 仓根脚本命中原因错误（应为缺 dry-run）"; cat "${work}/bulk-root-script.out"; exit 1
fi

# 12) 同一仓根脚本显式声明只读模式后必须放行（收窄新枚举面的误报），且输出
#     必须明示「仓外脚本不受控」的作用域边界——否则使用者会误以为全覆盖。
mk_repo "$work/repo-root-dry"
printf 'base\n' > .gitkeep
git add -A && git commit -qm base
cat > rewrite.py <<'PY'
import os, re, sys
DRY = '--dry-run' in sys.argv
for dp, _, fs in os.walk('internal'):
    for f in fs:
        if not f.endswith('.go'):
            continue
        p = os.path.join(dp, f)
        new = re.sub(r'\s+$', '', open(p).read())
        if not DRY:
            open(p, 'w').write(new)
PY
git add -A && git commit -qm script
if ! bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-root-dry.out" 2>&1; then
  echo "SELFTEST FAIL: 带 dry-run 的仓根批量脚本被误拦"; cat "${work}/bulk-root-dry.out"; exit 1
fi
if ! grep -q '仓外/临时脚本不受控' "${work}/bulk-root-dry.out"; then
  echo "SELFTEST FAIL: 通道 A 未明示作用域边界（仓外脚本不受控）"; cat "${work}/bulk-root-dry.out"; exit 1
fi

# 14) 自检目录不是免检区：豁免面是显式文件名清单，不是目录前缀。放进
#     scripts/tests/ 的非自检脚本必须仍受通道 A 约束——目录前缀排除会把这
#     整个目录变成「把批量改写脚本挪进去就绕过 checkpoint 闸门」的缺口。
mk_repo "$work/tests-dir-not-exempt"
mkdir -p scripts/tests
cat > scripts/tests/rewrite.py <<'PY'
import os, re
for root, _dirs, files in os.walk('.'):
    for name in files:
        if name.endswith('.go'):
            p = os.path.join(root, name)
            with open(p) as fh:
                text = fh.read()
            with open(p, 'w') as fh:
                fh.write(re.sub(r'\(\)', '', text))
PY
git add -A && git commit -qm script
if bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-tests-dir.out" 2>&1; then
  echo "SELFTEST FAIL: scripts/tests/ 下的非自检批量脚本未拦截"; cat "${work}/bulk-tests-dir.out"; exit 1
fi
if ! grep -q '缺少 --dry-run' "${work}/bulk-tests-dir.out"; then
  echo "SELFTEST FAIL: scripts/tests/ 非自检脚本命中原因错误（应为缺 dry-run）"; cat "${work}/bulk-tests-dir.out"; exit 1
fi

# 15) 显式登记的自检文件名仍必须豁免（豁免面按名单生效，不是把目录整体纳入
#     受检）：自检脚本的夹具里刻意写无 dry-run 脚本，把它们拉回通道 A 会让
#     整套门禁自相矛盾。
mk_repo "$work/tests-dir-exempt"
mkdir -p scripts/tests
cat > scripts/tests/guard-selftest.sh <<'SH'
#!/usr/bin/env bash
find . -name '*.go' -exec sed -i 's/a/b/' {} +
SH
git add -A && git commit -qm selftest
if ! bash scripts/check-bulk-edit-safety.sh >"${work}/bulk-tests-exempt.out" 2>&1; then
  echo "SELFTEST FAIL: 显式登记的自检脚本被误拦"; cat "${work}/bulk-tests-exempt.out"; exit 1
fi

echo "bulk-edit safety selftest: PASS"