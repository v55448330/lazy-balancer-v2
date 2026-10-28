#!/usr/bin/env bash
# 修复台账反向核对门：把「提交/台账声称修复」与代码事实对照，防止再次出现
# 「台账说修了、代码没改」。
#
# 用法：
#   scripts/check-fix-claims.sh --self-test
#   scripts/check-fix-claims.sh --ledger <file.tsv> [--commit <rev>]
#
# 台账格式（竖线分隔，首行表头固定；空字段保留）：
#   id|status|evidence|reason
#   - status: fixed | maintained | falsified | retired
#   - fixed 必须有 evidence，多个用 ';' 分隔，支持：
#   - code:<path>:<line>:<token>   该行必须包含 token（token 可含空格；在剥注释
#                                  视图上比对——注释里的 token 不是可执行证据）
#       test:[<dir>/]<TestName>      仓库内必须存在（未注释的）func <TestName>( 或 test('<name>'
#                                   （<dir>/ 前缀把搜索面限定到该目录；不带前缀时全仓搜索，
#                                    但同名测试命中多个文件即判失败——否则把目标包里的
#                                    测试删掉后，别的包里的同名通用测试会冒充证据）
#       ftest:<literal>              web/tests 内必须出现该字面量（describe/it 标题等，不得在注释里）
#       script:<path>                脚本必须存在（且可执行）
#       spec:<path>                  前端 spec 文件必须存在，且为 web/tests 下的 *.spec.ts
#   - test/ftest/script/spec 的空名字/空字面量/空路径一律判失败（grep 空模式恒命中＝假绿）；
#     spec 只接受前端用例路径——任意存在的文件不构成「前端 spec」证据。
#   - 带 <dir>/ 的 test: 前缀必须是存在的目录（拼错路径不得退化为「全仓搜索」）。
#   - test/ftest/code 的匹配先剥注释：被注释掉的声明/标题/token 不是可执行证据
#     （原文 grep 会把它们判成命中）。code: 用「删注释内容但保持行数」的视图，
#     行号不漂移；code: 的 token 不得为空（同属空值判失败口径）。
#   - maintained / falsified / retired 必须写非空 reason
#
# --commit 会解析该提交 message 中的 "Fixes: ID[,ID...]" 行，要求每个 ID 在台账
# 中状态为 fixed。没有 Fixes 行的提交不做 ID 断言（仍校验台账自身）。
#
# 退出码：0 全部通过；1 存在未闭合/证据缺失；2 用法或文件错误。
set -euo pipefail

usage() {
  # 头部注释的行区间随文档增长——以「退出码」行（末行文档）为终点机械截取，
  # 不再手抄行号（抄错时 --help 会截断或多打一行 set 语句）。
  sed -n "2,$(grep -n '^# 退出码' "$0" | head -1 | cut -d: -f1)p" "$0" | sed 's/^# \{0,1\}//'
}

root="$(cd "$(dirname "$0")/.." && pwd)"

# 剥注释视图（行数保持，供 code: 证据按行号比对）：注释内容替换为空串而非
# 删行——code: 证据以「第 N 行」定位，删行会让行号漂移，比对落到相邻行（假
# 命中或假失败）。逐文件状态独立：行注释（`//`，含行尾）截断；`/* ... */`
# 整段（含跨行）清空，块注释结束后的同行代码保留。
# 注释标记只在「行首（可带缩进）或紧跟空白」时成立：脚本里的 glob/路径片段
# （`scripts/*.py`、`**/*_test.go`）与字符串里的 URL（`http://...`）不是注释
# 起点——否则一次前导块态会把后续真实代码行整段吞掉（假失败）。
strip_comments_keep_lines() { # <file>
  awk '
    # 标记在「行首或前一字符为空白」时的位置；0 表示不存在。
    function marker_index(s, m,   p, i, before) {
      p = 1
      while (1) {
        i = index(substr(s, p), m)
        if (i == 0) return 0
        i = p + i - 1
        before = (i == 1) ? "" : substr(s, i - 1, 1)
        if (before == "" || before == " " || before == "\t") return i
        p = i + 1
      }
    }
    {
      rest = $0; kept = ""
      while (1) {
        if (inblock) {
          q = index(rest, "*/")
          if (q == 0) { rest = ""; break }
          rest = substr(rest, q + 2); inblock = 0
          continue
        }
        p = marker_index(rest, "/*"); c = marker_index(rest, "//")
        if (c > 0 && (p == 0 || c < p)) { rest = substr(rest, 1, c - 1); break }
        if (p == 0) break
        kept = kept substr(rest, 1, p - 1)
        rest = substr(rest, p + 2); inblock = 1
      }
      print kept rest
    }
  ' "$1"
}

# 剥注释视图中真正命中的文件清单（扩展正则，每行一个）：先按原文挑候选文件，再
# 逐文件走同一份剥注释视图复检（单源——三份内联 awk 各自漂移会让某个证据形态
# 悄悄放宽）。返回文件而不是布尔：test: 证据要按「命中文件数」判定歧义，布尔
# 结果无法区分「唯一命中」与「跨包同名测试冒充」。
code_match_files() { # <pattern> <dir>
  local pattern="$1" dir="$2" files file view
  files="$(grep -RlE --include='*_test.go' --include='*.spec.ts' -- "$pattern" "$dir" 2>/dev/null || true)"
  [ -z "$files" ] && return 0
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    view="$(strip_comments_keep_lines "$file")" || continue
    if grep -Eq -- "$pattern" <<< "$view"; then
      printf '%s\n' "$file"
    fi
  done <<< "$files"
}

# 是否存在匹配（布尔包装，保留调用点可读性）。
code_has_regex() { # <pattern> <dir>
  [ -n "$(code_match_files "$1" "$2")" ]
}

# 同 code_has_regex，但按字面量（ftest 标题可含正则元字符）。
code_has_literal() { # <literal> <dir>
  local literal="$1" dir="$2" files file view
  files="$(grep -RlF --include='*.spec.ts' -- "$literal" "$dir" 2>/dev/null || true)"
  [ -z "$files" ] && return 1
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    view="$(strip_comments_keep_lines "$file")" || continue
    if grep -Fq -- "$literal" <<< "$view"; then
      return 0
    fi
  done <<< "$files"
  return 1
}

self_test() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/fix-claims.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/scripts"
  cp "$0" "$tmp/scripts/check-fix-claims.sh"
  mkdir -p "$tmp/internal/demo"
  printf 'package demo\n\nfunc TestDemoBehavior(t *testing.T) {}\n' > "$tmp/internal/demo/demo_test.go"
  printf 'package demo\n\nvar token = "demo-marker"\n' > "$tmp/internal/demo/demo.go"
  # 前端用例与脚本证据形态的夹具：真实命中、可执行、存在但不可执行三形态。
  mkdir -p "$tmp/web/tests"
  printf "test('demo-fixture-title', () => {})\n" > "$tmp/web/tests/demo.spec.ts"
  mkdir -p "$tmp/tools"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/tools/ok.sh"
  chmod +x "$tmp/tools/ok.sh"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/tools/noexec.sh"
  chmod -x "$tmp/tools/noexec.sh"

  # 1) 正例：code 行含 token + test 存在 + maintained 有理由
  cat > "$tmp/ok.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/demo.go:3:demo-marker;test:TestDemoBehavior|
F-2|maintained||user ruled intentional
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok.tsv >/dev/null); then
    echo "SELFTEST FAIL: 正例被拒" >&2; return 1
  fi

  # 2) 反例：code token 不存在
  cat > "$tmp/bad-code.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/demo.go:3:not-there|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-code.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: token 不存在却通过" >&2; return 1
  fi

  # 3) 反例：test 不存在
  cat > "$tmp/bad-test.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:TestDoesNotExist|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-test.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 测试不存在却通过" >&2; return 1
  fi

  # 4) 反例：fixed 无证据
  cat > "$tmp/no-evidence.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed||
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger no-evidence.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: fixed 无证据却通过" >&2; return 1
  fi

  # 5) 反例：maintained 无理由
  cat > "$tmp/no-reason.tsv" <<'EOF'
id|status|evidence|reason
F-1|maintained||
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger no-reason.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: maintained 无理由却通过" >&2; return 1
  fi

  # 6) 反例：提交声称 Fixes 但台账状态非 fixed
  (cd "$tmp" && git init -q && git config user.email t@t && git config user.name t && \
    git add -A && git commit -qm "fix: x

Fixes: F-2")
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok.tsv --commit HEAD >/dev/null 2>&1); then
    echo "SELFTEST FAIL: Fixes 声明非 fixed 项却通过" >&2; return 1
  fi

  # 7) 正例：ftest 命中真实前端用例 + script 存在且可执行
  cat > "$tmp/ok-forms.tsv" <<'EOF'
id|status|evidence|reason
F-3|fixed|ftest:demo-fixture-title;script:tools/ok.sh|
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok-forms.tsv >/dev/null); then
    echo "SELFTEST FAIL: ftest/script 正例被拒" >&2; return 1
  fi

  # 8) 反例：ftest 字面量在前端用例中不存在
  cat > "$tmp/bad-ftest.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|ftest:absent-frontend-title|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-ftest.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: ftest 字面量不存在却通过" >&2; return 1
  fi

  # 9) 反例：ftest 空字面量（grep -F '' 恒命中，必须显式拒绝）
  cat > "$tmp/empty-ftest.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|ftest:|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger empty-ftest.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: ftest 空字面量却通过" >&2; return 1
  fi

  # 10) 反例：script 不存在
  cat > "$tmp/bad-script.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|script:tools/absent.sh|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-script.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: script 不存在却通过" >&2; return 1
  fi

  # 11) 反例：script 存在但不可执行
  cat > "$tmp/noexec-script.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|script:tools/noexec.sh|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger noexec-script.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: script 不可执行却通过" >&2; return 1
  fi

  # 12) 正例：spec 指向真实前端用例（web/tests 下的 *.spec.ts）
  cat > "$tmp/ok-spec.tsv" <<'EOF'
id|status|evidence|reason
F-4|fixed|spec:web/tests/demo.spec.ts|
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok-spec.tsv >/dev/null); then
    echo "SELFTEST FAIL: spec 正例被拒" >&2; return 1
  fi

  # 13) 反例：spec 目标文件不存在
  cat > "$tmp/bad-spec.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|spec:web/tests/absent.spec.ts|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-spec.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: spec 不存在却通过" >&2; return 1
  fi

  # 14) 反例：spec 路径为空（与其他证据形态的空值拒绝同口径）
  cat > "$tmp/empty-spec.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|spec:|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger empty-spec.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: spec 路径为空却通过" >&2; return 1
  fi

  # 15) 反例：路径存在但不是前端 spec（任意文件存在即通过＝假绿；spec 语义是
  #     web/tests 下的前端用例）
  cat > "$tmp/non-spec.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|spec:internal/demo/demo.go|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger non-spec.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 非前端 spec 路径却通过" >&2; return 1
  fi

  # 16) 反例：行注释里的 Go 测试声明（原文 grep 会命中，剥注释视图不得命中）
  printf 'package demo\n\n// func TestCommentedOut(t *testing.T) {}\n' > "$tmp/internal/demo/commented_test.go"
  cat > "$tmp/commented-test.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:TestCommentedOut|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger commented-test.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 注释掉的 Go 测试声明被当作证据" >&2; return 1
  fi

  # 17) 反例：块注释里的 Go 测试声明（多行 /* */ 状态必须被剥离）
  cat > "$tmp/internal/demo/block_test.go" <<'EOF'
package demo

/*
func TestBlockCommentedOut(t *testing.T) {
}
*/
EOF
  cat > "$tmp/block-commented-test.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:TestBlockCommentedOut|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger block-commented-test.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 块注释里的 Go 测试声明被当作证据" >&2; return 1
  fi

  # 18) 反例：注释掉的前端用例标题
  printf "// test('commented-frontend-title', () => {})\n" > "$tmp/web/tests/commented.spec.ts"
  cat > "$tmp/commented-ftest.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|ftest:commented-frontend-title|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger commented-ftest.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 注释掉的前端用例标题被当作证据" >&2; return 1
  fi

  # 19) 正例：剥注释不得把真实声明吃掉（同上两个夹具目录里真实用例仍在）
  cat > "$tmp/real-decl.tsv" <<'EOF'
id|status|evidence|reason
F-5|fixed|test:TestDemoBehavior;ftest:demo-fixture-title|
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger real-decl.tsv >/dev/null); then
    echo "SELFTEST FAIL: 剥注释后真实声明被误判为缺失" >&2; return 1
  fi

  # 20) 反例：web/tests 下的非 spec 文件（路径以 spec 形态存在但扩展名不符）
  printf 'fixture\n' > "$tmp/web/tests/notes.md"
  cat > "$tmp/near-miss-spec.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|spec:web/tests/notes.md|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger near-miss-spec.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: web/tests 下的非 spec 文件被当作前端 spec 证据" >&2; return 1
  fi

  # 21) 反例：code: 证据的 token 只出现在行注释里（原文 grep 会命中；剥注释
  #     视图不得命中）。行注释行号固定在第 3 行。
  cat > "$tmp/internal/demo/comments.go" <<'EOF'
package demo

// demo-line-comment-token
var realLineValue = "demo-real-token" // demo-trailing-comment-token

/*
demo-block-comment-token
*/
var realBlockNeighbor = "demo-after-block"
EOF
  cat > "$tmp/code-line-comment.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/comments.go:3:demo-line-comment-token|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger code-line-comment.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 行注释里的 token 被当作 code: 证据" >&2; return 1
  fi

  # 22) 反例：code: 证据的 token 只出现在块注释里
  cat > "$tmp/code-block-comment.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/comments.go:7:demo-block-comment-token|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger code-block-comment.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 块注释里的 token 被当作 code: 证据" >&2; return 1
  fi

  # 23) 正例：剥注释不得改行号——真实代码行（行尾带行注释）与块注释结束后的
  #     代码行仍按原行号命中。
  cat > "$tmp/code-real-line.tsv" <<'EOF'
id|status|evidence|reason
F-6|fixed|code:internal/demo/comments.go:4:demo-real-token;code:internal/demo/comments.go:9:demo-after-block|
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger code-real-line.tsv >/dev/null); then
    echo "SELFTEST FAIL: 剥注释后真实代码行被误判为缺失（行号不得漂移）" >&2; return 1
  fi

  # 24) 反例：code: 证据 token 为空（`grep -F ''` 恒命中，与其他形态的空值
  #     拒绝同口径）
  cat > "$tmp/code-empty-token.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/demo.go:3:|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger code-empty-token.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: code: 空 token 被当作证据" >&2; return 1
  fi

  # 25) 反例：同一行里代码之后的行尾注释同样不算证据（剥注释只保留代码段）
  cat > "$tmp/code-trailing-comment.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/comments.go:4:demo-trailing-comment-token|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger code-trailing-comment.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 行尾注释里的 token 被当作 code: 证据" >&2; return 1
  fi

  # 26) 反例：test: 名字为空（模式退化为「任意测试声明」，与其他空值拒绝同口径）
  cat > "$tmp/empty-test-name.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger empty-test-name.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: test: 空名字被当作证据" >&2; return 1
  fi

  # 27) 反例：ftest 字面量只出现在前端用例的块注释里（跨行 /* */ 必须整体剥离；
  #     剥注释逻辑单源后此形态与 test: 证据同口径）
  cat > "$tmp/web/tests/block-commented.spec.ts" <<'EOF'
/*
 * test('block-commented-frontend-title', () => {})
 */
test('real-frontend-title', () => {})
EOF
  cat > "$tmp/block-commented-ftest.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|ftest:block-commented-frontend-title|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger block-commented-ftest.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 块注释里的前端用例标题被当作证据" >&2; return 1
  fi

  # 28) 跨包同名测试：别处存在同名测试时，裸 test:<Name> 无法证明目标包的测试还在
  #     （把目标包的那个删掉，别处的通用同名测试仍会让台账通过）→ 必须判失败；
  #     写成 test:<dir>/<Name> 限定搜索面才通过。
  mkdir -p "$tmp/internal/other"
  printf 'package other\n\nfunc TestDemoBehavior(t *testing.T) {}\n' > "$tmp/internal/other/other_test.go"
  cat > "$tmp/ambiguous-test.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:TestDemoBehavior|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ambiguous-test.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 跨包同名测试被当作唯一证据" >&2; return 1
  fi
  cat > "$tmp/scoped-test.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:internal/demo/TestDemoBehavior|
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger scoped-test.tsv >/dev/null); then
    echo "SELFTEST FAIL: 带目录前缀的 test: 证据被拒" >&2; return 1
  fi

  # 29) 反例：目标包里的测试被删（只有别的包还有同名测试）——带前缀的写法必须判失败，
  #     这正是「台账声称修了、目标包测试没了」的实际形态。
  cat > "$tmp/scoped-gone.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:internal/other/TestAbsentInThatPackage;test:internal/demo/TestDemoBehavior|
EOF
  sed -e 's|^func TestDemoBehavior|func TestDemoBehaviorX|' "$tmp/internal/demo/demo_test.go" >"$tmp/internal/demo/demo_test.go.tmp"
  mv "$tmp/internal/demo/demo_test.go.tmp" "$tmp/internal/demo/demo_test.go"
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger scoped-gone.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 目标包测试已删但台账通过" >&2; return 1
  fi
  printf 'package demo\n\nfunc TestDemoBehavior(t *testing.T) {}\n' > "$tmp/internal/demo/demo_test.go"

  # 30) 反例：test: 的目录前缀指向不存在的目录——不得退化为全仓搜索
  cat > "$tmp/scoped-missing-dir.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:internal/absent/TestDemoBehavior|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger scoped-missing-dir.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: test: 目录前缀不存在却通过（退化为全仓搜索）" >&2; return 1
  fi

  # 31) 参数缺值必须按「用法错误」退出 2：旧实现落到 `shift 2` 失败，以 1 退出，
  #     与「台账有未闭合项」不可区分（调用方无法判错因、也拿不到用法提示）。
  set +e
  ( cd "$tmp" && bash scripts/check-fix-claims.sh --ledger >/dev/null 2>&1 )
  local missing_value_rc=$?
  set -e
  if [ "$missing_value_rc" -ne 2 ]; then
    echo "SELFTEST FAIL: --ledger 缺参数值的退出码应为 2，实际 ${missing_value_rc}" >&2; return 1
  fi
  set +e
  ( cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok.tsv --commit >/dev/null 2>&1 )
  local missing_commit_rc=$?
  set -e
  if [ "$missing_commit_rc" -ne 2 ]; then
    echo "SELFTEST FAIL: --commit 缺参数值的退出码应为 2，实际 ${missing_commit_rc}" >&2; return 1
  fi

  echo "fix-claims selftest: PASS"
}

ledger=""
commit=""
while [ $# -gt 0 ]; do
  case "$1" in
    # 缺值必须以「用法错误」退出（文档承诺的退出码 2），不能落到 `shift 2`
    # 失败——那在 set -e 下直接以 1 退出，与「台账存在未闭合项」（同样是 1）
    # 无法区分，调用方既拿不到用法提示也判不出错因。
    --ledger)
      if [ $# -lt 2 ] || [ -z "${2:-}" ]; then
        echo "用法错误：$1 缺少参数值" >&2
        usage >&2
        exit 2
      fi
      ledger="$2"
      shift 2
      ;;
    --commit)
      if [ $# -lt 2 ] || [ -z "${2:-}" ]; then
        echo "用法错误：$1 缺少参数值" >&2
        usage >&2
        exit 2
      fi
      commit="$2"
      shift 2
      ;;
    --self-test) self_test; exit $? ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$ledger" ]; then
  echo "用法错误：需要 --ledger <file.tsv> 或 --self-test" >&2
  exit 2
fi
[ -f "$ledger" ] || { echo "台账不存在: $ledger" >&2; exit 2; }
cd "$root"

fail=0
status_file="$(mktemp "${TMPDIR:-/tmp}/fix-claims-status.XXXXXX")"
trap 'rm -f "$status_file"' EXIT
line_no=0
while IFS='|' read -r id status evidence reason; do
  line_no=$((line_no + 1))
  [ "$line_no" -eq 1 ] && [ "$id" = "id" ] && continue
  [ -z "${id// /}" ] && continue
  case "$status" in
    fixed)
      if [ -z "${evidence// /}" ]; then
        echo "FAIL ${id}: fixed 但无 evidence" >&2
        fail=1
        continue
      fi
      IFS=';' read -ra items <<< "$evidence" || true
      for item in "${items[@]:-}"; do
        item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$item" ] && continue
        case "$item" in
          code:*)
            rest="${item#code:}"
            path="${rest%%:*}"
            rest="${rest#*:}"
            line="${rest%%:*}"
            token="${rest#*:}"
            if [ ! -f "$path" ]; then
              echo "FAIL ${id}: 证据文件不存在: $path" >&2; fail=1; continue
            fi
            case "$line" in ''|*[!0-9]*) echo "FAIL ${id}: 行号非法: $line" >&2; fail=1; continue;; esac
            if [ -z "${token// /}" ]; then
              echo "FAIL ${id}: code: token 为空（grep -F '' 恒命中，不构成证据）" >&2; fail=1; continue
            fi
            # 比对在「剥注释但保持行数」的视图上做：注释里的 token 不是可执行
            # 证据（原文行匹配会让「只有注释提到 X」的台账声明通过）。
            code_view="$(strip_comments_keep_lines "$path")" || { echo "FAIL ${id}: 无法读取证据文件: $path" >&2; fail=1; continue; }
            line_content="$(printf '%s\n' "$code_view" | sed -n "${line}p")"
            case "$line_content" in
              *"$token"*) ;;
              *) echo "FAIL ${id}: $path:$line 不含 token（注释里的 token 不算证据）: $token" >&2; fail=1 ;;
            esac
            ;;
          test:*)
            rest="${item#test:}"
            test_dir=""
            name="$rest"
            # 可选路径前缀 test:<dir>/<Name>：把搜索面限定到该包/目录，去掉
            # 「目标包测试被删、别处同名通用测试顶替」的冒名通道。
            if [[ "$rest" == */* ]]; then
              test_dir="${rest%/*}"
              name="${rest##*/}"
              if [ -z "${test_dir// /}" ]; then
                echo "FAIL ${id}: test: 目录前缀为空（形如 test:<dir>/<Name>）" >&2; fail=1; continue
              fi
              if [ ! -d "$test_dir" ]; then
                echo "FAIL ${id}: test: 证据目录不存在: $test_dir" >&2; fail=1; continue
              fi
            fi
            # 空名字会退化成 `^[[:space:]]*test[(]` 通用前缀——前端/后端任一条
            # 测试行都能满足，与 ftest/spec 的空值拒绝同口径必须显式失败。
            if [ -z "${name// /}" ]; then
              echo "FAIL ${id}: test: 名字为空（空模式命中任意测试声明，不构成证据）" >&2; fail=1; continue
            fi
            # 声明必须落在代码行（行首 func / test(）上；注释掉的声明不算证据。
            test_scope="${test_dir:-.}"
            matches="$(code_match_files "^[[:space:]]*func[[:space:]]+${name}[(]|^[[:space:]]*test[(]['\"]${name}" "$test_scope")"
            match_count="$(printf '%s\n' "$matches" | grep -c . || true)"
            if [ "$match_count" -eq 0 ]; then
              echo "FAIL ${id}: 测试不存在（注释掉的声明不算证据）: ${name}（搜索面: ${test_scope}）" >&2; fail=1
            elif [ -z "$test_dir" ] && [ "$match_count" -gt 1 ]; then
              # 跨包同名：全仓搜索命中多处时无法证明「目标包的那个测试还在」，
              # 必须由台账显式写出目录（test:<dir>/<Name>）消歧。
              echo "FAIL ${id}: test: 同名测试在多处命中，无法证明目标包仍有该测试——请写成 test:<dir>/${name}：" >&2
              printf '%s\n' "$matches" | sed 's/^/  /' >&2
              fail=1
            fi
            ;;
          ftest:*)
            literal="${item#ftest:}"
            if [ -z "$literal" ]; then
              echo "FAIL ${id}: ftest 字面量为空（grep -F '' 恒命中，不构成证据）" >&2; fail=1; continue
            fi
            if ! code_has_literal "$literal" web/tests; then
              echo "FAIL ${id}: 前端用例不存在（注释掉的标题不算证据）: $literal" >&2; fail=1
            fi
            ;;
          spec:*)
            spec="${item#spec:}"
            if [ -z "$spec" ]; then
              echo "FAIL ${id}: spec 路径为空" >&2; fail=1; continue
            fi
            # spec 的语义是「前端用例文件」：任意存在的文件（Go 源码/配置/文档）
            # 都能满足 [ -f ]，那样的形状等于「写一个存在路径即通过」的假绿。
            case "$spec" in
              web/tests/*.spec.ts) ;;
              *) echo "FAIL ${id}: spec 必须是 web/tests 下的 *.spec.ts 前端用例: $spec" >&2; fail=1; continue ;;
            esac
            if [ ! -f "$spec" ]; then
              echo "FAIL ${id}: 前端 spec 不存在: $spec" >&2; fail=1
            fi
            ;;
          script:*)
            script="${item#script:}"
            if [ -z "$script" ]; then
              echo "FAIL ${id}: script 路径为空" >&2; fail=1; continue
            fi
            if [ ! -f "$script" ]; then
              echo "FAIL ${id}: 脚本不存在: $script" >&2; fail=1
            elif [ ! -x "$script" ]; then
              echo "FAIL ${id}: 脚本不可执行: $script" >&2; fail=1
            fi
            ;;
          *)
            echo "FAIL ${id}: 未知证据形态: $item" >&2; fail=1
            ;;
        esac
      done
      ;;
    maintained|falsified|retired)
      if [ -z "${reason// /}" ]; then
        echo "FAIL ${id}: $status 但 reason 为空" >&2; fail=1
      fi
      ;;
    *)
      echo "FAIL ${id}: 非法 status: ${status:-<空>}" >&2; fail=1
      ;;
  esac
  printf '%s\t%s\n' "$id" "$status" >> "$status_file"
done < "$ledger"

if [ -n "$commit" ]; then
  msg="$(git log -1 --format=%B "$commit" 2>/dev/null)" || { echo "无法读取提交 $commit" >&2; exit 2; }
  claims="$(printf '%s\n' "$msg" | sed -n 's/^Fixes:[[:space:]]*//p' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d')"
  for id in $claims; do
    st="$(awk -F'\t' -v id="$id" '$1==id{print $2}' "$status_file" | tail -1)"
    if [ "$st" != "fixed" ]; then
      echo "FAIL 提交声称修复 ${id}，但台账状态=${st:-缺失}" >&2
      fail=1
    fi
  done
fi

if [ "$fail" -ne 0 ]; then
  echo "fix-claims: FAILED" >&2
  exit 1
fi
echo "fix-claims: OK ($((line_no - 1)) 条台账)"
