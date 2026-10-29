#!/usr/bin/env bash
# 批量源码编辑安全守卫（事故：2026-10-23 全仓正则删空括号导致 1294 文件损坏）。
#
# 两道检查：
#   A. 脚本静态面：仓内同时具备「遍历源码」与「写盘替换」的脚本必须支持只读
#      模式（--dry-run / DRY_RUN），否则拒绝。枚举面=仓内全部 *.sh / *.py 的
#      已跟踪+未跟踪并集（作业序是「写脚本→跑门禁→提交」，只扫已跟踪会在关键
#      窗口假绿；而枚举面只写 scripts/ 时，放在仓根/tools/hack 的一次性批量
#      脚本完全不受第一道闸门约束——历史事故形态正是「临时脚本 + 全仓正则」）。
#      写盘特征覆盖非紧邻 -i 的常见形态（sed -E -i / sed -e … -i / perl -pi -e /
#      python -c）——只认「sed -i 紧邻」等于对最常见的批量改写作业形态失效。
#      边界（必须可见，不得给「已受控」的错觉）：仓外脚本（/tmp/xxx.py 等）
#      无法枚举，通道 B 的形态门只对空括号族有效——批量改写请先 checkpoint。
#   B. 变更形态面：对当前变更集（staged 与 worktree 各查一段，两者皆空时查
#      HEAD^..HEAD）统计空括号
#      `()` / `（）` 的删除量；一次删除 ≥100 且新增不足其 1/5，判为「批量删括号」
#      事故形态。阈值可用 BULK_PAREN_MIN / BULK_PAREN_RATIO 覆盖。
#      干净树时只能看到最近一条提交——多提交变更集请用 BULK_EDIT_RANGE 显式
#      指定范围（CI/评审传 origin/<base>...HEAD），否则中段提交的批量删除不可见。
#      该通道依赖 python3 计数：缺失或统计失败一律 fail-closed（拒绝静默通过），
#      与 check-no-audit-artifacts.sh 对缺 perl 的取向一致。
#      通道 A 的豁免面是**显式文件名**清单（本守卫 + 六个守卫自检），不是目录
#      前缀：按 `^scripts/tests/` 排除会让放进该目录的任何脚本免检，把真实批量
#      改写脚本挪进去即绕过唯一一道「必须先 checkpoint」的静态闸门。
#
# 用法：bash scripts/check-bulk-edit-safety.sh [--self-test]
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
cd "$root"

paren_min="${BULK_PAREN_MIN:-100}"
paren_ratio="${BULK_PAREN_RATIO:-5}" # removed > added*ratio 视为异常

# 自检豁免面：显式文件名清单 + 长度断言，口径与 check-no-audit-artifacts.sh 的
# content_exempt_paths 一致。此前按目录前缀 `^scripts/tests/` 排除，导致该目录下
# 任何脚本（不限于自检）都免检——把真实批量改写脚本挪进去即绕过唯一一道
# 「必须先 checkpoint」的静态闸门。新增自检必须在此显式登记并同步下面的计数。
selftest_exempt_paths=(
  scripts/tests/bulk-edit-safety-selftest.sh
  scripts/tests/dockerfile-copy-gate-selftest.sh
  scripts/tests/guard-selftest.sh
  scripts/tests/race-gate-selftest.sh
  scripts/tests/shuffle-gate-selftest.sh
  scripts/tests/startup-chain-gate-selftest.sh
)
if [[ ${#selftest_exempt_paths[@]} -ne 6 ]]; then
  echo "ERROR: 自检豁免面清单长度漂移（期望 6，实际 ${#selftest_exempt_paths[@]}）——豁免面必须逐项显式登记" >&2
  exit 1
fi
selftest_exempt_re=""
for exempt_path in "${selftest_exempt_paths[@]}"; do
  selftest_exempt_re+="${selftest_exempt_re:+|}^$(printf '%s' "$exempt_path" | sed 's/[.]/\\./g')\$"
done

scan_scripts() {
  local bad=0 f
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    local traverses=0 writes=0 dry=0
    # 遍历特征三类同权：文件系统遍历（find/for/glob）、仓库文件枚举
    # （git ls-files / git grep -l / rg -l）、管道逐文件（xargs）——事故等价
    # 写法 `git ls-files -z '*.go' | xargs -0 perl -pi -e ...` 不含 find/for，
    # 只认前一类会让第一道闸门对它静默放行。
    grep -Eq '(os\.walk|os\.scandir|glob\.glob|Path\([^)]*\)\.glob|find[[:space:]].*-name|for[[:space:]].*in[[:space:]].*\*\.(go|ts|vue)|xargs|git[[:space:]]+ls-files|git[[:space:]]+grep[[:space:]]+[^|;&]*-[A-Za-z]*l|rg[[:space:]][^|;&]*-[A-Za-z]*l)' "$f" && traverses=1 || true
    # 写盘特征必须覆盖「非紧邻 -i」的全部常见形态（sed -E -i / sed -e … -i /
    # perl -pi -e / python -c）：紧邻匹配漏掉它们等于第一道闸门对最常见的
    # 批量改写作业形态失效（事故形态正是「全仓 sed/perl 正则替换」）。
    grep -Eq '(re\.sub|re\.compile|sed[^|;&]*[[:space:]](-[A-Za-z]*i|--in-place)|perl[[:space:]][^|;&]*-[A-Za-z]*i|python[0-9.]*[[:space:]]+-c|shutil\.(copy|move)|\.write_text\(|open\([^)]*["'\'']w|writeFileSync|writeFile\()' "$f" && writes=1 || true
    # dry-run 判据必须在可执行位置：剥掉「整行注释」（行首空白后 #）再匹配。
    # 注释里提一句 --dry-run（事故形态「临时脚本 + 注释 TODO: add --dry-run +
    # git ls-files | xargs perl -pi -e」）不构成只读模式；行尾注释不受影响
    # （同一行存在可执行上下文）。
    grep -v '^[[:space:]]*#' "$f" | grep -Eq -- '(--dry-run|DRY_RUN)' && dry=1 || true
    if (( traverses && writes && !dry )); then
      echo "ERROR: 批量改写脚本缺少 --dry-run 只读模式：$f" >&2
      bad=1
    fi
  # 枚举面必须含未跟踪脚本：事故作业序是「写批量脚本 → 跑门禁 → 提交」，
  # 只扫已跟踪文件使通道 A 在最需要它的时间窗（脚本刚写好、尚未 git add）
  # 完全失效——同仓 test-all.sh（bash -n）与 check-no-audit-artifacts.sh
  # （未跟踪文件入面）都取「受控 + 未跟踪」并集，三处口径必须一致。
  # 枚举面=仓内全部 .sh/.py（不限 scripts/）：仓根/tools/hack 的一次性批量脚本
  # 与 scripts/ 内的脚本按同一口径受检。
  done < <(git ls-files --cached --others --exclude-standard '*.sh' '*.py' \
    | grep -v 'check-bulk-edit-safety.sh' \
    | grep -v -E "$selftest_exempt_re" \
    | grep -v '^web/node_modules/' || true)
  return "$bad"
}

# diff_ranges 列出全部需要检查的变更集（每行一个），而不是互斥取一段：
# 常见的「部分暂存」工作流下 staged 非空会让未暂存改动完全跳过通道 B——
# 而第二段改动往往正是批量变换。
#
# BULK_EDIT_RANGE 显式指定范围（CI/评审传 origin/<base>...HEAD）：干净树时
# 本脚本只能看到最后一条提交，多提交 PR 的中段批量删除不可见——需要全范围
# 检查的调用方必须显式传入。
diff_ranges() {
  if [[ -n "${BULK_EDIT_RANGE:-}" ]]; then
    printf 'RANGE:%s\n' "${BULK_EDIT_RANGE}"
    return 0
  fi
  local any=0
  if ! git diff --cached --quiet; then
    echo "--cached"
    any=1
  fi
  if ! git diff --quiet; then
    echo "WORKTREE"
    any=1
  fi
  if (( any == 0 )) && git rev-parse -q --verify HEAD^ >/dev/null 2>&1; then
    echo "HEAD^..HEAD"
  fi
}

count_parens() {
  python3 - "$1" "$2" <<'PY'
import subprocess, sys
rng, tok = sys.argv[1], sys.argv[2]
paths = ['--', '*.go', '*.ts', '*.vue', '*.js', '*.css']
if rng == 'WORKTREE':
    args = ['git', 'diff', '-U0', '--no-color'] + paths
elif rng == '--cached':
    args = ['git', 'diff', '--cached', '-U0', '--no-color'] + paths
else:
    args = ['git', 'diff', '-U0', '--no-color', rng] + paths
proc = subprocess.run(args, capture_output=True, text=True)
if proc.returncode != 0:
    sys.stderr.write(proc.stderr)
    sys.exit(1)
added = sum(line.count(tok) for line in proc.stdout.splitlines() if line.startswith('+') and not line.startswith('+++'))
removed = sum(line.count(tok) for line in proc.stdout.splitlines() if line.startswith('-') and not line.startswith('---'))
print(added, removed)
PY
}

check_diff_shape() {
  local ranges; ranges="$(diff_ranges)"
  if [[ -z "${ranges}" ]]; then
    echo "bulk-edit safety: 无可检查的变更集（干净 HEAD）"
    return 0
  fi
  # fail-closed：统计依赖 python3。缺失时旧实现让 read 拿到空值、阈值按 0
  # 处理，通道 B 静默失效并打印「变更形态正常」——门禁在最需要时变绿。
  # 与 check-no-audit-artifacts.sh 对缺 perl 的取向对齐：拒绝静默通过。
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: 需要 python3 统计变更形态（缺失时拒绝静默通过）" >&2
    return 1
  fi
  local bad=0 range tok counts added removed git_range label
  while IFS= read -r range; do
    [[ -n "${range}" ]] || continue
    case "${range}" in
      RANGE:*)
        git_range="${range#RANGE:}"
        label="${git_range}（BULK_EDIT_RANGE 显式范围）"
        ;;
      HEAD^..HEAD)
        git_range="${range}"
        label="${range}（干净树：仅检查最近一条提交；多提交变更集请设 BULK_EDIT_RANGE）"
        ;;
      *)
        git_range="${range}"
        label="${range}"
        ;;
    esac
    for tok in '()' '（）'; do
      # 统计命令自身失败（python3 运行时错误 / git diff 失败）同样 fail-closed：
      # 命令替换失败不会触发 set -e（read 自身成功），必须显式判定。
      if ! counts="$(count_parens "${git_range}" "$tok")"; then
        echo "ERROR: 变更形态统计失败（范围：${label}，形态：「${tok}」）" >&2
        return 1
      fi
      read -r added removed <<<"${counts}"
      if [[ -z "${added}" || -z "${removed}" ]]; then
        echo "ERROR: 变更形态统计输出异常（范围：${label}，形态：「${tok}」）" >&2
        return 1
      fi
      if (( removed >= paren_min )) && (( removed > added * paren_ratio )); then
        echo "ERROR: 变更集疑似批量删除空括号「${tok}」：删除 ${removed}，新增 ${added}（范围：${label}）" >&2
        bad=1
      fi
    done
    if (( bad == 0 )); then
      echo "bulk-edit safety: 变更形态正常（${label}）"
    fi
  done <<<"${ranges}"
  return "$bad"
}

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/bulk-edit-safety-selftest.sh"
fi

status=0
# 作用域必须可见：输出里明写「仓外不受控」，让假绿的边界变成可读事实，而不是
# 让人以为两条闸门覆盖了任何位置的批量改写。
echo "== 通道 A：批量改写脚本静态面（作用域=仓内受控+未跟踪 *.sh/*.py；仓外/临时脚本不受控——批量改写请先 checkpoint）=="
scan_scripts || status=1
check_diff_shape || status=1
exit "$status"
