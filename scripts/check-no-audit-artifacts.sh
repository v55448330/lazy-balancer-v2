#!/usr/bin/env bash
# 公网仓库守卫：审计过程记录、轮次测试与审计编号不得入库。
# 历史审计产物在私有审计仓；本脚本由 scripts/test-all.sh 与发布链调用。
#
# 三条独立通道，任一命中即失败：
#   1) 路径：审计报告目录与轮次测试文件名（Go/TS）——受控文件与未跟踪文件同扫，
#      仅跳过 .gitignore 已忽略者与构建/运行产物目录；
#   2) 内容：注释行与测试声明行里的审计编号/轮次元数据——覆盖 Go/TS/Vue/JS/CSS/
#      Markdown/Shell/YAML/SQL/go.mod/Python/Dockerfile/docker-entrypoint.sh/
#      .dockerignore/.gitignore/.gitattributes/Caddyfile。JSON/HTML/TOML/conf 同样入面（夹具字符串与
#      模板文案里可能混入审计编号），其中 JSON/HTML 按「全文」扫描而非仅注释行
#      ——JSON 字符串值与 HTML 文本节点没有注释前缀，只扫注释行等于留通道。
#      作业面无扩展名约定文件（.gitignore/.gitattributes）与 Python 脚本同样在面内：
#      批量脚本与忽略清单的注释块都是审计编号的真实混入面（扫描面声明见
#      content_scan_exts / content_scan_basenames）。
#      刻意例外：web/package-lock.json（npm 生成物，integrity 为混合大小写
#      base64、随依赖升级整份重写，人工审计标注不进该文件）不入内容面。
#      轮次引用按「审计动作共现」判定：裸轮次＋审计
#      动作（N 轮修复）、斜杠并列（第 N/N 轮审计）、无「第」的中文数字归属、
#      注释头被编辑截断的残骸（// N 轮）：…）都命中；循环轮次表述（每 N 轮
#      落行、连续 N 轮共识、第 N/N 轮打点）不按裸数字判罚；
#   3) 跨行拆字：“第”与“轮”之间被换行拆开书写同样命中（编号拆成两行不可绕过），
#      续行带注释前缀（“第”换行后接“// N 轮”）是同一形态的变体，一并命中。
#
# 扫描面口径：扩展名与文件名匹配不区分大小写（.MD/.Go 与 .md/.go 同等入面）；
# 入面文件若含 NUL 字节（二进制形态）直接判错——整文件跳过等于留一条逃逸通道。
#
# 误报收窄：白名单只锚定“审计编号形态”，不按裸数字判罚。百分位 P50/P95/P99、
# 版本串 v2.3.x、sha256/十六进制摘要、HTTP/3、TLS 1.3、PID1、X509、ED25519、
# HS256、LBF1 文件魔数、时间格式骨架（YYYY-MM-DD / HH-mm-ss / HH:mm:ss）等
# 产品 token 不触发（见内嵌扫描器的 SHIELD 与纯十六进制令牌过滤）。
#
# 用法：bash scripts/check-no-audit-artifacts.sh [--self-test]
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/guard-selftest.sh"
fi

cd "$script_dir/.."

# fail-closed：必须在 git 检出内运行——非 git 上下文无法枚举受控文件，拒绝静默通过。
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: 必须在 git 检出内运行本守卫（git rev-parse 失败，拒绝静默通过）" >&2
  exit 1
fi
if ! controlled=$(git ls-files --cached --others --exclude-standard); then
  echo "ERROR: git ls-files 失败——必须在 git 检出内运行本守卫" >&2
  exit 1
fi

# 构建产物/运行数据/本地工具目录一律不入扫描面（.gitignore 已覆盖大部分，
# 这里再显式声明一次：守卫不依赖 .gitignore 的完整性来避免扫描噪声）。
# WAF 运行目录按「waf」+ 可选后缀分隔符收窄（waf/、waf-slave/、waf.dist/、
# waf.log/）：宽形态 `waf[^/]*/` 会连带命中嵌套 Go 模块 wafiplist/，把整个模块
# 从路径与内容两条通道同时摘掉——模块里的注释编号与轮次测试文件名因此永不入面
# （永久静默盲区）。运行目录以 `-`/`.` 起后缀，模块名不会。
skip_re='^(\.git/|(.*/)?node_modules/|(.*/)?dist/|ui/|(.*/)?backup[^/]*/|(.*/)?data[^/]*/|(.*/)?logs[^/]*/|(.*/)?certs[^/]*/|(.*/)?waf([-.][^/]*)?/|test-ui/|test-data/|(\.(omp|agent|superpowers|omo|sisyphus|opencode|worktrees|playwright-mcp))/)'

# ---------------------------------------------------------------------------
# 审计产物路径模式——单一事实源。
# 每条 = “<.gitignore 行><TAB><检测正则>”。.gitignore 的审计排除块必须与第一列
# 逐行一致（双向校验：多一行、少一行、改一行都失败），检测正则取第二列并集。
# 新增形态时两列同时加。
#
# 「宽名族」四条（*audit[0-9]* / *round[0-9]* 及其目录变体）的检测正则要求
# 词元边界：audit/round 前必须是路径分隔符或非字母数字字符。无边界写法会把
# 合法名字误判成审计产物并阻断提交——背景图/地面层文档这类文件名里恰好含
# 「round 紧接数字」的片段即为实例（守卫 fail-closed，代价是错误文案指向
# 「审计记录不得提交」，排查方向被误导）。.gitignore 第一列仍按宽形态忽略
# （误忽略无害）。误报对照由 scripts/tests/guard-selftest.sh 钉住。
# ---------------------------------------------------------------------------
audit_path_rules=(
  $'docs/audit/\t^docs/audit/'
  $'**/audit[0-9]*_test.go\t(^|/)audit[0-9]+[^/]*_test\\.go$'
  $'**/*_audit[0-9]*_test.go\t(^|/)[^/]+_audit[0-9]+[^/]*_test\\.go$'
  $'**/audit_round[0-9]*_test.go\t(^|/)audit_round[0-9]+[^/]*_test\\.go$'
  $'**/r[0-9]*_test.go\t(^|/)r[0-9]+[^/]*_test\\.go$'
  $'**/round[0-9]*_test.go\t(^|/)round[0-9]+[^/]*_test\\.go$'
  $'**/*_r[0-9]*_test.go\t(^|/)[^/]+_r[0-9]+[^/]*_test\\.go$'
  $'**/*_round[0-9]*_test.go\t(^|/)[^/]+_round[0-9]+[^/]*_test\\.go$'
  $'**/*audit[0-9]*\t(^|/|[^A-Za-z0-9])audit[0-9][^/]*'
  $'**/*round[0-9]*\t(^|/|[^A-Za-z0-9])round[0-9][^/]*'
  $'**/*audit[_-][0-9]*\t(^|/|[^A-Za-z0-9])audit[_-][0-9][^/]*'
  $'**/*round[_-][0-9]*\t(^|/|[^A-Za-z0-9])round[_-][0-9][^/]*'
  $'**/*audit[0-9]*/\t(^|/|[^A-Za-z0-9])audit[0-9][^/]*'
  $'**/*round[0-9]*/\t(^|/|[^A-Za-z0-9])round[0-9][^/]*'
)

path_regex=""
ignore_expected=""
for rule in "${audit_path_rules[@]}"; do
  ignore_expected+="${rule%%$'\t'*}"$'\n'
  re="${rule#*$'\t'}"
  path_regex+="${path_regex:+|}(${re})"
done

# —— .gitignore 与模式表双向一致 ——
begin_marker='# >>> audit-artifact patterns'
end_marker='# <<< audit-artifact patterns'
if ! grep -qxF "$begin_marker" .gitignore || ! grep -qxF "$end_marker" .gitignore; then
  echo "ERROR: .gitignore 缺少审计排除块标记（${begin_marker} / ${end_marker}）" >&2
  exit 1
fi
if [[ "$(grep -cxF "$begin_marker" .gitignore)" != "1" || "$(grep -cxF "$end_marker" .gitignore)" != "1" ]]; then
  echo "ERROR: .gitignore 审计排除块标记重复" >&2
  exit 1
fi

actual_ignore="$(awk -v b="$begin_marker" -v e="$end_marker" '$0==b{f=1;next} $0==e{f=0} f' .gitignore | sed '/^[[:space:]]*$/d')"
expected_ignore="$(printf '%s' "$ignore_expected" | sed '/^[[:space:]]*$/d')"
# 去重口径不得用于比较：重复模式行对 git 行为无害，但破坏「逐行一致」契约
# （重复行被 sort -u 折叠后两侧相等 → 门禁给绿，之后删掉其中一行仍判一致）。
# 故先单独拒绝重复行，再按排序后全量（保留重复）比较。
duplicate_ignore="$(printf '%s\n' "$actual_ignore" | LC_ALL=C sort | uniq -d)"
if [[ -n "$duplicate_ignore" ]]; then
  echo "ERROR: .gitignore 审计排除块存在重复模式行（逐行一致契约不成立）：" >&2
  printf '%s\n' "$duplicate_ignore" | sed 's/^/  /' >&2
  exit 1
fi
if [[ "$(printf '%s\n' "$actual_ignore" | LC_ALL=C sort)" != "$(printf '%s\n' "$expected_ignore" | LC_ALL=C sort)" ]]; then
  echo "ERROR: .gitignore 审计排除块与本脚本模式表不一致（两侧模式集必须一一对应）：" >&2
  diff <(printf '%s\n' "$expected_ignore" | LC_ALL=C sort) \
       <(printf '%s\n' "$actual_ignore" | LC_ALL=C sort) | sed 's/^/  /' >&2 || true
  exit 1
fi

# ---------------------------------------------------------------------------
# 通道 0：依赖/构建缓存不得「被跟踪」。
# skip_re 把 node_modules 从内容扫描面摘掉（按源码形态设计的扫描器不该读转译
# 副本），但被跟踪本身就是仓卫生缺陷：一次 `git add -A` 就会把 vitest 的
# .vite/.vitest-cache 转译缓存连同其中的失败记录一起发布，且与 tests 源随时
# 分叉。故此处单列一条反向断言——.gitignore 只负责「不被暂存」，本通道负责
# 「已在索引里的也拦下」。
# ---------------------------------------------------------------------------
# 正则必须是 GNU/BSD 通用的 ERE：非捕获组 `(?:…)` 属 PCRE，GNU grep -E 会以
# rc=2 报「repetition-operator operand invalid」。故 rc 必须与「无命中」区分开：
# 只有 0（有命中）/1（无命中）是正常结果，>1 一律 fail-closed——用 `|| true`
# 兜住会把正则错误吞成空结果，通道永远假绿且自检无法变红。
tracked_cache_re='(^|/)node_modules/|(^|/)[.](vite|vitest-cache)/'
tracked_cache_rc=0
tracked_cache="$(printf '%s\n' "$controlled" | grep -E "$tracked_cache_re")" || tracked_cache_rc=$?
if [[ $tracked_cache_rc -gt 1 ]]; then
  echo "ERROR: 依赖/构建缓存通道的正则无法执行（grep rc=${tracked_cache_rc}）：${tracked_cache_re}" >&2
  echo "门禁 fail-closed——正则错误不等于无命中，请改成通用 ERE。" >&2
  exit 1
fi
if [[ -n "$tracked_cache" ]]; then
  echo "ERROR: 依赖/构建缓存目录不得入库（git rm -r --cached 撤销，并确认 .gitignore 覆盖）：" >&2
  echo "$tracked_cache" >&2
  exit 1
fi

# —— 通道 1：路径 ——
# 与通道 0 同口径 fail-closed：skip_re / path_regex（由上方十四条规则拼装）
# 损坏时 grep 以 rc>1 报错，`|| true` 会把它吞成空结果——审计产物路径通道
# 静默放行、永远假绿。rc 只有 0（有命中）/1（无命中）是正常结果，>1 一律
# 报错退出并点名出错的正则。
path_filter_rc=0
path_candidates="$(printf '%s\n' "$controlled" | grep -v -E "$skip_re")" || path_filter_rc=$?
if [[ $path_filter_rc -gt 1 ]]; then
  echo "ERROR: 路径通道的 skip_re 无法执行（grep rc=${path_filter_rc}）：${skip_re}" >&2
  echo "门禁 fail-closed——正则错误不等于无命中，请改成通用 ERE。" >&2
  exit 1
fi
path_filter_rc=0
bad_paths="$(printf '%s\n' "$path_candidates" | grep -E "$path_regex")" || path_filter_rc=$?
if [[ $path_filter_rc -gt 1 ]]; then
  echo "ERROR: 路径通道的 path_regex 无法执行（grep rc=${path_filter_rc}）：${path_regex}" >&2
  echo "门禁 fail-closed——正则错误不等于无命中，请改成通用 ERE。" >&2
  exit 1
fi
if [[ -n "$bad_paths" ]]; then
  echo "ERROR: 审计记录/轮次测试不得提交到公网仓库：" >&2
  echo "$bad_paths" >&2
  exit 1
fi

# —— 通道 2/3：内容与跨行拆字（内嵌扫描器）——
# 扫描面：受控 + 未跟踪（已按 .gitignore 与 skip_re 过滤）。
# 内容扫描豁免：仅限自检脚本（其内容即被测样本）。豁免面必须是显式单条——
# 数组长度断言防止它悄悄长成漏检通道。
content_exempt_paths=(scripts/tests/guard-selftest.sh)
if [[ ${#content_exempt_paths[@]} -ne 1 ]]; then
  echo "ERROR: 内容扫描豁免面必须恰好一条，实际：${content_exempt_paths[*]}" >&2
  exit 1
fi
content_exempt="^$(printf '%s' "${content_exempt_paths[0]}" | sed 's/[.]/\\./g')$"

# 内容面豁免：npm 生成物（integrity 为 base64，且随依赖升级整份重写）——
# 只豁免该单一路径，业务 JSON 夹具/种子仍须扫描。
content_scan_exempt_re='(^|/)package-lock\.json$'

# 内容扫描面（单一事实源）：可扫描的文本扩展名 + 无扩展名的约定文件。
# 新增可写文本形态时只改这两个数组；自检按同一清单逐项造夹具断言确实入面
# （漏登记即红）。py 与 check-bulk-edit-safety.sh 的 scripts/*.py 作业面同口径
# ——一次性批量脚本写在 .py 里时，其注释同样可能夹带审计编号；.gitignore /
# .gitattributes 没有扩展名，但注释块同样是可写入审计编号的地方。
content_scan_exts=(go ts vue js css md markdown txt sh yml yaml sql mod json html htm toml conf py)
content_scan_basenames=(Dockerfile docker-entrypoint.sh .dockerignore .gitignore .gitattributes Caddyfile)
content_scan_ext_alt=""
for ext in "${content_scan_exts[@]}"; do
  content_scan_ext_alt+="${content_scan_ext_alt:+|}${ext}"
done
content_scan_name_alt=""
for name in "${content_scan_basenames[@]}"; do
  if [[ "$name" == "Dockerfile" ]]; then
    # Dockerfile 派生文件（Dockerfile.dev 等）与主文件同族入面。
    content_scan_name_alt+="${content_scan_name_alt:+|}(^|/)Dockerfile[^/]*"
  else
    content_scan_name_alt+="${content_scan_name_alt:+|}(^|/)${name//./[.]}"
  fi
done
content_scan_re="\\.(${content_scan_ext_alt})$|${content_scan_name_alt}$"

scan_targets="$(printf '%s\n' "$controlled" \
  | grep -v -E "$skip_re" \
  | grep -v -E "$content_exempt" \
  | grep -v -E "$content_scan_exempt_re" \
  | grep -Ei "$content_scan_re" \
  | while IFS= read -r f; do [[ -f "$f" ]] && printf '%s\n' "$f"; done || true)"

if [[ -n "$scan_targets" ]]; then
  # 内容/跨行扫描器用 perl 实现（跨行拆字需要整文件匹配；BSD grep 无 -P/-z
  # 等价能力）。缺 perl 时 fail-closed——不允许退化成只做行级扫描而静默通过。
  if ! command -v perl >/dev/null 2>&1; then
    echo "ERROR: 需要 perl 才能运行内容扫描（缺少 perl，拒绝静默通过）" >&2
    exit 1
  fi
  scan_prog="$(mktemp "${TMPDIR:-/tmp}/audit-guard-scan.XXXXXX")"
  list_file="$(mktemp "${TMPDIR:-/tmp}/audit-guard-files.XXXXXX")"
  trap 'rm -f "$scan_prog" "$list_file"' EXIT

  cat >"$scan_prog" <<'PERL'
use strict;
use warnings;

# SHIELD：产品 token 先剥离，再匹配审计编号形态。剥离而非排除整行——同一行里
# 既有产品 token 又有审计编号时仍须命中。
my $shield = join '|',
  q{X-[A-Za-z][A-Za-z0-9-]*},            # X-LB-* 自定义头
  q{REQUEST-[0-9A-Z-]*}, q{RESPONSE-[0-9A-Z-]*},
  q{HTTP/[0-9.]+}, q{HTTP[0-9]},         # HTTP/3、HTTP2
  q{TLS[ ]?v?[0-9]+(\.[0-9]+)?}, q{QUIC[ ]?v?[0-9.]+},
  q{IPV[46]}, q{UTF-?8}, q{SHA-?[0-9]{3}}, q{HMAC-SHA256},
  q{(?:HS|RS|ES|PS|EdDSA)[0-9]{3}},      # JWT/PKI 算法名
  q{ED25519}, q{X25519}, q{X509}, q{P-256}, q{P256},
  q{AES-?[0-9]{3}(-GCM)?}, q{BASE64}, q{MD5},
  q{P[0-9]{2}(-P?[0-9]{2})?},            # P50/P95/P99 与 P50-P99 百分位
  q{v[0-9]+\.[0-9]+(?:\.[0-9x*]+)*(?:-[A-Za-z0-9.]+)?},  # 版本串 v2.3.x / v2.3.8-beta
  q{YYYY-MM-DD}, q{NOT-NULL}, q{NULL-[a-z]+},
  # 时间格式骨架（日志文件名/时间戳布局注释里的 HH-mm-ss、HH:mm:ss）：
  # 两字母+分隔的三段形态不是审计编号，属产品口径 token。
  q{[Hh]{2}[-:][Mm]{2}[-:][Ss]{2}},
  q{BY-DESIGN}, q{TOP-LEVEL}, q{HTTP-only}, q{TCP-only}, q{HTTP-date},
  q{TLS-enabled}, q{TLS-only}, q{VERSION-only}, q{JSON-[A-Za-z]*},
  q{IP-control}, q{IP-level}, q{ACME-issued}, q{UPSERT-overwritten},
  q{AB-BA}, q{WEB-VIEWS-CORE}, q{UTC-[0-9]+}, q{MM-DD}, q{DOM-TOM},
  q{Apache-[0-9.]+}, q{CVE-[0-9]+(?:-[0-9]+)*}, q{RFC-?[0-9]+}, q{ISO-[0-9]+},
  q{HTTP-[0-9.]+}, q{TLS-[0-9.]+},
  q{CRS-active}, q{LBF1}, q{PID1}, q{DNS-01},
  q{IPv[46]-(?:only|first|mapped|compatible)},  # IPv6-only 等网络口径
  q{YYYYMMDD(?:-HHMMSS)?},                      # 日志轮转文件名骨架
  q{[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}(?:\.[0-9]+)?},
  q{[0-9]{8}T[0-9]{2}-[0-9]{2}-[0-9]{2}},       # 日志轮转 ISO 时间戳（含毫秒）
  q{MAX-[0-9]+}, q{MIN-[0-9]+},      # 容量边界常量（MAX-1 个自有键），非编号
  q{[A-F0-9]{16,}};                      # 长十六进制摘要（逐段哈希/指纹）

# 审计编号家族（历史出现过的全部形态）：
#   (a) 字母+数字开头，后接一段或多段短横线分段（序数-序号，或前缀-序数-序号）；
#   (b) 纯大写字母前缀 + 两段以上短横线分段（前缀-序数-序号）。
my $fam = q{[A-Z][A-Za-z]{0,7}[0-9][0-9A-Za-z]*(-[0-9A-Za-z]+)+}
        . q{|[A-Z]{2,8}(-[0-9A-Za-z]+){2,}}
        . q{|\b[A-Z][A-Z0-9]{1,7}-[A-Z]{0,2}[0-9]{1,3}\b};

# —— 中文词条的 UTF-8 字节形态 ——
# 输入以 :raw 打开、不经 use utf8 解码（保持对任意字节形态的抗性），故中文字面
# 量必须写成字节转义；下列变量按字面含义命名，避免长正则不可读。
my $cn_di    = '\xe7\xac\xac';                                    # 第
my $cn_round = '\xe8\xbd\xae';                                    # 轮
my $cn_not_carousel = '(?!\xe6\x92\xad|\xe8\xaf\xa2)';           # 不吞「轮播/轮询」
  # 注：排除项必须写完整字符序列——写成字节字符类会误伤首字节相同的其它汉字
  # （「漏」与「播」同以 E6 起头），令「N 轮漏收敛」一类引用漏检。
# 审计动作词。轮次引用几乎总与它们共现；循环轮次表述（每 N 轮落行、连续 N 轮
# 共识、N 轮心跳、第 N/N 轮打点）不会——这是「裸数字不判罚」的收窄依据。
my $cn_audit_verbs = join '|',
  '\xe5\xae\xa1\xe8\xae\xa1',   # 审计
  '\xe4\xbf\xae\xe5\xa4\x8d',   # 修复
  '\xe8\xa3\x81\xe5\xae\x9a',   # 裁定
  '\xe5\x8f\x91\xe7\x8e\xb0',   # 发现
  '\xe6\x94\xb6\xe6\x95\x9b',   # 收敛
  '\xe5\x8a\xa0\xe5\x9b\xba',   # 加固
  '\xe5\xa4\x8d\xe6\xa0\xb8';   # 复核
# 并列轮次常以全角标点收尾（「第 N/N 轮，与写侧」）；循环轮次则接动作词或
# ASCII 逗号（「第 N/N 轮, iterations」）。
my $cn_stop_punct = '(?:\xef\xbc\x8c|\xe3\x80\x81|\xef\xbc\x9b|\xe3\x80\x82|\xef\xbc\x89)';
# 斜杠并列轮次：第 N/N 轮。
my $cn_slash_round = $cn_di . '[ \t]*[0-9]+(?:\.[0-9]+)?'
  . '(?:/[ \t]*[0-9]+(?:\.[0-9]+)?)+[ \t]*' . $cn_round;

# 括号/破折号引导的轮次归属：全角/ASCII 左括号或破折号之后直接跟「NN 轮」。
# 其后不是倍数（「（NN 轮×60s」）、不是收尾括号（「（NN 轮」）也不接数字时，
# 属回溯到某轮的审计归属而非循环计数——循环计数必然带倍数/单位或直接收尾；
# 破折号前紧邻数字是区间写法（「第 N-NN 轮」），同样排除。审计动作常被折到
# 下一行注释，同行动作词判定看不到，故这一形态必须独立成条。
# 前缀逐字节写完整字符序列：写成字节字符类会误伤首字节相同的汉字。
my $cn_round_attr = '(?<![0-9])(?:\xef\xbc\x88|\(|(?:\xe2\x80\x94){1,2}|--?)'
  . '[ \t]*[0-9]{2,3}[ \t]*' . $cn_round . '(?!(?:\xc3\x97|\xef\xbc\x89|[0-9]))';

# 轮次/编号的其它书写形态：中文轮次（含裸轮次与并列轮次）、审计序数、
# round/audit 前缀、R 两位数、A 两位数、SYS/SEC/HP/CL 前缀，以及编号紧邻
# “裁定”的审计结论引用。
my $legacy = join '|',
  $cn_di . '[ \t]*[0-9]+(?:\.[0-9]+)?[ \t]*' . $cn_round . $cn_not_carousel,
  # 裸轮次 + 审计动作（「N 轮修复前落库」）：裸数字单独出现不判罚。
  '[0-9]{1,3}(?:/[0-9]{1,3})?[ \t]*' . $cn_round . '[ \t]*(?:' . $cn_audit_verbs . ')',
  # 斜杠并列轮次 + 审计动作/全角标点收尾（「第 N/N 轮审计」「第 N/N 轮，」）。
  $cn_slash_round . '[ \t]*(?:(?:' . $cn_audit_verbs . ')|' . $cn_stop_punct . ')',
  # 注释头以裸轮次收尾于标点/审计动作（「// N 轮）：…」——被编辑截断的引用
  # 残骸；循环语义的注释头接动作词（「// N 轮渲染 → NR）」）故不在内）。
  '^[ \t]*(?://+|#|\*|/\*|--|;|<!--)[ \t]*[0-9]{1,3}[ \t]*' . $cn_round
    . '[ \t]*(?:(?:' . $cn_audit_verbs . ')|\xef\xbc\x89|\xef\xbc\x9a|\xef\xbc\x8c)',
  # 中文数字轮次 + 审计归属（审计动作词后接全角括号与中文数字轮次）。
  '\xe5\xae\xa1\xe8\xae\xa1[ \t]*\xef\xbc\x88' . $cn_di
    . '[^\n]{1,8}?' . $cn_round,
  '\xe5\xae\xa1\xe8\xae\xa1[ \t]*[0-9]{2,3}(?![0-9])',
  # 被历史清洗截断的注释残骸（「历史」+「问题」+冒号连写形态）——语义已被
  # 剥离，只剩审计过程的痕迹；正常产品文案不会以该形态开头。
  '\xe5\x8e\x86\xe5\x8f\xb2[ \t]*\xe9\x97\xae\xe9\xa2\x98[ \t]*[:\xef\xbc\x9a]',
  '(?i:\b(?:round|audit))[-_]?[0-9]{1,3}\b',
  '\b[Rr][0-9]{2}[a-z]?\b',
  '\bA[0-9]{2}[A-Za-z]?\b',
  '\b(?:SYS|SEC|HP|CL)[-_]?[0-9]{1,3}\b',
  # 括号/破折号引导的轮次归属（见 $cn_round_attr）。
  $cn_round_attr,
  '[A-Z][A-Za-z]{0,4}[0-9]{1,3}[A-Za-z]?[ \t]*\xe8\xa3\x81\xe5\xae\x9a';

# 连写形态（无短横线）：1-5 位大写字母 + 2-3 位数字 + 1-2 位大写字母收尾。
my $concat = q{\b[A-Z]{1,5}[0-9]{2,3}[A-Z]{1,2}\b};

# 下划线/小驼峰测试名形态：测试前缀 + 编号段 + 下划线接业务描述。
my $tname = q{\bTest[A-Za-z]{0,3}[0-9]+(?:_[0-9A-Za-z]+)+};

# 跨行拆字：“第”与“轮”被换行隔开的书写无法用行扫描发现，整文件再扫一遍。
# 续行带注释前缀（「第」换行后接「// N 轮」）是同一形态的常见变体——前缀必须
# 一并容忍，否则拆字仍可绕过。
my $cont_prefix = '(?:(?://+|#|\*|/\*)[ \t]*)?';
my $cross = join '|',
  $cn_di . '[ \t]*\r?\n[ \t]*' . $cont_prefix . '[0-9]+(?:\.[0-9]+)?[ \t]*'
    . '\r?\n?[ \t]*' . $cn_round . $cn_not_carousel,
  $cn_di . '[ \t]*[0-9]+(?:\.[0-9]+)?[ \t]*\r?\n[ \t]*' . $cont_prefix
    . $cn_round . $cn_not_carousel,
  # 轮次写在本行（须是括号/破折号归属形态）、审计动作折到下一行注释：行级判定
  # 只看同行共现，折行写法会把动作词挪出匹配窗口。轮次形态沿用 $cn_round_attr
  # （循环计数写法已在源头排除），续行必须是注释（审计动作只出现在注释里）。
  $cn_round_attr . '[^\n]*\r?\n[ \t]*(?://+|#|\*|/\*|--|;)[ \t]*(?:' . $cn_audit_verbs . ')';

my $comment_re = qr{^[ \t]*(?://|///|\*|/\*|<!--|--|#|;)};
my $decl_re    = qr{^[ \t]*(?:func (?:Test|Benchmark|Fuzz)|describe\(|test\(|it\(|t\.Run\()};

my $hits = 0;
sub report {
  my ($file, $line, $text) = @_;
  my $where = $line ? "$file:$line" : "$file:cross-line";
  $text =~ s/\s+$//;
  print "$where: $text\n";
  $hits++;
}

my $list = shift or die "usage: scan <file-list>\n";
open(my $lf, '<', $list) or die "cannot read file list: $!\n";
while (my $f = <$lf>) {
  chomp $f;
  next if $f eq '';
  open(my $fh, '<:raw', $f) or do { warn "cannot read $f: $!\n"; $hits++; next };
  local $/;
  my $text = <$fh>;
  close $fh;
  # 含 NUL 的文件落在文本扩展名扫描面里不是正常源文件形态——整文件跳过等于留
  # 一条逃逸通道（把编号藏进带 NUL 的文件即可绕过）。此处按不可审查报错
  # （fail-closed），由人判断该文件去留，而不是静默放行。
  if ($text =~ /\x00/) {
    print "$f: contains NUL byte (binary form, not scannable as text)\n";
    $hits++;
    next;
  }
  # 文档/结构化文本按全文扫描：Markdown 与纯文本整篇都是可读文案；JSON 的
  # 字符串值、HTML 的文本节点没有注释前缀，只扫注释行等于给编号留通道
  # （夹具/种子 JSON、模板文案是真实混入面）。
  my $is_doc = ($f =~ /\.(?:md|markdown|txt|html|htm|json)$/i);

  $text =~ s/(?:$shield)//g;

  my @lines = split /\n/, $text, -1;
  for my $i (0 .. $#lines) {
    my $l = $lines[$i];
    next unless $is_doc || $l =~ $comment_re || $l =~ $decl_re;
    my $hit = ($l =~ /$fam/ || $l =~ /$legacy/ || $l =~ /$tname/);
    if (!$hit && $l =~ /$concat/) {
      # 纯十六进制字母数字连写不是编号；出现十六进制之外的字母才是编号形态。
      my @toks = ($l =~ /($concat)/g);
      $hit = grep { !/^[0-9A-F]+$/ } @toks;
    }
    report($f, $i + 1, $l) if $hit;
  }

  while ($text =~ /$cross/g) {
    my $snip = substr($text, $-[0], $+[0] - $-[0]);
    $snip =~ s/\s+/ /g;
    report($f, 0, $snip);
  }
}
close $lf;
exit($hits ? 1 : 0);
PERL

  printf '%s\n' "$scan_targets" >"$list_file"

  set +e
  scan_out="$(perl "$scan_prog" "$list_file")"
  scan_rc=$?
  set -e
  case "$scan_rc" in
    0) ;;
    1)
      echo "ERROR: 审计编号/轮次元数据不得提交到公网仓库：" >&2
      echo "$scan_out" >&2
      exit 1
      ;;
    *)
      echo "ERROR: 内容扫描器异常退出（rc=${scan_rc}）——拒绝静默通过" >&2
      echo "$scan_out" >&2
      exit 1
      ;;
  esac
fi

echo "no audit artifacts tracked"
