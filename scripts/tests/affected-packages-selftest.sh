#!/usr/bin/env bash
# 自检：scripts/lib/affected-packages.sh（--fast 档的判据本体）。
#
# 为什么需要自检：映射退化的表现是「快检恒绿」——少测一个包不会红，只会在
# 若干天后以「合并树才暴露的跨域断裂」形式回来（本轮的 services/handlers
# 即为该形态）。所以这里把三条口径逐条钉住：
#   ① 模块归属取最长前缀（根模块与嵌套模块不串台）；
#   ② 反向依赖闭包必须生效（改 services 必须带出 handlers）；
#   ③ 无包可解析的文件不得静默丢弃（输出为空 -> 调用方 fail-closed）。
set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=../lib/affected-packages.sh
. ./scripts/lib/affected-packages.sh

fail() {
  echo "affected-packages selftest FAIL: $*" >&2
  exit 1
}

# 模块清单与门禁本体同源派生（不手写：新增嵌套模块必须自动入面）。
module_list=()
while IFS= read -r line; do
  [[ -n "$line" ]] && module_list+=("$line")
done < <(
  git ls-files '*go.mod' |
    sed -e 's|/go.mod$||' -e 's|^go.mod$|.|' |
    LC_ALL=C sort -u
)
[[ ${#module_list[@]} -ge 2 ]] || fail "模块清单派生为空（期望至少根模块 + 一个嵌套模块）"

# ① 模块归属。
owner_root="$(affected_module_of_go_file internal/services/security.go)"
[[ "$owner_root" == "." ]] || fail "internal/services/security.go 归属=$owner_root, want ."
owner_geoip="$(affected_module_of_go_file caddygeoip/auditwriter.go)"
[[ "$owner_geoip" == "caddygeoip" ]] || fail "caddygeoip/auditwriter.go 归属=$owner_geoip, want caddygeoip"
owner_waf="$(affected_module_of_go_file wafiplist/dependency_parity_test.go)"
[[ "$owner_waf" == "wafiplist" ]] || fail "wafiplist 归属=$owner_waf"
owner_non_go="$(affected_module_of_go_file docs/mcp.zh-CN.md)"
[[ -z "$owner_non_go" ]] || fail "非 Go 文件不应有模块归属，got=$owner_non_go"
owner_nested_deep="$(affected_module_of_go_file caddygeoip/sub/dir/x.go)"
[[ "$owner_nested_deep" == "caddygeoip" ]] || fail "嵌套模块深路径归属=$owner_nested_deep"

# ② 反向依赖闭包：改 services 必须带出 handlers（本轮跨域断裂的最小形态）。
services_targets="$(affected_go_targets . internal/services/security.go)"
grep -qxF './internal/services' <<<"$services_targets" || fail "services 变更未包含自身包"
grep -qxF './internal/handlers' <<<"$services_targets" ||
  fail "services 变更未带出反向依赖 handlers（闭包失效，快检会漏测跨域断裂）"
grep -qxF './internal/middleware' <<<"$services_targets" ||
  fail "services 变更未带出 middleware"

# 闭包不是「全模块」：无关叶包不得被顺手带上（带上就等于退回全量）。
if grep -qxF './internal/db' <<<"$services_targets"; then
  fail "反向闭包过度包含 ./internal/db（依赖方向被反转，闭包实现有误）"
fi

# ②b 两档语义必须真的不同：--fast 只测变更包（不含依赖方），
#     --fast-deep 才带闭包。若两者退化成一回事，快检就会静默变成全量（或反之
#     静默少测），这条断言是档位语义的钉。
changed_pkgs="$(affected_module_changed_packages . internal/services/security.go)"
grep -qxF './internal/services' <<<"$changed_pkgs" || fail "--fast 面缺少变更包自身"
if grep -qxF './internal/handlers' <<<"$changed_pkgs"; then
  fail "--fast 面混入了依赖方 handlers（应只在 --fast-deep 出现）"
fi

# ③ 模块隔离：嵌套模块的变更不得带出根模块的包。
for pair in "wafiplist wafiplist/iplistfast.go" "caddygeoip caddygeoip/auditwriter.go"; do
  read -r mod file <<<"$pair"
  nested_targets="$(affected_go_targets "$mod" "$file")"
  grep -qxF './.' <<<"$nested_targets" || fail "$mod 变更未包含模块根包"
  if grep -q '^\./internal/' <<<"$nested_targets"; then
    fail "$mod 的变更带出了根模块包（模块隔离失效）"
  fi
done

# ④ 依赖图位移判据。
affected_module_dependency_changed . go.mod internal/x.go ||
  fail "go.mod 变更未被识别为依赖图位移"
if affected_module_dependency_changed . internal/x.go; then
  fail "纯代码变更被误判为依赖图位移（会无条件跑整模块）"
fi
if affected_module_dependency_changed caddygeoip go.mod; then
  fail "根模块 go.mod 被误判为嵌套模块位移"
fi
affected_module_dependency_changed caddygeoip caddygeoip/go.sum ||
  fail "嵌套模块 go.sum 变更未被识别"

# ⑤ 无包可解析不得静默丢弃（输出为空由调用方判失败）。
bogus_targets="$(affected_go_targets . internal/definitely-not-a-package/x.go)"
[[ -z "$bogus_targets" ]] || fail "不可解析的目录应输出为空（交由调用方 fail-closed），got=$bogus_targets"

echo "affected-packages selftest OK (modules: ${module_list[*]})"
