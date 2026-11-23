// Package dnsname 提供 DNS 名的单一归一实现。
//
// 归一（去首尾空白、小写、去掉一个末尾点）被三个互不成环的包共同消费：
//   - acme.Issuer 的权威应答比较（额外补 FQDN 末尾点）；
//   - dnsprovider 的挑战值在途登记键（challenge_claims）；
//   - dnsprovider/ownership 的清理账本匹配/去重。
//
// 同一个归一口径还用于 provider 侧的子域名派生（RelativeTo：挑战 FQDN 减去
// zone 得到 API 的 sub_domain），dnspod 与 tencent 两个 provider 共用。
//
// 三处各写一份时，同一次挑战以不同书写形态（大小写/尾点）出现会让登记键与
// 账本键不一致：同值并发判定失效、清理归属落空，只能等 StaleOwnershipAge
// 兜底。放在叶子包而非任一消费者内，是因为 dnsprovider → dnspod → ownership
// 的既有依赖方向不允许 ownership 反向导入父包。
package dnsname

import "strings"

// NormalizeName 归一 DNS 名：去首尾空白、小写、去掉一个末尾点（DNS 名大小写
// 不敏感且尾点可省略）。只去一个尾点——连续尾点（畸形输入）不是合法 FQDN，
// 保留一个可让上层按自身口径拒绝，而不是在这里静默吞掉。
//
// 去尾点后必须再次去空白：输入 `example.com .`（点前带空白）在去点后残留
// `example.com `，旧实现直接返回该形态——同一名字的归一结果依赖调用次数
// （非幂等），登记键/账本键与权威应答比较会出现二次归一后才相等的假失配。
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(name), ".")))
}

// RelativeTo 返回 name 相对 zone 的子域名（`_acme-challenge.www.example.com`
// 相对 `example.com` → `_acme-challenge.www`），供 provider API 的 sub_domain
// 字段使用。两侧先按 NormalizeName 归一：zone 由 ResolveZone 输出为小写，而
// 挑战 FQDN 可能保留输入原样（`_acme-challenge.lb-test.Example.COM`）——不归一
// 的后缀比较会失配，把整个 FQDN 当子域名写进 API（TXT 落到错误名字）。
//
// 不属于 zone 的名字原样返回其归一形态：归属校验由调用方按自身口径负责，本函数
// 不做拒绝。
func RelativeTo(name, zone string) string {
	normalized := NormalizeName(name)
	zone = NormalizeName(zone)
	if zone == "" {
		return normalized
	}
	return strings.TrimSuffix(normalized, "."+zone)
}
