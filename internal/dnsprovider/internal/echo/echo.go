// Package echo 提供凭据分段展开的跨 provider 共享实现（audit 133/134 冗余
// 收敛：dnspod/tencent/aliyun/cloudflare 四包曾各持一份逐字相同副本）。
//
// 脱敏主体（sanitize*/错误文案形态正则）仍保留在各 provider——凭据形态不同
// 是有意的；本包只收敛「凭据 → 已知明文形态集」这一段纯函数。
package echo

import "strings"

// SecretMinLen 是凭据分段参与定向替换的最小长度：短于该值的分段要么是
// 分隔噪声要么命中面过大（误伤正常文案）。
const SecretMinLen = 8

// Secrets 展开一段凭据的全部已知明文形态：完整值 + 各分段（按 ,、tab、
// 换行、空格、; 拆分，长度达标且与完整值不同的分段）。空值返回 nil。
func Secrets(secret string) []string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	secrets := []string{secret}
	for _, part := range strings.FieldsFunc(secret, func(r rune) bool {
		return r == ',' || r == '\t' || r == '\n' || r == ' ' || r == ';'
	}) {
		part = strings.TrimSpace(part)
		if len(part) >= SecretMinLen && part != secret {
			secrets = append(secrets, part)
		}
	}
	return secrets
}
