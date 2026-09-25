package handlers

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"

	"lazy-balancer-v2/internal/models"
)

// 受信代理（CDN 真实 IP）写侧校验与归一（v2.3.x）：UpdateConfig 与
// PreviewConfigUpdate 共用——未过校验的载荷不得落库、也不得给出变更清单。
//
// 归一（原地回写 req 字段）：
//   - ranges：裸 IP 补 /32（v4）//128（v6）；条数 ≤64；前缀长度 <8（v4）
//     或 <96（v6）一律拒绝——过宽网段会让伪造头在任意来源被采信。
//   - headers：条数 ≤8；字符集 ^[A-Za-z0-9-]{1,64}$；去重保序；
//     空数组 = 仅 X-Forwarded-For（渲染层省略 client_ip_headers）。
var trustedProxyHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func validateTrustedProxyFields(req *models.UpdateConfigRequest) error {
	if req.TrustedProxyRanges != nil {
		normalized, err := normalizeTrustedProxyRanges(*req.TrustedProxyRanges)
		if err != nil {
			return err
		}
		*req.TrustedProxyRanges = normalized
	}
	if req.TrustedProxyHeaders != nil {
		normalized, err := normalizeTrustedProxyHeaders(*req.TrustedProxyHeaders)
		if err != nil {
			return err
		}
		*req.TrustedProxyHeaders = normalized
	}
	return nil
}

func normalizeTrustedProxyRanges(raw string) (string, error) {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("受信代理网段必须是 JSON 数组: %v", err)
	}
	if len(entries) > 64 {
		return "", fmt.Errorf("受信代理网段条数上限 64（当前 %d）", len(entries))
	}
	normalized := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return "", fmt.Errorf("无效的受信代理网段: %s", entry)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		minBits := 8
		if prefix.Addr().Is6() {
			minBits = 96
		}
		if prefix.Bits() < minBits {
			return "", fmt.Errorf("受信代理网段过宽（%s）：最小允许 /8（IPv4）与 /96（IPv6），请收窄到该 CDN 的回源网段", prefix.String())
		}
		// 去重保序（与 headers 侧同口径，第 53 轮补充轮 U6B-7）
		if _, dup := seen[prefix.String()]; dup {
			continue
		}
		seen[prefix.String()] = struct{}{}
		normalized = append(normalized, prefix.String())
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("序列化受信代理网段失败: %v", err)
	}
	return string(out), nil
}

func normalizeTrustedProxyHeaders(raw string) (string, error) {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("受信代理请求头必须是 JSON 数组: %v", err)
	}
	if len(entries) > 8 {
		return "", fmt.Errorf("受信代理请求头条数上限 8（当前 %d）", len(entries))
	}
	seen := make(map[string]struct{}, len(entries))
	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !trustedProxyHeaderPattern.MatchString(entry) {
			return "", fmt.Errorf("无效的受信代理请求头: %s（仅允许字母/数字/连字符，1-64 字符）", entry)
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		normalized = append(normalized, entry)
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("序列化受信代理请求头失败: %v", err)
	}
	return string(out), nil
}
