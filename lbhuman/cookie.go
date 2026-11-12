// Package lbhuman 人机验证网关（CC 防护）：挑战-放行底座。
//
//   - http.handlers.lb_human：阶段 2（限流）与阶段 3（WAF）之间的人机区分
//     处理器——有效验证 cookie 直通；CC 触发（突刺/4xx 比例/会话异常）或
//     force 模式 → 挑战页；挑战通过发签名 cookie。
//   - admin.api.lb_human：GET /lb/human/stats 挑战/通过/失败计数端点
//     （TrafficStatsAdmin 同模式：admin.api 模块随编译自动挂载）。
//
// 设计裁定（2026-11-12 用户确认）：检测在自动封禁配置（global_config），
// 策略只配模式/方式/有效期/豁免；挑战页并入拦截页模块（M2 滑块）。
// 零磁盘 I/O：计数器/挑战 token/cookie nonce 全部进程内内存。
package lbhuman

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// cookieName 验证通过 cookie 名（下划线前缀=用户自定义 header 不可伪造）。
const cookieName = "__lb_human"

// normalizeIP IPv6 按 /64 归一（隐私扩展地址漂移不误判）；IPv4 原样。
func normalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if parsed.To4() != nil {
		return ip
	}
	// IPv6：取前 64 位（/64 前缀）作身份锚
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}

// clientIPFrom XFF 首值优先（Caddy 反代链自动追加），直连回落 RemoteAddr。
func clientIPFrom(remoteAddr, xff string) string {
	if xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			xff = xff[:idx]
		}
		if v := strings.TrimSpace(xff); v != "" {
			return v
		}
	}
	host := remoteAddr
	if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	return strings.Trim(host, "[]")
}

// uaHash UA 指纹短哈希（cookie 绑定 UA 防转借，不存原文）。
func uaHash(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:8])
}

// signCookie 签名 cookie：base64url(exp|nonce) + "." + HMAC-SHA256(secret,
// ip|uaHash|exp|nonce)。IP/UA 绑定，exp 滑动过期，nonce 一次性。
func signCookie(secret []byte, ip, ua string, ttl time.Duration) (value string, expiresAt time.Time) {
	expiresAt = time.Now().Add(ttl)
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	payload := fmt.Sprintf("%d|%s", expiresAt.Unix(), hex.EncodeToString(nonce))
	mac := cookieMAC(secret, ip, ua, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + hex.EncodeToString(mac), expiresAt
}

func cookieMAC(secret []byte, ip, ua, payload string) []byte {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%s|%s|%s", normalizeIP(ip), uaHash(ua), payload)
	return h.Sum(nil)
}

// verifyCookie 校验：签名一致+未过期+IP/UA 绑定匹配。
func verifyCookie(secret []byte, cookieValue, ip, ua string, now time.Time) bool {
	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	mac, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	payload := string(payloadRaw)
	expected := cookieMAC(secret, ip, ua, payload)
	if !hmac.Equal(mac, expected) {
		return false
	}
	var exp int64
	if _, err := fmt.Sscanf(payload, "%d|", &exp); err != nil {
		return false
	}
	return now.Unix() <= exp
}

// —— 挑战 token 管理（PoW 挑战：token 一次性+TTL，nonce 防重放）——

const (
	challengeTokenTTL   = 5 * time.Minute
	challengeDifficulty = 4 // 前 4 位十六进制零（<1s 浏览器可算）
)

type challengeToken struct {
	value     string
	expiresAt time.Time
	used      bool
}

var (
	challengeTokens   = map[string]challengeToken{}
	challengeTokensMu sync.Mutex
)

// issueChallengeToken 签发 PoW 挑战 token（随机 16 字节 hex，5min TTL）。
func issueChallengeToken() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	token := hex.EncodeToString(raw)
	challengeTokensMu.Lock()
	challengeTokens[token] = challengeToken{value: token, expiresAt: time.Now().Add(challengeTokenTTL)}
	// 顺手清理过期 token（低频写路径顺带，无独立 janitor）
	now := time.Now()
	for k, v := range challengeTokens {
		if now.After(v.expiresAt) || v.used {
			delete(challengeTokens, k)
		}
	}
	challengeTokensMu.Unlock()
	return token
}

// consumeChallengeToken 校验并消费（一次性）。
func consumeChallengeToken(token string) bool {
	challengeTokensMu.Lock()
	defer challengeTokensMu.Unlock()
	t, ok := challengeTokens[token]
	if !ok || t.used || time.Now().After(t.expiresAt) {
		return false
	}
	challengeTokens[token] = challengeToken{value: t.value, expiresAt: t.expiresAt, used: true}
	return true
}

// powValid 校验 sha256(token+nonce) 前 challengeDifficulty 位十六进制为零。
func powValid(token, nonce string) bool {
	sum := sha256.Sum256([]byte(token + nonce))
	hexSum := hex.EncodeToString(sum[:])
	return strings.HasPrefix(hexSum, strings.Repeat("0", challengeDifficulty))
}
