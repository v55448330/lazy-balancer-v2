package lbhuman

// 会话指纹采集（自动封禁 NAT 检测的会话身份证据，无 JA3）：
// cookie 签名段优先（__lb_human 的 HMAC 段，human_secret 密钥绑定不可裸伪造），
// UA+Accept-Language 组合哈希兜底（弱证据，前缀隔离）。
// 与面板侧 services.autobanSessionFingerprint 为镜像实现——lbhuman 是依赖
// Caddy 的独立插件模块，面板主模块不引入其依赖树；改一处必须同步另一处，
// 语义等价由 fingerprint_test.go 的对拍钉测兜底。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

// sessionFingerprint 会话指纹：
//   - cookie 签名段优先：__lb_human 形如 base64url(exp|nonce).HMAC-hex，
//     取签名段前 16 位 hex（c: 前缀）。签名由 human_secret 密钥绑定（IP/UA/
//     payload 全参与 HMAC），无密钥不可伪造新签名段；同会话 cookie 不变 →
//     指纹稳定。此处只做形态门（payload 可解码+签名段 64 位 hex），密钥校验
//     由 verifyCookie 承担——指纹是计数身份不是放行凭证。
//   - 无有效 cookie → UA+Accept-Language 组合 sha256 前 16 位 hex（u: 前缀）。
//   - UA 与语言均空 → 空串（无会话标识，自动封禁计 IP 级）。
func sessionFingerprint(cookieValue, ua, acceptLanguage string) string {
	if cookieValue != "" {
		parts := strings.SplitN(cookieValue, ".", 2)
		if len(parts) == 2 && len(parts[1]) == 64 {
			if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
				if _, err := hex.DecodeString(parts[1]); err == nil {
					return "c:" + parts[1][:16]
				}
			}
		}
	}
	if ua == "" && acceptLanguage == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua + "\x00" + acceptLanguage))
	return "u:" + hex.EncodeToString(sum[:8])
}

// requestSessionFingerprint 从请求提取会话指纹（cookie 精确名匹配 __lb_human）。
func requestSessionFingerprint(r *http.Request) string {
	cookieValue := ""
	if c, err := r.Cookie(cookieName); err == nil {
		cookieValue = c.Value
	}
	return sessionFingerprint(cookieValue, r.UserAgent(), r.Header.Get("Accept-Language"))
}
