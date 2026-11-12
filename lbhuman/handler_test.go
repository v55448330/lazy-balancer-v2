package lbhuman

import (
	"github.com/caddyserver/caddy/v2"
	"testing"
	"time"
)

func TestCookieSignAndVerify(t *testing.T) {
	secret := []byte("test-secret-32-bytes-for-hmac-sha256")
	ip := "203.0.113.7"
	ua := "Mozilla/5.0 Chrome/120"

	value, exp := signCookie(secret, ip, ua, 30*time.Minute)
	if exp.Before(time.Now()) {
		t.Fatal("cookie expiry must be in the future")
	}
	if !verifyCookie(secret, value, ip, ua, time.Now()) {
		t.Fatal("valid cookie must verify")
	}
	// IP 绑定：换 IP 必须失败
	if verifyCookie(secret, value, "203.0.113.8", ua, time.Now()) {
		t.Fatal("cookie must be IP-bound")
	}
	// UA 绑定：换 UA 必须失败
	if verifyCookie(secret, value, ip, "Different UA", time.Now()) {
		t.Fatal("cookie must be UA-bound")
	}
	// 过期拒绝
	if verifyCookie(secret, value, ip, ua, exp.Add(time.Second)) {
		t.Fatal("expired cookie must reject")
	}
	// 篡改拒绝
	if verifyCookie(secret, value+"x", ip, ua, time.Now()) {
		t.Fatal("tampered cookie must reject")
	}
}

func TestIPv6Normalization(t *testing.T) {
	// /64 归一：同 /64 前缀的不同地址视为同一身份
	a := "2001:db8:1234:5678::1"
	b := "2001:db8:1234:5678::9999"
	if normalizeIP(a) != normalizeIP(b) {
		t.Fatalf("same /64 must normalize equal: %s vs %s", normalizeIP(a), normalizeIP(b))
	}
	// 不同 /64 不归一
	c := "2001:db8:9999::1"
	if normalizeIP(a) == normalizeIP(c) {
		t.Fatal("different /64 must differ")
	}
}

func TestChallengeTokenOneTime(t *testing.T) {
	token := issueChallengeToken()
	if !consumeChallengeToken(token) {
		t.Fatal("fresh token must consume")
	}
	if consumeChallengeToken(token) {
		t.Fatal("used token must reject (one-time)")
	}
}

func TestPoWValidity(t *testing.T) {
	// 找一个合法 nonce（难度 4 前导零）
	token := "test-token"
	for i := 0; i < 200000; i++ {
		nonce := string(rune(i))
		if powValid(token, nonce) {
			if !powValid(token, nonce) {
				t.Fatal("pow must be deterministic")
			}
			return
		}
	}
	t.Fatal("no valid nonce found within 200k iterations")
}

func TestCCWindowAndTrigger(t *testing.T) {
	key := "rule1|203.0.113.99"
	// 突刺触发：40 次/10s
	for i := 0; i < 45; i++ {
		ccRecord(key, 10, false, "ua1")
	}
	stats := ccPeek(key, 10)
	if stats.Count != 45 {
		t.Fatalf("count=%d want 45", stats.Count)
	}
	trig := evalCC(stats, 40, 10, 0, 0, false)
	if !trig.Triggered || trig.Reason != "rps_spike" {
		t.Fatalf("rps spike must trigger: %+v", trig)
	}

	// 4xx 比例触发：70% 且请求≥20
	key2 := "rule1|203.0.113.100"
	for i := 0; i < 25; i++ {
		ccRecord(key2, 10, i < 20, "ua1") // 20 个 4xx，5 个正常
	}
	stats2 := ccPeek(key2, 10)
	trig2 := evalCC(stats2, 1000, 10, 70, 0, false)
	if !trig2.Triggered || trig2.Reason != "4xx_ratio" {
		t.Fatalf("4xx ratio must trigger: %+v", trig2)
	}

	// 会话异常：多 UA + RPS 超阈
	key3 := "rule1|203.0.113.101"
	for i := 0; i < 50; i++ {
		ccRecord(key3, 10, false, string(rune('a'+i%8)))
	}
	stats3 := ccPeek(key3, 10)
	trig3 := evalCC(stats3, 1000, 10, 0, 5, true)
	if !trig3.Triggered || trig3.Reason != "session_anomaly" {
		t.Fatalf("session anomaly must trigger: %+v", trig3)
	}
}

func TestExemptPaths(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{
		ExemptPaths: []string{"/api/", "/static/"},
		ExemptIPs:   []string{"10.0.0.1", "192.168.0.0/16"},
	}}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if !h.isExempt("10.0.0.1", "/") {
		t.Fatal("exact IP exempt")
	}
	if !h.isExempt("192.168.1.5", "/") {
		t.Fatal("CIDR exempt")
	}
	if !h.isExempt("1.2.3.4", "/api/users") {
		t.Fatal("path prefix exempt")
	}
	if h.isExempt("1.2.3.4", "/admin") {
		t.Fatal("non-exempt path must not match")
	}
}
