package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// TCP 拦截提示（2026-11-06 用户裁定）：无配置项，全局固定默认文案——
// "Connection blocked by " + branding app_name（空/未注入回退 "Lazy Balancer v2"）。
// 断连路由（deny/blacklist/allow/geoip）的 lb_l4_sec 载荷恒发射 block_notice；
// trust_detect / allow_sample 透传形态不发射。

func TestTCPBlockNoticeText_fallbackAndBranding(t *testing.T) {
	t.Cleanup(func() { SetTCPBlockNoticeBrand("") })
	SetTCPBlockNoticeBrand("")
	if got := tcpBlockNoticeText(); got != "Connection blocked by Lazy Balancer v2" {
		t.Fatalf("空品牌回退 = %q, want 默认文案", got)
	}
	SetTCPBlockNoticeBrand("甲板面板")
	if got := tcpBlockNoticeText(); got != "Connection blocked by 甲板面板" {
		t.Fatalf("品牌注入 = %q, want 参照 branding app_name", got)
	}
	SetTCPBlockNoticeBrand("   ")
	if got := tcpBlockNoticeText(); got != "Connection blocked by Lazy Balancer v2" {
		t.Fatalf("纯空白品牌 = %q, want 回退默认文案", got)
	}
}

func TestTCPBlockNoticeText_controlCharsStrippedAndClamped(t *testing.T) {
	t.Cleanup(func() { SetTCPBlockNoticeBrand("") })
	SetTCPBlockNoticeBrand("A\x00B\nC\x1bD")
	got := tcpBlockNoticeText()
	if strings.ContainsAny(got, "\x00\n\x1b") {
		t.Fatalf("控制字符未剥离: %q", got)
	}
	if !strings.Contains(got, "ABCD") {
		t.Fatalf("可见字符被误删: %q", got)
	}
	SetTCPBlockNoticeBrand(strings.Repeat("长", 300))
	if got := tcpBlockNoticeText(); len(got) > 256 {
		t.Fatalf("超长未钳制: %d bytes", len(got))
	}
}

// 控制字符口径覆盖 C0+DEL 之外的 C1 区（U+0080-009F）与 Unicode 行/段
// 分隔符（U+2028/U+2029）；合法 CJK 与 C1 上界之外（U+00A0）不得误删。
// 与 caddyl4sec validateBlockNotice 同口径（该模块独立不能 import services，
// 两侧逐字同步，改动必须成对）。
func TestTCPBlockNoticeText_c1AndLineSeparatorsStripped(t *testing.T) {
	t.Cleanup(func() { SetTCPBlockNoticeBrand("") })
	SetTCPBlockNoticeBrand("A\u0085B\u009fC\u2028D\u2029E甲板F\u00a0G")
	got := tcpBlockNoticeText()
	for _, r := range []rune{0x85, 0x9F, 0x2028, 0x2029} {
		if strings.ContainsRune(got, r) {
			t.Fatalf("控制字符 U+%04X 未剥离: %q", r, got)
		}
	}
	// U+00A0 处于串中（尾部会被 TrimSpace 按空白语义裁掉，不属剥离口径）：
	// C1 上界外字符与合法 CJK 一并保留。
	if !strings.Contains(got, "ABCDE甲板F\u00a0G") {
		t.Fatalf("可见字符/CJK/C1 上界外字符被误删: %q", got)
	}
}

// 断连路由恒带 block_notice；透传形态（trust_detect）不带——回归形状。
func TestBuildTCPServer_closeRoutesCarryBlockNotice(t *testing.T) {
	stubSecurityLibsAvailable(t)
	server, err := buildTCPServer(l4SecTestRule("lb_tcp_notice"), &tcpSecurityRenderInput{policies: l4SecAllFeaturePolicies()})
	if err != nil {
		t.Fatalf("buildTCPServer: %v", err)
	}
	raw, err := json.Marshal(server)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	routes := doc["routes"].([]interface{})
	closeReasons := map[string]bool{"deny": true, "blacklist": true, "allow": true, "geoip": true}
	sawClose, sawPassthrough := 0, 0
	for _, r := range routes {
		route := r.(map[string]interface{})
		for _, h := range route["handle"].([]interface{}) {
			handler := h.(map[string]interface{})
			if handler["handler"] != "lb_l4_sec" {
				continue
			}
			reason, _ := handler["reason"].(string)
			if closeReasons[reason] {
				sawClose++
				notice, _ := handler["block_notice"].(string)
				if notice == "" {
					t.Fatalf("reason=%s 断连路由缺 block_notice", reason)
				}
				if strings.ContainsAny(notice, "\r\n") {
					t.Fatalf("block_notice 不应含换行（写入期追加 CRLF）: %q", notice)
				}
			}
			if reason == "trust_detect" {
				sawPassthrough++
				if _, has := handler["block_notice"]; has {
					t.Fatal("trust_detect 透传形态不应发射 block_notice")
				}
			}
		}
	}
	if sawClose == 0 {
		t.Fatal("夹具未产生任何断连路由（deny/blacklist/allow/geoip）——夹具失效")
	}
	if sawPassthrough == 0 {
		t.Fatal("夹具未产生 trust_detect 透传路由——回归形状失效")
	}
}
