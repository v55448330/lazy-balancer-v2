package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CC 触发后的响应方式必须从策略贯通到 lb_human handler：默认 verify，
// ban 时下发 ban（handler 侧返回 403）。
func TestBuildHumanHandler_carriesCCResponse(t *testing.T) {
	installAutobanFixture(t, "2026-11-12 10:00:00")
	if _, err := db.DB.Exec(`INSERT INTO global_config (id,human_secret) VALUES (1,'test-secret') ON CONFLICT(id) DO UPDATE SET human_secret='test-secret'`); err == nil {
		// ignore: human_secret may live in another table in some fixtures
	}
	policies := []*models.SecurityPolicy{{
		ID: 1, Enabled: true, HumanVerifyMode: "force", HumanVerifyType: "slider",
		HumanVerifyTTL: 30, CCDetectEnabled: true, CCRPSLimit: 40, CCRPSWindow: 10,
		CC4xxRatio: 70, CCSessionUAThreshold: 5, CCResponse: "",
	}}
	h := buildHumanHandler("lb_cc", policies)
	if h == nil {
		t.Fatal("human handler missing")
	}
	if got := h["cc_response"]; got != "verify" {
		t.Fatalf("默认 cc_response=%v, want verify", got)
	}
	policies[0].CCResponse = "ban"
	h = buildHumanHandler("lb_cc", policies)
	if got := h["cc_response"]; got != "ban" {
		t.Fatalf("cc_response=%v, want ban", got)
	}
}

// 挑战失败仅在开关开启时计入自动封禁；scope=logged 不计。
func TestObserveHumanChallengeFailure_respectsSwitchAndScope(t *testing.T) {
	installAutobanFixture(t, "2026-11-12 10:00:00")
	setAutobanConfigRaw(t, true, 3, 5, "1h", "all", false)
	enable := func(on bool) {
		v := 0
		if on {
			v = 1
		}
		if _, err := db.DB.Exec(`UPDATE global_config SET autoban_count_human_failed=? WHERE id=1`, v); err != nil {
			t.Fatalf("set count_human_failed: %v", err)
		}
	}

	enable(false)
	ObserveHumanChallengeFailure("203.0.113.50", "lb_cc", autobanNow())
	autobanMu.Lock()
	if autobanWindows["203.0.113.50"] != nil {
		autobanMu.Unlock()
		t.Fatal("开关关闭时挑战失败不得计入")
	}
	autobanMu.Unlock()

	enable(true)
	for i := 0; i < 3; i++ {
		ObserveHumanChallengeFailure("203.0.113.50", "lb_cc", autobanNow())
	}
	autobanMu.Lock()
	w := autobanWindows["203.0.113.50"]
	autobanMu.Unlock()
	if w == nil || w.Count != 3 || !w.Reached {
		t.Fatalf("挑战失败计数=%+v, want count=3 reached", w)
	}

	resetAutobanStateForTest()
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_scope='logged' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	ObserveHumanChallengeFailure("203.0.113.51", "lb_cc", autobanNow())
	autobanMu.Lock()
	if autobanWindows["203.0.113.51"] != nil {
		autobanMu.Unlock()
		t.Fatal("scope=logged 时挑战失败不得计入")
	}
	autobanMu.Unlock()
}
