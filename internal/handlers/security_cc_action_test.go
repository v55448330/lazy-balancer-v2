package handlers

// CC 触发动作三态（challenge/queue/reject）+ 排队等待秒数策略级配置契约：
// 缺省归一 challenge/0（自动=CC 窗口）；非法动作拒绝；等待秒数域 [0,300]；
// Create 与 Update 同口径；9007 内置等待页播种+queue_widget 占位符。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func ccContractText(t *testing.T, id int, col string) string {
	t.Helper()
	var v string
	if err := db.DB.QueryRow(fmt.Sprintf(`SELECT COALESCE(%s,'') FROM security_policies WHERE id=?`, col), id).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", col, err)
	}
	return v
}

func TestSecurityPolicy_ccTriggerActionNormalization(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)

	// 缺省（不携带）→ challenge（存量行为冻结）
	cid := createTestPolicy(t, router, map[string]any{
		"name": "cc-action-default", "policy_type": "stage2", "cc_detect_enabled": true,
	})
	if got := ccContractText(t, cid, "cc_trigger_action"); got != "challenge" {
		t.Fatalf("缺省动作=%q, want challenge", got)
	}
	if got := ccContractInt(t, cid, "cc_queue_wait_sec"); got != 0 {
		t.Fatalf("缺省等待秒数=%d, want 0（自动=CC 窗口）", got)
	}
	// 三态合法值往返（Create 与 Update 同口径）
	for _, action := range []string{"challenge", "queue", "reject"} {
		t.Run(action, func(t *testing.T) {
			id := createTestPolicy(t, router, map[string]any{
				"name": "cc-action-" + action, "policy_type": "stage2", "cc_detect_enabled": true,
				"cc_trigger_action": action, "cc_queue_wait_sec": 30,
			})
			if got := ccContractText(t, id, "cc_trigger_action"); got != action {
				t.Fatalf("Create 动作=%q, want %q", got, action)
			}
			if got := ccContractInt(t, id, "cc_queue_wait_sec"); got != 30 {
				t.Fatalf("Create 等待=%d, want 30", got)
			}
			uid := createTestPolicy(t, router, map[string]any{
				"name": "cc-action-u-" + action, "policy_type": "stage2", "cc_detect_enabled": true,
			})
			rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", uid), map[string]any{
				"policy_type": "stage2", "cc_trigger_action": action, "cc_queue_wait_sec": 60,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT 动作=%s status=%d body=%s", action, rec.Code, rec.Body.String())
			}
			if got := ccContractText(t, uid, "cc_trigger_action"); got != action {
				t.Fatalf("PUT 动作=%q, want %q", got, action)
			}
			if got := ccContractInt(t, uid, "cc_queue_wait_sec"); got != 60 {
				t.Fatalf("PUT 等待=%d, want 60", got)
			}
		})
	}
	// 非法动作拒绝（Create 与 Update）
	rec := postJSON(t, router, "/security/policies", map[string]any{
		"name": "cc-action-bad", "policy_type": "stage2", "cc_detect_enabled": true, "cc_trigger_action": "bogus",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法动作 Create status=%d, want 400", rec.Code)
	}
	// 等待秒数越界钳位（与 cc 阈值族同口径：负值回落 0，超上限钳 300）
	for _, tc := range []struct{ input, want int }{{-5, 0}, {301, 300}, {0, 0}, {300, 300}} {
		id := createTestPolicy(t, router, map[string]any{
			"name": fmt.Sprintf("cc-wait-%d", tc.input), "policy_type": "stage2", "cc_detect_enabled": true,
			"cc_trigger_action": "queue", "cc_queue_wait_sec": tc.input,
		})
		if got := ccContractInt(t, id, "cc_queue_wait_sec"); got != tc.want {
			t.Fatalf("等待=%d stored=%d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestSeedDefaultBlockPage_seedsQueueWaitPage(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := SeedDefaultBlockPage(t.TempDir()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var builtin int
	var name, content string
	if err := db.DB.QueryRow(`SELECT COALESCE(is_builtin,0), name, COALESCE(content,'') FROM security_block_pages WHERE id=9007`).Scan(&builtin, &name, &content); err != nil {
		t.Fatalf("9007 等待页未播种: %v", err)
	}
	if builtin != 1 {
		t.Fatalf("9007 is_builtin=%d, want 1", builtin)
	}
	if !strings.Contains(content, "{{queue_widget}}") {
		t.Fatal("9007 等待页必须含 {{queue_widget}} 占位符（lb_human 替换为倒计时组件）")
	}
	// 漂移自愈：篡改后重播种归位
	if _, err := db.DB.Exec(`UPDATE security_block_pages SET content='<html>篡改</html>', is_builtin=0 WHERE id=9007`); err != nil {
		t.Fatal(err)
	}
	if _, err := SeedDefaultBlockPage(t.TempDir()); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(content,'') FROM security_block_pages WHERE id=9007`).Scan(&content); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "{{queue_widget}}") {
		t.Fatal("9007 漂移后必须自愈归位（占位符恢复）")
	}
}
