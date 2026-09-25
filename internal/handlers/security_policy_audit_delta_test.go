package handlers

// 更新安全策略审计真 delta（2026-09-25 用户裁定 A 方案）：审计详情只记
// 实际变动的字段（旧值→新值）；同值全量提交落「（无字段变化）」——此前按
// 「请求中非 nil 字段」记录，编辑页全量提交时无变化也全字段入日志。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateSecurityPolicy_auditRecordsOnlyChangedFields(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	router := newSecurityRouter(t)

	// Given：一条存量 stage2 策略（rps=100/burst=50/enabled/block_page_id=0；
	// geoip_mode/ip_whitelist_enabled 按 stage2 归一后形态播种——与 API 创建
	// 的真实存量一致，避免归一化对齐产生的真实列变更被误判为假 delta）
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, rate_limit_enabled, rate_limit_rps, rate_limit_burst, enabled, block_page_id, block_status_code, policy_type, geoip_mode, ip_whitelist_enabled)
		VALUES ('审计策略', 'off', 1, 100, 50, 1, 0, 0, 'stage2', 'off', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	path := fmt.Sprintf("/security/policies/%d", policyID)
	fullPayload := func(rps, burst int) map[string]any {
		return map[string]any{
			"name": "审计策略", "enabled": true, "policy_type": "stage2",
			"rate_limit_enabled": true, "rate_limit_rps": rps, "rate_limit_burst": burst,
			"block_page_id": 0, "block_status_code": 0, "mode": "off",
		}
	}
	readDetail := func() string {
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		return detail
	}

	// When：同值全量提交（编辑页未改任何项点保存的形态）
	if r := putJSON(t, router, path, fullPayload(100, 50)); r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：落「（无字段变化）」，不含任何字段项
	d := readDetail()
	if !strings.Contains(d, "无字段变化") {
		t.Fatalf("detail=%q, want 含（无字段变化）", d)
	}
	for _, notWant := range []string{"限流 RPS", "限流突发", "拦截页", "启用→"} {
		if strings.Contains(d, notWant) {
			t.Fatalf("同值提交 detail 不应含 %q: %q", notWant, d)
		}
	}

	// When：全量提交但其中两个字段真变（rps 100→200、burst 50→80）
	if r := putJSON(t, router, path, fullPayload(200, 80)); r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：详情只含这两个字段，且为「旧值→新值」格式
	d = readDetail()
	for _, want := range []string{"限流 RPS：100→200", "限流突发：50→80"} {
		if !strings.Contains(d, want) {
			t.Fatalf("detail 缺 %q: %q", want, d)
		}
	}
	for _, notWant := range []string{"拦截页→", "启用→", "名称→", "WAF 模式→"} {
		if strings.Contains(d, notWant) {
			t.Fatalf("未变字段不应入详情 %q: %q", notWant, d)
		}
	}
}
