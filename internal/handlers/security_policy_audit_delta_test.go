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

// ID 引用→名称（2026-09-25 用户裁定）：ACL 列表引用/自定义规则/拦截页的
// 审计详情以名称呈现（缺失 ID 回落 #id，空数组=（空），拦截页 0=（无））。
func TestUpdateSecurityPolicy_auditResolvesRefNames(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	router := newSecurityRouter(t)

	// Given：名单两条、自定义规则一条、stage1 策略（refs=[7]、custom=[16]、page=0）
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id, name) VALUES (7, '中科大恶意 IP 名单（USTC）'), (10, '测试列表')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, conditions, action, score, enabled) VALUES (16, '发版探针规则', '[]', 'block', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_enabled, ip_acl_mode, ip_acl_list_refs, custom_rules, enabled, policy_type, geoip_mode, ip_whitelist_enabled)
		VALUES ('引用策略', 'off', 1, 'deny', '[7]', '[16]', 1, 'stage1', 'off', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()

	// When：refs [7]→[7,10]、custom [16]→[]、page 0→9002
	r := putJSON(t, router, fmt.Sprintf("/security/policies/%d", policyID), map[string]any{
		"policy_type": "stage1", "ip_acl_list_refs": "[7,10]", "custom_rules": "[]", "block_page_id": 9002,
	})
	if r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}

	// Then：详情呈现名称而非裸 ID
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ACL 列表引用：中科大恶意 IP 名单（USTC）→中科大恶意 IP 名单（USTC）、测试列表",
		"自定义规则：发版探针规则→（空）",
		"拦截页：（无）→系统维护页面",
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail 缺 %q: %q", want, detail)
		}
	}
	for _, notWant := range []string{"[7]", "[16]", "#9002"} {
		if strings.Contains(detail, notWant) {
			t.Fatalf("详情不应残留裸 ID %q: %q", notWant, detail)
		}
	}
}
