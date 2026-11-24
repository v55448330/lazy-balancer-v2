package handlers

// 更新安全策略审计 delta 必须与落库值同源：写侧归一（mapIntPtr/mapStrPtr 的
// 默认回落与钳制）发生在 UPDATE 构建处，delta 若取请求原始值会记录一个从未
// 落库的「变更」（cc_rps_limit=-5 落 40 却记录 40→-5）。本文件钉住归一字段
// 的审计终态口径：归一后与存量同值=无变更；真变更记归一后的值。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateSecurityPolicy_auditDeltaUsesNormalizedValues(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	router := newSecurityRouter(t)
	// 存量 stage2 CC 策略（CC 阈值默认形态，与 API 创建的真实存量一致）。
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, human_verify_mode, human_verify_type, human_verify_ttl, cc_rps_limit, enabled, policy_type, geoip_mode, ip_whitelist_enabled)
		VALUES ('归一审计', 'off', 'force', 'slider', 30, 40, 1, 'stage2', 'off', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	path := fmt.Sprintf("/security/policies/%d", policyID)
	readDetail := func() string {
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		return detail
	}

	// When：提交 cc_rps_limit=-5（写侧归一回落缺省 40，与存量同值）。
	if r := putJSON(t, router, path, map[string]any{"cc_rps_limit": -5}); r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(cc_rps_limit,0) FROM security_policies WHERE id=?`, policyID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 40 {
		t.Fatalf("cc_rps_limit=%d, want 40（负值回落缺省）", stored)
	}
	// Then：审计不得记录从未落库的 -5，归一后无变更落「（无字段变化）」。
	detail := readDetail()
	if strings.Contains(detail, "-5") || strings.Contains(detail, "CC 请求速率阈值") {
		t.Fatalf("detail=%q, want 无 CC 请求速率阈值变更（落库值与存量同为 40）", detail)
	}
	if !strings.Contains(detail, "无字段变化") {
		t.Fatalf("detail=%q, want 含（无字段变化）", detail)
	}

	// When：提交超上限值 200000（写侧钳制到 100000）。
	if r := putJSON(t, router, path, map[string]any{"cc_rps_limit": 200000}); r.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", r.Code, r.Body.String())
	}
	// Then：审计记归一后的钳制值（40→100000），不是请求原始值。
	detail = readDetail()
	if !strings.Contains(detail, "CC 请求速率阈值：40→100000") {
		t.Fatalf("detail=%q, want CC 请求速率阈值：40→100000（归一后终值）", detail)
	}
	if strings.Contains(detail, "200000") {
		t.Fatalf("detail=%q, 不得记录未落库的请求原始值 200000", detail)
	}
}
