package handlers

import (
	"net/http"
	"strconv"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 策略列表是读端点：引用名单装载失败时只能写日志，不得写「渲染跳过」审计——
// 该审计属于真正执行渲染的路径，读端点写入会账实不符（同一文件的既有契约
// 明文禁止读端点带写副作用）。空白名单摘要必须走摘要侧的轻量存在性判定，
// 不得复用渲染装载函数。
func TestSecurityPolicyList_doesNotWriteRenderSkipAudit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	// 威胁库系统名单：waf 目录指向空目录 → .iplist 缺失 → 装载失败
	restore := services.OverrideThreatWafDirForTest(t.TempDir())
	t.Cleanup(restore)
	threatName := db.ThreatSystemLists()[0].Name
	var listID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1`, threatName).Scan(&listID); err != nil {
		t.Fatalf("find seeded threat list %q: %v", threatName, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies
		(name, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs,
		 ip_whitelist, ip_blacklist, crs_excluded_rules, custom_rules, enabled, policy_type)
		VALUES ('引用威胁库','blocking',5,'allow','[]',1,?,'[]','[]','[]','[]',1,'mixed')`, "["+strconv.FormatInt(listID, 10)+"]"); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	recorder := getRequest(t, router, "/security/policies")
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var audits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='渲染跳过'`).Scan(&audits); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if audits != 0 {
		t.Fatalf("读端点写入 %d 条「渲染跳过」审计（账实不符）", audits)
	}
}
