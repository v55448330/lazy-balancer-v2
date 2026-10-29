package handlers

// UpdateSecurityPolicy 的存量行读取次数钉测：同一策略行的限流/ACL/GeoIP/
// 引用/类型/审计基准此前按门各读一遍（同一行 10 次，含 3 次全列扫描），
// 整段都在 BEGIN IMMEDIATE 写锁内。单次投影收敛后，请求内对
// security_policies 的 SELECT 只剩「事务开头一次 + 写后必需终态读」。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateSecurityPolicy_readsStoredRowOnce(t *testing.T) {
	recorder := countingMainDB(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled) VALUES ('单读策略', 'blocking', 1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// Given 只改描述的部分更新（所有门都要看存量：限流/ACL/GeoIP/类型/审计基准）。
	recorder.reset()
	response := putJSON(t, router, fmt.Sprintf("/security/policies/%d", policyID), map[string]any{"description": "只改描述"})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// Then 同一策略行的读语句 ≤5：事务开头单次投影 + 写后必需终态读
	//（重推断合并行 / 拦截状态码归一 / 审计名）。
	if reads := recorder.count(policyRowReadMatch); reads > 5 {
		t.Fatalf("更新请求对同一策略行的 SELECT=%d 条, want <=5（写锁内按门逐列各读一遍是 sink）", reads)
	}

	// 回归形状：审计真 delta 仍成立（单次投影不得把基准读成写后值）。
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(detail, "描述：→只改描述") {
		t.Fatalf("audit detail=%q, want 记录「描述：→只改描述」", detail)
	}

	// 畸形形状：不存在的策略必须在事务开头的单次读取即 404，且不再为各门
	// 逐列读（存在性判定不重复）。
	recorder.reset()
	missing := putJSON(t, router, "/security/policies/999999", map[string]any{"description": "x"})
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing policy status=%d body=%s, want 404", missing.Code, missing.Body.String())
	}
	if reads := recorder.count(policyRowReadMatch); reads > 1 {
		t.Fatalf("不存在策略的 SELECT=%d 条, want <=1（存在性由开头单次读取判定）", reads)
	}
}

// 部分更新不得波及未提交的列：单次投影读出的存量值只用作校验/审计基准，
// 写入仍是「指针字段才进 UPDATE」。
func TestUpdateSecurityPolicy_partialUpdateKeepsUnsubmittedColumns(t *testing.T) {
	countingMainDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode, enabled, rate_limit_enabled, rate_limit_rps, rate_limit_burst, ip_acl_mode, ip_acl_enabled) VALUES (7, '保留列策略', 'blocking', 1, 1, 33, 9, 'deny', 0)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	response := putJSON(t, router, "/security/policies/7", map[string]any{"description": "改描述"})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var rateEnabled, rps, burst, aclEnabled int
	var aclMode string
	if err := db.DB.QueryRow(`SELECT COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(rate_limit_burst,0), COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_mode,'') FROM security_policies WHERE id=7`).
		Scan(&rateEnabled, &rps, &burst, &aclEnabled, &aclMode); err != nil {
		t.Fatal(err)
	}
	if rateEnabled != 1 || rps != 33 || burst != 9 || aclEnabled != 0 || aclMode != "deny" {
		payload, _ := json.Marshal(map[string]any{"rate_limit_enabled": rateEnabled, "rps": rps, "burst": burst, "ip_acl_enabled": aclEnabled, "ip_acl_mode": aclMode})
		t.Fatalf("未被提交的列被改写: %s, want 限流(1,33,9) ACL(0,deny)", payload)
	}
}
