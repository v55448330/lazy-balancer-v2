package services

// 威胁情报库经 IP 访问控制策略的名单引用生效。2026-11-25 用户裁定：威胁库不做
// 独立归因——事件保持逐策略 ACL deny 链的规则编号（1500000+policyID），不单列
// 「威胁情报库」触发类型，入库时不做任何名单比对或额外查询；用户通过策略名
// 识别威胁库策略。本用例把这一契约钉住：属主策略引用了威胁库名单、命中的就是
// 该名单里的地址，事件仍按策略链编号入库。

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

const (
	ipAclChainPolicyID     = 5
	ipAclChainRuleID       = "1500005"
	ipAclChainClient       = "45.33.32.9"
	ipAclChainTxTimestamp  = 1786447017
	ipAclChainTxNanoSuffix = "841320426"
)

// ipAclChainSeed 种子：一条规则、一份威胁情报库系统名单、一条引用该名单的
// ACL deny 策略及其绑定。
func ipAclChainSeed(t *testing.T) {
	t.Helper()
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	// 名单条目写进真实的名单文件路径：命中地址确实在威胁库名单里（不是只靠
	// 策略引用来冒充场景）。
	wafDir := t.TempDir()
	t.Cleanup(OverrideThreatWafDirForTest(wafDir))
	if err := writeThreatIplistCompiled(filepath.Join(wafDir, "threat-ustc.iplist"), []string{ipAclChainClient}); err != nil {
		t.Fatal(err)
	}
	threatList := db.ThreatSystemLists()[0]
	var threatListID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1`, threatList.Name).Scan(&threatListID); err != nil {
		if err != sql.ErrNoRows {
			t.Fatalf("查找威胁库名单: %v", err)
		}
		res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system) VALUES (?,?,?,'[]',1)`, threatList.Name, "测试威胁库", "恶意 IP")
		if err != nil {
			t.Fatal(err)
		}
		threatListID, _ = res.LastInsertId()
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','r','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,ip_acl_list_refs) VALUES (?, '威胁情报拦截', 1, 'blocking', 1, 'deny', '[]', ?)`, ipAclChainPolicyID, fmt.Sprintf("[%d]", threatListID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',?)`, ipAclChainPolicyID); err != nil {
		t.Fatal(err)
	}
}

// ipAclChainAuditLine 生成一条阶段 1 拒绝事务的审计行（host 对应夹具规则 lb_rule1）。
func ipAclChainAuditLine(txID, ruleTriggered, clientIP string) string {
	return fmt.Sprintf(`{"transaction":{"unix_timestamp":%d%s,"id":%q,"client_ip":%q,"server_id":"go029.com","request":{"method":"GET","uri":"/attr","headers":{"host":["go029.com"]}},"is_interrupted":true},"messages":[{"message":"hit %s","data":{"id":%s,"raw":"id:%s,phase:1,deny,log,msg:'IP 访问控制拒绝'"}}]}`,
		ipAclChainTxTimestamp, ipAclChainTxNanoSuffix, txID, clientIP, ruleTriggered, ruleTriggered, ruleTriggered)
}

// ipAclChainIngest 写入若干审计行并跑一轮入库。
func ipAclChainIngest(t *testing.T, lines ...string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	body := ""
	for _, line := range lines {
		body += line + "\n"
	}
	if err := os.WriteFile(logPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := securityEventsNewTailer(logPath, offsetPath).securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

type ipAclChainRow struct {
	ruleTriggered string
	policyID      int
	policyName    string
}

func ipAclChainRows(t *testing.T) map[string]ipAclChainRow {
	t.Helper()
	rows, err := db.MetricsDB.Query(`SELECT client_ip, rule_triggered, policy_id, COALESCE(policy_name,'') FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]ipAclChainRow{}
	for rows.Next() {
		var ip string
		var r ipAclChainRow
		if err := rows.Scan(&ip, &r.ruleTriggered, &r.policyID, &r.policyName); err != nil {
			t.Fatal(err)
		}
		out[ip] = r
	}
	return out
}

func TestSecurityEventsIngest_threatListPolicyHitKeepsPolicyChainRuleID(t *testing.T) {
	ipAclChainSeed(t)
	ipAclChainIngest(t, ipAclChainAuditLine("tx-threat-list", ipAclChainRuleID, ipAclChainClient))

	got, ok := ipAclChainRows(t)[ipAclChainClient]
	if !ok {
		t.Fatal("事件未入库")
	}
	if got.ruleTriggered != ipAclChainRuleID || got.policyID != ipAclChainPolicyID {
		t.Fatalf("威胁库策略的名单命中事件 rule_triggered=%q policy_id=%d, want %q / %d（保持策略链编号，不单列触发类型）",
			got.ruleTriggered, got.policyID, ipAclChainRuleID, ipAclChainPolicyID)
	}
}
