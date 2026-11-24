package services

// 阶段 1 名单类拒绝命中威胁情报库名单时，事件按「威胁情报库」触发类型记录。
//
// 背景：逐策略预检链把 ACL deny 规则的触发 id 编码为 1500000+策略ID——只带策略
// 编号，不带「命中的是哪份名单」。威胁情报库经 IP 访问控制策略的名单引用拦截
// 时，事件因此被归为「IP 访问控制」，威胁情报库的筛选与标签形同虚设。入库侧在
// 属主归因完成之后判定：命中的是属主策略引用的威胁情报库名单 → 按威胁情报库的
// 固定 id 记录（筛选、标签、总览分桶沿用既有口径）；属主策略不变。

import (
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

const (
	threatAttrPolicyID     = 5
	threatAttrACLRuleID    = "1500005"
	threatAttrThreatClient = "45.33.32.9"
	threatAttrOtherClient  = "198.51.100.7"
	threatAttrThreatRuleID = "14"
	threatAttrTxTimestamp  = 1786447017
	threatAttrTxNanoSuffix = "841320426"
)

// securityEventsStage1AuditLine 生成一条阶段 1 拒绝事务的审计行（规则 id 与
// 客户端 IP 可指定；host 对应夹具规则 lb_rule1）。
func securityEventsStage1AuditLine(txID, ruleTriggered, clientIP string) string {
	return fmt.Sprintf(`{"transaction":{"unix_timestamp":%d%s,"id":%q,"client_ip":%q,"server_id":"go029.com","request":{"method":"GET","uri":"/attr","headers":{"host":["go029.com"]}},"is_interrupted":true},"messages":[{"message":"hit %s","data":{"id":%s,"raw":"id:%s,phase:1,deny,log,msg:'IP 访问控制拒绝'"}}]}`,
		threatAttrTxTimestamp, threatAttrTxNanoSuffix, txID, clientIP, ruleTriggered, ruleTriggered, ruleTriggered)
}

// securityEventsSeedThreatAttr 种子：一条规则、一份威胁情报库系统名单（条目来自
// .iplist 文件，与生产读取路径一致）、一条引用该名单的 ACL deny 策略及其绑定。
func securityEventsSeedThreatAttr(t *testing.T) {
	t.Helper()
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	wafDir := t.TempDir()
	t.Cleanup(OverrideThreatWafDirForTest(wafDir))
	if err := writeThreatIplistCompiled(filepath.Join(wafDir, "threat-ustc.iplist"), []string{threatAttrThreatClient}); err != nil {
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
	refs := fmt.Sprintf("[%d]", threatListID)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,ip_acl_list_refs) VALUES (?, '威胁情报拦截', 1, 'blocking', 1, 'deny', '[]', ?)`, threatAttrPolicyID, refs); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',?)`, threatAttrPolicyID); err != nil {
		t.Fatal(err)
	}
}

// securityEventsRunThreatAttrTick 写入若干审计行并跑一轮入库。
func securityEventsRunThreatAttrTick(t *testing.T, lines ...string) {
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

type threatAttrRow struct {
	ruleTriggered string
	policyID      int
	policyName    string
}

func securityEventsThreatAttrRows(t *testing.T) map[string]threatAttrRow {
	t.Helper()
	rows, err := db.MetricsDB.Query(`SELECT client_ip, rule_triggered, policy_id, COALESCE(policy_name,'') FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]threatAttrRow{}
	for rows.Next() {
		var ip string
		var r threatAttrRow
		if err := rows.Scan(&ip, &r.ruleTriggered, &r.policyID, &r.policyName); err != nil {
			t.Fatal(err)
		}
		out[ip] = r
	}
	return out
}

// Given 属主策略引用了威胁情报库名单，When 请求 IP 命中该名单，
// Then 事件按威胁情报库的固定 id 落库，属主策略仍是该策略。
func TestSecurityEventsIngest_threatIntelHitRecordedAsThreatFamily(t *testing.T) {
	securityEventsSeedThreatAttr(t)
	securityEventsRunThreatAttrTick(t,
		securityEventsStage1AuditLine("tx-threat-hit", threatAttrACLRuleID, threatAttrThreatClient))

	got := securityEventsThreatAttrRows(t)[threatAttrThreatClient]
	if got.ruleTriggered != threatAttrThreatRuleID {
		t.Fatalf("rule_triggered=%q, want %q（命中威胁情报库名单必须按威胁情报库记录）", got.ruleTriggered, threatAttrThreatRuleID)
	}
	if got.policyID != threatAttrPolicyID || got.policyName != "威胁情报拦截" {
		t.Fatalf("属主策略=(%d,%q), want (%d,\"威胁情报拦截\")（改触发类型不得改变属主归因）", got.policyID, got.policyName, threatAttrPolicyID)
	}
}

// Given 同一策略，When 请求 IP 不在威胁情报库名单里，
// Then 触发 id 保持逐策略链原值（仍是 IP 访问控制）。
func TestSecurityEventsIngest_nonThreatHitKeepsPolicyChainRuleID(t *testing.T) {
	securityEventsSeedThreatAttr(t)
	securityEventsRunThreatAttrTick(t,
		securityEventsStage1AuditLine("tx-other", threatAttrACLRuleID, threatAttrOtherClient))

	got := securityEventsThreatAttrRows(t)[threatAttrOtherClient]
	if got.ruleTriggered != threatAttrACLRuleID || got.policyID != threatAttrPolicyID {
		t.Fatalf("got (%q,%d), want (%q,%d)", got.ruleTriggered, got.policyID, threatAttrACLRuleID, threatAttrPolicyID)
	}
}

// securityEventsThreatIntelRuleTriggered 的形状表：只有「阶段 1 名单类预检族」
// 且「属主策略的威胁库名单命中」才改写；其余一律原样。
func TestSecurityEventsThreatIntelRuleTriggered_shapes(t *testing.T) {
	threat := map[int][]netip.Prefix{threatAttrPolicyID: {netip.MustParsePrefix("45.33.32.0/24")}}
	owner := &models.SecurityPolicy{ID: threatAttrPolicyID}
	cases := []struct {
		name, ruleTriggered, clientIP, want string
		policy                              *models.SecurityPolicy
		index                               map[int][]netip.Prefix
	}{
		{"ACL deny 链命中威胁库", threatAttrACLRuleID, threatAttrThreatClient, threatAttrThreatRuleID, owner, threat},
		{"ACL deny 链未命中威胁库", threatAttrACLRuleID, threatAttrOtherClient, threatAttrACLRuleID, owner, threat},
		{"黑名单链命中威胁库", "1510005", threatAttrThreatClient, threatAttrThreatRuleID, owner, threat},
		{"GeoIP 预检族不改写", "800005", threatAttrThreatClient, "800005", owner, threat},
		{"爬虫豁免族不改写", "810005", threatAttrThreatClient, "810005", owner, threat},
		{"属主策略未引用威胁库", threatAttrACLRuleID, threatAttrThreatClient, threatAttrACLRuleID, owner, nil},
		{"属主策略为空（未归因）", threatAttrACLRuleID, threatAttrThreatClient, threatAttrACLRuleID, nil, threat},
		{"客户端 IP 为空", threatAttrACLRuleID, "", threatAttrACLRuleID, owner, threat},
		{"客户端 IP 畸形", threatAttrACLRuleID, "not-an-ip", threatAttrACLRuleID, owner, threat},
		{"历史固定 id 原样", threatAttrThreatRuleID, threatAttrThreatClient, threatAttrThreatRuleID, owner, threat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := securityEventsThreatIntelRuleTriggered(tc.ruleTriggered, tc.policy, tc.clientIP, tc.index); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// securityEventsBuildThreatListIndexFrom 的形状表：只收威胁库名单的条目；
// 引用集合相同的策略共享同一份前缀集；未引用威胁库的策略不出现。
func TestSecurityEventsBuildThreatListIndexFrom_shapes(t *testing.T) {
	policies := map[int]*models.SecurityPolicy{
		1: {ID: 1, IPACLListRefs: "[50]"},
		2: {ID: 2, IPACLListRefs: "[50, 51]"},
		3: {ID: 3, IPACLListRefs: "[60]"},
		4: {ID: 4},
	}
	threatIDs := map[int64]bool{50: true, 51: true}
	entries := map[int64][]string{
		50: {"45.33.32.9"},
		51: {"198.51.100.0/24"},
		60: {"203.0.113.5"},
	}
	index := securityEventsBuildThreatListIndexFrom(policies, threatIDs, entries)
	if len(index) != 2 {
		t.Fatalf("索引策略数=%d, want 2（只有引用了威胁库的策略）: %v", len(index), index)
	}
	if !securityEventsIPInPrefixSet("45.33.32.9", index[1]) || securityEventsIPInPrefixSet("198.51.100.7", index[1]) {
		t.Fatalf("策略 1 的威胁库集合应只含名单 50: %v", index[1])
	}
	if !securityEventsIPInPrefixSet("45.33.32.9", index[2]) || !securityEventsIPInPrefixSet("198.51.100.7", index[2]) {
		t.Fatalf("策略 2 的威胁库集合应含名单 50 与 51: %v", index[2])
	}
	if securityEventsIPInPrefixSet("203.0.113.5", index[2]) {
		t.Fatal("非威胁库名单（60）的条目不得进入威胁库集合")
	}
	// 引用集合相同的另一条策略共享同一份切片（同一代际内不重复聚合）。
	policies[5] = &models.SecurityPolicy{ID: 5, IPACLListRefs: "[51, 50]"}
	index = securityEventsBuildThreatListIndexFrom(policies, threatIDs, entries)
	if len(index[2]) == 0 || &index[2][0] != &index[5][0] {
		t.Fatal("引用集合相同（仅顺序不同）的策略必须共享同一份前缀集")
	}
	if index == nil || len(index) != 3 {
		t.Fatalf("索引策略数=%d, want 3", len(index))
	}
}
