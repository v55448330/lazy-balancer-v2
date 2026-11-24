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
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
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
func securityEventsSeedThreatAttr(t *testing.T) string {
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
	return wafDir
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

// 威胁库名单文件由更新任务每日改写，不推进 cluster_version（摄取映射只在配置
// 版本变化时重建）。名单索引必须跟随文件本身：改写后的下一轮入库按新名单归类。
//
// Given 首轮名单含 A；When 名单文件改写为只含 B（配置版本号不变）且新事件分别来自
// A、B；Then B 记为威胁情报库，A 不再是。
func TestSecurityEventsIngest_threatIndexFollowsListFileChanges(t *testing.T) {
	wafDir := securityEventsSeedThreatAttr(t)
	securityEventsRunThreatAttrTick(t,
		securityEventsStage1AuditLine("tx-before-1", threatAttrACLRuleID, threatAttrThreatClient))
	if got := securityEventsThreatAttrRows(t)[threatAttrThreatClient].ruleTriggered; got != threatAttrThreatRuleID {
		t.Fatalf("改写前 rule_triggered=%q, want %q", got, threatAttrThreatRuleID)
	}

	listPath := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := writeThreatIplistCompiled(listPath, []string{threatAttrOtherClient}); err != nil {
		t.Fatal(err)
	}
	// 显式给新代际一个更晚的修改时间：不依赖两次写入之间的真实时间差。
	newer := time.Now().Add(time.Hour)
	for _, p := range []string{listPath, wafiplist.FastPath(listPath)} {
		if err := os.Chtimes(p, newer, newer); err != nil {
			t.Fatal(err)
		}
	}

	securityEventsRunThreatAttrTick(t,
		securityEventsStage1AuditLine("tx-after-old", threatAttrACLRuleID, threatAttrThreatClient),
		securityEventsStage1AuditLine("tx-after-new", threatAttrACLRuleID, threatAttrOtherClient))
	rows := securityEventsThreatAttrRows(t)
	if got := rows[threatAttrOtherClient].ruleTriggered; got != threatAttrThreatRuleID {
		t.Fatalf("改写后新名单内的 IP rule_triggered=%q, want %q（索引未随名单文件刷新）", got, threatAttrThreatRuleID)
	}
	if got := rows[threatAttrThreatClient].ruleTriggered; got != threatAttrACLRuleID {
		t.Fatalf("改写后已移出名单的 IP rule_triggered=%q, want %q", got, threatAttrACLRuleID)
	}
}

// 记录文件状态与装载名单的先后：状态必须在装载**之前**记录。更新任务恰在装载期间
// 改写名单文件时，索引装到哪一版内容并不要紧——要紧的是记录的状态不能是装载之后
// 的，否则下一轮比对认为文件没变，索引停在旧内容上直到文件再次变化。
func TestSecurityEventsThreatIndex_stampRecordedBeforeLoad(t *testing.T) {
	wafDir := securityEventsSeedThreatAttr(t)
	var refs string
	if err := db.DB.QueryRow(`SELECT ip_acl_list_refs FROM security_policies WHERE id=?`, threatAttrPolicyID).Scan(&refs); err != nil {
		t.Fatal(err)
	}
	policyByID := map[int]*models.SecurityPolicy{threatAttrPolicyID: {ID: threatAttrPolicyID, IPACLListRefs: refs}}
	load := func(refIDs []int64) (map[int64][]string, error) {
		entries, _, err := loadIPListEntriesVia(nil, refIDs)
		return entries, err
	}
	rewriteList := func() {
		listPath := filepath.Join(wafDir, "threat-ustc.iplist")
		if err := writeThreatIplistCompiled(listPath, []string{threatAttrOtherClient}); err != nil {
			t.Fatal(err)
		}
		newer := time.Now().Add(time.Hour)
		for _, p := range []string{listPath, wafiplist.FastPath(listPath)} {
			if err := os.Chtimes(p, newer, newer); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Given：一次重建，名单文件在装载时已被改写（装载到的是新内容）。
	_, duringRewrite := securityEventsBuildThreatListIndexWith(policyByID, func(refIDs []int64) (map[int64][]string, error) {
		rewriteList()
		return load(refIDs)
	}, securityEventsStatThreatLists)
	// When：更新任务已停、文件状态稳定，下一轮重建记录的是当前状态。
	_, settled := securityEventsBuildThreatListIndexWith(policyByID, load, securityEventsStatThreatLists)
	// Then：上一轮记录的状态必须与当前不同（即下一轮会重建），不能相等。
	if securityEventsThreatStampsEqual(duringRewrite, settled) {
		t.Fatalf("装载期间名单被改写，索引记录的却是装载之后的文件状态：下一轮比对会认为文件未变，索引停在旧内容上\n装载期间记录=%+v\n当前状态=%+v", duringRewrite, settled)
	}
}

// 锁外快照之后映射代际已推进（别的 pass 装载了新一代映射，索引随新条目一起构建
// 过）：锁内不得再用上一代的 policyByID 重建并写进新一代缓存。新旧文件状态戳
// 恰好相同时尤其要靠代际判定，而不是只比对文件状态。
func TestSecurityEventsThreatIndex_rebuiltElsewhereOnGenerationChange(t *testing.T) {
	stamp := securityEventsStatThreatLists([]string{filepath.Join(t.TempDir(), "absent.iplist")})
	entry := securityEventsMappingsCacheEntry{database: &sql.DB{}, version: 7, loaded: true, threatIndexBuilt: true, threatStamps: stamp}

	// 同代际、文件未变、也无人重建：仍需重建。
	if securityEventsThreatIndexRebuiltElsewhere(entry, entry) {
		t.Fatal("同代际且无人重建时不应判定为已由他人重建")
	}
	// 同代际，取快照之后别的 pass 已完成重建（状态戳已更新）。
	rebuilt := entry
	rebuilt.threatStamps = securityEventsStatThreatLists([]string{filepath.Join(t.TempDir(), "other.iplist")})
	if !securityEventsThreatIndexRebuiltElsewhere(entry, rebuilt) {
		t.Fatal("同代际内已有别的 pass 完成重建时不应再重建")
	}
	// 代际已推进（配置版本变化），文件状态戳不变。
	next := entry
	next.version++
	if !securityEventsThreatIndexRebuiltElsewhere(entry, next) {
		t.Fatal("映射代际已推进：必须沿用新一代条目自带的索引，不得用上一代的 policyByID 重建")
	}
	// 数据库实例更换（重连/重装）同理。
	reconnected := entry
	reconnected.database = &sql.DB{}
	if !securityEventsThreatIndexRebuiltElsewhere(entry, reconnected) {
		t.Fatal("数据库实例已更换：必须沿用新一代条目自带的索引")
	}
	// 缓存已被复位（未装载）：不得把重建结果写进未装载的条目。
	if !securityEventsThreatIndexRebuiltElsewhere(entry, securityEventsMappingsCacheEntry{}) {
		t.Fatal("缓存已复位：不得写进未装载的条目")
	}
}

// threatAttrBenchEntries 按线上量级生成名单条目（三份威胁库合计约 1.6 万条）：
// 以分散的 /32 为主、混入少量 /24，避免聚合把规模压没。
func threatAttrBenchEntries(n int) map[int64][]string {
	entries := make([]string, 0, n)
	for i := range n {
		a, b, c, d := 1+(i*7919)%200, (i*104729)%256, (i*1299709)%256, (i*15485863)%256
		if i%8 == 0 {
			entries = append(entries, fmt.Sprintf("%d.%d.%d.0/24", a, b, c))
		} else {
			entries = append(entries, fmt.Sprintf("%d.%d.%d.%d/32", a, b, c, d))
		}
	}
	per := n / 3
	return map[int64][]string{7: entries[:per], 8: entries[per : 2*per], 9: entries[2*per:]}
}

// BenchmarkThreatListIndexBuild 量「一次索引重建」的代价（只在配置版本变化或
// 名单文件被更新任务改写时发生）。
func BenchmarkThreatListIndexBuild(b *testing.B) {
	entries := threatAttrBenchEntries(16000)
	threatIDs := map[int64]bool{7: true, 8: true, 9: true}
	policies := map[int]*models.SecurityPolicy{226: {ID: 226, IPACLListRefs: "[7,8,9]"}}
	for b.Loop() {
		if index := securityEventsBuildThreatListIndexFrom(policies, threatIDs, entries); len(index) != 1 {
			b.Fatalf("索引策略数=%d, want 1", len(index))
		}
	}
}

// BenchmarkThreatIntelRuleTriggered 量「单条阶段 1 事件」的归类判定代价（热路径）：
// 名单内与名单外的 IP 交替。
func BenchmarkThreatIntelRuleTriggered(b *testing.B) {
	entries := threatAttrBenchEntries(16000)
	threatIDs := map[int64]bool{7: true, 8: true, 9: true}
	policies := map[int]*models.SecurityPolicy{226: {ID: 226, IPACLListRefs: "[7,8,9]"}}
	index := securityEventsBuildThreatListIndexFrom(policies, threatIDs, entries)
	policy := policies[226]
	inList := strings.TrimSuffix(entries[7][1], "/32")
	const outOfList = "203.0.113.200"
	inListHit := false
	for b.Loop() {
		ip := outOfList
		if inListHit {
			ip = inList
		}
		securityEventsThreatIntelRuleTriggered(threatAttrACLRuleID, policy, ip, index)
	}
}
