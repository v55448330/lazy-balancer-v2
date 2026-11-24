package db

import (
	"strings"
	"testing"
)

// blockingSeedNames 是可拦截（stage1/stage3）的默认策略名——这些种子创建时
// 必须指向内置默认拦截页，否则「创建默认策略」后命中拦截只剩 Caddy 默认 403
// 空响应（向导新建策略默认页=1）。
var blockingSeedNames = []string{"威胁情报拦截", "手动黑名单", "自动封禁联动", "地域拦截", "WAF 请求防护", "WAF 响应防护"}

func seedByName(t *testing.T, name string) *defaultPolicySeed {
	t.Helper()
	for i := range defaultPolicySeeds {
		if defaultPolicySeeds[i].name == name {
			return &defaultPolicySeeds[i]
		}
	}
	t.Fatalf("默认策略种子缺少 %q", name)
	return nil
}

// 默认策略模板的初始值必须安全且直观：请求体记录默认关闭（向导自身警示
// 「请仅在排障期间开启」）、可拦截种子默认指向内置 403 页、名称与行为一致。
func TestDefaultPolicySeeds_safeDefaults(t *testing.T) {
	req := seedByName(t, "WAF 请求防护")
	if req.logReqBody != 0 {
		t.Fatalf("WAF 请求防护 logReqBody=%d want 0（请求体记录默认关闭）", req.logReqBody)
	}
	for _, text := range []string{req.content, req.desc} {
		if strings.Contains(text, "记录请求体") || strings.Contains(text, "开启请求体记录") {
			t.Fatalf("WAF 请求防护 文案仍宣称记录请求体: %q", text)
		}
	}
	if !strings.Contains(req.desc, "默认关闭") {
		t.Fatalf("WAF 请求防护 说明未披露请求体记录默认关闭: %q", req.desc)
	}
	cc := seedByName(t, "基础 CC 防护")
	if cc.blockPageID != 9005 {
		t.Fatalf("基础 CC 防护 blockPageID=%d want 9005（滑块页保持不变）", cc.blockPageID)
	}
	for _, name := range blockingSeedNames {
		if sd := seedByName(t, name); sd.blockPageID != 1 {
			t.Fatalf("%s blockPageID=%d want 1（内置默认拦截页）", name, sd.blockPageID)
		}
	}
	geo := seedByName(t, "地域拦截")
	if !strings.Contains(geo.desc, "IPv6") {
		t.Fatalf("地域拦截 说明未披露 IPv6 未启用时同样按海外拦截: %q", geo.desc)
	}
	resp := seedByName(t, "WAF 响应防护")
	if resp.mode != "blocking" {
		t.Fatalf("WAF 响应防护 mode=%q want blocking（名称须与阻断行为一致）", resp.mode)
	}
	for i := range defaultPolicySeeds {
		if defaultPolicySeeds[i].name == "WAF 响应检测" {
			t.Fatal("旧名 WAF 响应检测 不得再作为模板名（行为是阻断而非仅检测）")
		}
	}
}

// apply 创建的新行必须落安全默认值：请求体记录关闭、可拦截策略挂内置页。
func TestApplyDefaultSecurityPolicies_createsSafeDefaults(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	if _, err := ApplyDefaultSecurityPolicies(0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var logReq, pageID int
	if err := database.QueryRow(`SELECT COALESCE(log_request_body,0), COALESCE(block_page_id,0) FROM security_policies WHERE name='WAF 请求防护'`).Scan(&logReq, &pageID); err != nil {
		t.Fatalf("read WAF 请求防护: %v", err)
	}
	if logReq != 0 {
		t.Fatalf("新建 WAF 请求防护 log_request_body=%d want 0", logReq)
	}
	if pageID != 1 {
		t.Fatalf("新建 WAF 请求防护 block_page_id=%d want 1", pageID)
	}
	for _, name := range blockingSeedNames {
		var id int
		if err := database.QueryRow(`SELECT COALESCE(block_page_id,0) FROM security_policies WHERE name=?`, name).Scan(&id); err != nil {
			t.Fatalf("read %s block_page_id: %v", name, err)
		}
		if id != 1 {
			t.Fatalf("新建 %s block_page_id=%d want 1", name, id)
		}
	}
	var ccPage int
	if err := database.QueryRow(`SELECT COALESCE(block_page_id,0) FROM security_policies WHERE name='基础 CC 防护'`).Scan(&ccPage); err != nil {
		t.Fatalf("read CC block_page_id: %v", err)
	}
	if ccPage != 9005 {
		t.Fatalf("新建 基础 CC 防护 block_page_id=%d want 9005", ccPage)
	}
	var pages int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE id=1`).Scan(&pages); err != nil || pages != 1 {
		t.Fatalf("内置默认拦截页 id=1 必须存在（pages=%d err=%v）", pages, err)
	}
	var respMode string
	if err := database.QueryRow(`SELECT COALESCE(mode,'') FROM security_policies WHERE name='WAF 响应防护'`).Scan(&respMode); err != nil {
		t.Fatalf("read WAF 响应防护: %v", err)
	}
	if respMode != "blocking" {
		t.Fatalf("新建 WAF 响应防护 mode=%q want blocking", respMode)
	}
	var legacyN int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name='WAF 响应检测'`).Scan(&legacyN); err != nil || legacyN != 0 {
		t.Fatalf("旧名 WAF 响应检测 不得再被创建（n=%d err=%v）", legacyN, err)
	}
}

// 存量行不受新默认值影响：已存在的默认策略在 apply 时保持用户可见字段原样
// （请求体记录/拦截页），只有 reset 才恢复模板值。
func TestApplyDefaultSecurityPolicies_existingRowsKeepValues(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	// 旧模板创建的存量默认行：log_request_body=1、无拦截页。
	if _, err := database.Exec(`INSERT INTO security_policies (name,description,mode,policy_type,is_default_policy,enabled,log_request_body,block_page_id)
		VALUES ('WAF 请求防护','[默认规则] CRS 阻断模式，全选请求方向规则组；开启请求体记录','blocking','stage3',1,1,1,0)`); err != nil {
		t.Fatalf("seed legacy default row: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies(0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	status := ""
	for _, it := range items {
		if it.Kind == "policy" && it.Name == "WAF 请求防护" {
			status = it.Status
		}
	}
	if status != "exists" {
		t.Fatalf("存量行 apply status=%q want exists", status)
	}
	var logReq, pageID int
	if err := database.QueryRow(`SELECT COALESCE(log_request_body,0), COALESCE(block_page_id,0) FROM security_policies WHERE name='WAF 请求防护'`).Scan(&logReq, &pageID); err != nil {
		t.Fatalf("re-read legacy row: %v", err)
	}
	if logReq != 1 || pageID != 0 {
		t.Fatalf("存量行被改写: log_request_body=%d block_page_id=%d want 1/0", logReq, pageID)
	}
}

// 模板改名后存量默认行只跟改名（标签对齐行为），不改任何行为字段、不重复
// 创建第二条默认策略；用户禁用的行改名后仍保持禁用。
func TestApplyDefaultSecurityPolicies_legacyResponseNameRenamedOnly(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	if _, err := database.Exec(`INSERT INTO security_policies (name,description,mode,policy_type,is_default_policy,enabled,log_request_body,block_page_id,waf_check_response)
		VALUES ('WAF 响应检测','[默认规则] CRS 阻断模式，全选响应方向规则组；开启响应体检查','blocking','stage3',1,0,1,0,1)`); err != nil {
		t.Fatalf("seed legacy response row: %v", err)
	}
	items, err := ApplyDefaultSecurityPolicies(0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	status := ""
	for _, it := range items {
		if it.Kind == "policy" && it.Name == "WAF 响应防护" {
			status = it.Status
		}
	}
	if status != "disabled" {
		t.Fatalf("改名后的禁用存量行 status=%q want disabled（不得重新启用）", status)
	}
	var oldCount, newCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name='WAF 响应检测'`).Scan(&oldCount); err != nil {
		t.Fatalf("count old name: %v", err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name='WAF 响应防护'`).Scan(&newCount); err != nil {
		t.Fatalf("count new name: %v", err)
	}
	if oldCount != 0 || newCount != 1 {
		t.Fatalf("改名结果 old=%d new=%d want 0/1", oldCount, newCount)
	}
	var enabled, logReq, pageID, checkResp int
	if err := database.QueryRow(`SELECT COALESCE(enabled,1), COALESCE(log_request_body,0), COALESCE(block_page_id,0), COALESCE(waf_check_response,0) FROM security_policies WHERE name='WAF 响应防护'`).Scan(&enabled, &logReq, &pageID, &checkResp); err != nil {
		t.Fatalf("re-read renamed row: %v", err)
	}
	if enabled != 0 || logReq != 1 || pageID != 0 || checkResp != 1 {
		t.Fatalf("改名不得改行为字段: enabled=%d log_request_body=%d block_page_id=%d waf_check_response=%d want 0/1/0/1", enabled, logReq, pageID, checkResp)
	}
	var total int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE COALESCE(is_default_policy,0)=1`).Scan(&total); err != nil {
		t.Fatalf("count default policies: %v", err)
	}
	if total != 8 {
		t.Fatalf("默认策略数=%d want 8（改名不得重复创建）", total)
	}
}

// 身份补标谓词必须覆盖模板曾用名：旧版本创建、尚未带 is_default_policy 的
// 存量响应策略行仍应被识别为默认策略。
func TestBackfillDefaultPolicyMarkers_coversLegacyName(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	applyDefaultPoliciesFixture(t)
	if _, err := database.Exec(`INSERT INTO security_policies (name,description,mode,policy_type,is_default_policy,enabled)
		VALUES ('WAF 响应检测','[默认规则] CRS 阻断模式，全选响应方向规则组；开启响应体检查','blocking','stage3',0,1)`); err != nil {
		t.Fatalf("seed pre-marker row: %v", err)
	}
	if err := BackfillDefaultPolicyMarkers(); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var marked int
	if err := database.QueryRow(`SELECT COALESCE(is_default_policy,0) FROM security_policies WHERE name='WAF 响应检测'`).Scan(&marked); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if marked != 1 {
		t.Fatalf("存量旧名默认行 is_default_policy=%d want 1", marked)
	}
}
