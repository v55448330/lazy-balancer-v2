package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// ruleTriggeredMultiFilterSQL 的逗号多值契约
// 单值与 ruleTriggeredFilterSQL 逐字节一致（向后兼容）；
// 多值逐段复用单段解析后 OR 连接；任一段只能走消息关键词路径时整串回退单输入。
func TestRuleTriggeredMultiFilterSQL_singleValueByteIdentical(t *testing.T) {
	for _, single := range []string{"地域拦截", "942100", "IP 访问控制", "WAF 规则（CRS）", "评分拦截", "sqlmap"} {
		var a1, a2 []any
		got := ruleTriggeredMultiFilterSQL(single, &a1)
		want := ruleTriggeredFilterSQL(single, &a2)
		if got != want {
			t.Errorf("single %q: got %q, want %q (byte-identical)", single, got, want)
		}
		if len(a1) != len(a2) {
			t.Errorf("single %q: args len %d, want %d", single, len(a1), len(a2))
		}
	}
}

func TestRuleTriggeredMultiFilterSQL_multiFamilyOR(t *testing.T) {
	var args []any
	got := ruleTriggeredMultiFilterSQL("地域拦截,自定义规则", &args)
	// (2026-09-10):单数字族(8)改精确匹配后 LIKE 片段为 0——地域拦截
	// 现为 rule_triggered = '8'。自定义规则族 1 个复合 GLOB 段保持。
	if n := strings.Count(got, "rule_triggered = ?"); n != 1 {
		t.Errorf("multi family: exact fragments=%d, want 1: %q", n, got)
	}
	if !strings.Contains(got, " OR ") || !strings.HasPrefix(got, "(") || !strings.HasSuffix(got, ")") {
		t.Errorf("multi family: must be a parenthesized OR group: %q", got)
	}
	// 自定义规则族的形态条件整体在段内（5 位任意 + ≥7 位以 1 开头）
	if !strings.Contains(got, "GLOB '[0-9][0-9][0-9][0-9][0-9]'") ||
		!strings.Contains(got, "GLOB '1[0-9][0-9][0-9][0-9][0-9][0-9]*'") {
		t.Errorf("multi family: custom-rule family condition missing: %q", got)
	}
}

func TestRuleTriggeredMultiFilterSQL_mixedFamilyAndDigits(t *testing.T) {
	var args []any
	got := ruleTriggeredMultiFilterSQL("地域拦截,942100", &args)
	if !strings.Contains(got, "rule_triggered = ?") {
		t.Errorf("mixed: digit part must keep exact-or-prefix branch: %q", got)
	}
	if !strings.Contains(got, " OR ") {
		t.Errorf("mixed: parts must be OR-joined: %q", got)
	}
}

func TestRuleTriggeredMultiFilterSQL_unresolvablePartFallsBack(t *testing.T) {
	// 「foo bar」非 family/非数字——整串回退单输入路径（保护含逗号的消息关键词）
	var a1, a2 []any
	got := ruleTriggeredMultiFilterSQL("地域拦截,foo bar", &a1)
	want := ruleTriggeredFilterSQL("地域拦截,foo bar", &a2)
	if got != want {
		t.Errorf("unresolvable part: got %q, want fallback %q", got, want)
	}
}

func TestRuleTriggeredMultiFilterSQL_partialFamilyPrefix(t *testing.T) {
	// 部分前缀段（「评分」命中「评分拦截」family）同样可拆分 OR；
	// 前缀值在 args（SQL 只有占位符），断言 949%/959% 均入参
	var args []any
	got := ruleTriggeredMultiFilterSQL("评分,自定义规则", &args)
	hasArg := func(want string) bool {
		for _, a := range args {
			if a == want {
				return true
			}
		}
		return false
	}
	// 3 字符前缀族锚定 6 位（949___/959___）——不再交叉命中
	// 5 位自定义发射 id（94900-94999 等）。
	if !hasArg("949___") || !hasArg("959___") {
		t.Errorf("partial family prefix must put 949___/959___ into args: %v", args)
	}
	if !strings.Contains(got, " OR ") {
		t.Errorf("partial family: parts must be OR-joined: %q", got)
	}
}

// （2026-09-05 安全核心域审计裁定修复）：「自定义规则」筛选 family 必须与
// categorizeAttack 总览口径一致——5 位任意数字 ID（emit=crID+10000）与 ≥7 位
// 以 1 开头的合成 ID（1000000+）归本族；6 位 1xxxxx（CRS 保留段余数、无发射
// 源，总览判「其他」）不得被 LIKE 前缀误并入。以真实 SQLite 判定生成的条件
// 实际命中哪些 ID。
func TestRuleTriggeredFilterSQL_customRuleFamilyMatchesCategorizeAttackScope(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE rule_triggered_family_probe (rule_triggered TEXT)`); err != nil {
		t.Fatal(err)
	}
	probes := []string{
		"10003",    // 5 位自定义（emit=crID+10000）
		"24567",    // 5 位自定义（不以 1 开头）
		"1000001",  // 7 位合成（1000000+n）
		"1234567",  // 7 位以 1 开头
		"3642688",  // OR 分支（DB 父规则 42）
		"67000064", // 旧内嵌 OR 分支（合成父 emit id 1000001）
		"100123",   // 6 位 1xxxxx：CRS 保留段余数，总览判「其他」
		"942100",   // CRS
		"2",        // IP ACL
		"223456",   // 6 位非 1 开头
	}
	for _, id := range probes {
		if _, err := db.DB.Exec(`INSERT INTO rule_triggered_family_probe (rule_triggered) VALUES (?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	// Given：按 family 标签生成筛选条件
	var args []any
	cond := ruleTriggeredFilterSQL("自定义规则", &args)
	// When：对探针 ID 集执行该条件
	matched := map[string]bool{}
	rows, err := db.DB.Query(`SELECT rule_triggered FROM rule_triggered_family_probe WHERE `+cond, args...)
	if err != nil {
		t.Fatalf("query family filter: %v", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		matched[id] = true
	}
	rows.Close()
	// Then：逐 ID 与 categorizeAttack 口径一致
	for _, id := range probes {
		want := categorizeAttack(id, "") == "自定义规则"
		if matched[id] != want {
			t.Errorf("自定义规则 family 匹配 %q=%v, want %v（须与 categorizeAttack 口径一致），条件 %q", id, matched[id], want, cond)
		}
	}
	for _, id := range []string{"3642688", "67000064"} {
		if !matched[id] || categorizeAttack(id, "") != "自定义规则" {
			t.Errorf("OR 分支 %s 必须在筛选与总览中都归自定义规则：matched=%v category=%q", id, matched[id], categorizeAttack(id, ""))
		}
	}
}

func TestDescribeThreatRuleName_orBranchUsesParentName(t *testing.T) {
	if got := describeThreatRuleNameWithNames("3642689", map[int]string{42: "父规则"}); got != "父规则（#3642689）" {
		t.Fatalf("OR 分支标签=%q, want 父规则名称与分支事件 id", got)
	}
}

// 阶段化模型：地域拦截 = [800000,810000)，爬虫
// = [810000,900000)。两者以互斥 6 位 GLOB 表达，且均不得落入「WAF 规则
// （CRS）」family（CRS 规则 ID 恒 9xxxxx）。
func TestRuleTriggeredFilterSQL_geoipPrecheckSegmentFamily(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE rule_triggered_geoip_probe (rule_triggered TEXT)`); err != nil {
		t.Fatal(err)
	}
	probes := []string{
		"8",      // 旧共享 GeoIP id（策略引擎时代，历史事件）
		"800123", // 预检精确段 800000+policyID
		"809999", // 地域段上界
		"810016", // 爬虫段下界
		"899999", // 爬虫段上界
		"900000", // CRS 保留段起（非 GeoIP）
		"942100", // CRS
		"80012",  // 5 位自定义规则（非 GeoIP 段）
		"2",      // IP ACL
	}
	for _, id := range probes {
		if _, err := db.DB.Exec(`INSERT INTO rule_triggered_geoip_probe (rule_triggered) VALUES (?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	matchSet := func(t *testing.T, family string) map[string]bool {
		t.Helper()
		var args []any
		cond := ruleTriggeredFilterSQL(family, &args)
		matched := map[string]bool{}
		rows, err := db.DB.Query(`SELECT rule_triggered FROM rule_triggered_geoip_probe WHERE `+cond, args...)
		if err != nil {
			t.Fatalf("query %q family filter: %v", family, err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			matched[id] = true
		}
		rows.Close()
		return matched
	}
	geoip := matchSet(t, "地域拦截")
	for _, id := range []string{"8", "800123", "809999"} {
		if !geoip[id] {
			t.Errorf("地域拦截 family 必须命中 %q", id)
		}
	}
	for _, id := range []string{"810016", "899999", "900000", "942100", "80012", "2"} {
		if geoip[id] {
			t.Errorf("地域拦截 family 不得命中 %q", id)
		}
	}
	crawler := matchSet(t, "爬虫Bot")
	for _, id := range []string{"810016", "899999"} {
		if !crawler[id] {
			t.Errorf("爬虫Bot family 必须命中 %q", id)
		}
	}
	for _, id := range []string{"800123", "809999", "942100"} {
		if crawler[id] {
			t.Errorf("爬虫Bot family 不得命中 %q", id)
		}
	}
	crs := matchSet(t, "WAF 规则（CRS）")
	if crs["800123"] || crs["809999"] || crs["810016"] || crs["899999"] {
		t.Errorf("WAF 规则（CRS）family 不得吞 GeoIP 预检段 800xxx: %v", crs)
	}
	if !crs["942100"] || !crs["900000"] {
		t.Errorf("WAF 规则（CRS）family 必须命中 9xxxxx CRS id: %v", crs)
	}
}

// 3 字符前缀族（920/921/949/959）筛选不得交叉命中 5 位自定义
// 规则发射 id（crID≥82000 时发射 92000-99999）——categorizeAttack len==5 先行
// 归「自定义规则」，筛选族与分类口径对齐：LIKE 追加三个下划线锚定总长 6 位。
func TestRuleTriggeredFilter_3CharPrefixAnchorsSixDigits(t *testing.T) {
	for _, family := range []string{"协议异常", "协议攻击", "评分拦截"} {
		var args []any
		_ = ruleTriggeredFilterSQL(family, &args)
		for _, a := range args {
			pat, ok := a.(string)
			if !ok {
				continue
			}
			if strings.HasSuffix(pat, "%") && !strings.HasSuffix(pat, "___%") {
				t.Fatalf("族 %q 的 LIKE 模式 %q 未锚定 6 位长度（前缀族不得交叉命中 5 位自定义发射 id）", family, pat)
			}
		}
	}
	var args []any
	sql := ruleTriggeredFilterSQL("协议异常", &args)
	found := false
	for _, a := range args {
		if pat, ok := a.(string); ok && strings.HasSuffix(pat, "___") {
			found = true
		}
	}
	if !found {
		t.Fatalf("协议异常族应含 6 位锚定模式（920___）: sql=%q args=%v", sql, args)
	}
}

// ---- 回归钉 ----

// 前端事件页多选筛选值为「WAF·CRS」（SecurityEvents.vue），旧结构化
// 判定只认显示标签「WAF 规则（CRS）」——多值任一段不可结构化即整串回退字面量
// LIKE，而 rule_triggered 只存规则 ID，查询恒空（正向）/排除失效（反向）。
func TestRuleTriggeredMultiFilterSQL_compactWAFCRSLabel(t *testing.T) {
	var args []any
	got := ruleTriggeredMultiFilterSQL("WAF·CRS,IP 访问控制", &args)
	if strings.Contains(got, "%WAF·CRS,IP 访问控制%") {
		t.Fatalf("「WAF·CRS」多选回退为字面量 LIKE（查询恒空）: %q", got)
	}
	if !strings.Contains(got, "GLOB '9[0-9][0-9][0-9][0-9][0-9]'") {
		t.Fatalf("「WAF·CRS」段缺少 CRS 9xxxxx 形态条件: %q", got)
	}
	if !strings.Contains(got, " OR ") {
		t.Fatalf("多段必须 OR 连接: %q", got)
	}
	// 单值契约：与单输入路径逐字节一致（args 同步）。
	var a1, a2 []any
	if g1, g2 := ruleTriggeredMultiFilterSQL("WAF·CRS", &a1), ruleTriggeredFilterSQL("WAF·CRS", &a2); g1 != g2 {
		t.Fatalf("single WAF·CRS: multi=%q single=%q", g1, g2)
	}
}

// 「WAF·」「WAF·自」等部分输入（allow-create 可输入）不得生成空 OR
// 条件 "()"（拼入 AND () 令 SQLite 语法错误 → 事件列表 500）。
func TestRuleTriggeredFilterSQL_partialWAFPrefixNeverEmpty(t *testing.T) {
	for _, input := range []string{"WAF·", "WAF·自", "WAF·C"} {
		var args []any
		got := ruleTriggeredFilterSQL(input, &args)
		if got == "" || strings.Contains(got, "()") {
			t.Fatalf("输入 %q 生成空条件（SQL 语法错误）: %q", input, got)
		}
	}
	// 「WAF·」同时覆盖 CRS 与自定义两族。
	var args []any
	got := ruleTriggeredFilterSQL("WAF·", &args)
	if !strings.Contains(got, "GLOB '9[0-9][0-9][0-9][0-9][0-9]'") {
		t.Fatalf("WAF· 部分输入缺少 CRS 族: %q", got)
	}
	if !strings.Contains(got, "GLOB '[0-9][0-9][0-9][0-9][0-9]'") {
		t.Fatalf("WAF· 部分输入缺少自定义规则族: %q", got)
	}
}

// 尾随/连续逗号产生的空段必须忽略并按剩余有效段结构化，不得因空段
// 回退字面量 LIKE（静默错结果）。
func TestRuleTriggeredMultiFilterSQL_ignoresEmptySegments(t *testing.T) {
	for _, input := range []string{"IP 访问控制,", "IP 访问控制,,WAF·CRS", ",IP 访问控制"} {
		var args []any
		got := ruleTriggeredMultiFilterSQL(input, &args)
		if got == "()" {
			t.Fatalf("输入 %q 生成空条件: %q", input, got)
		}
		for _, a := range args {
			if pat, ok := a.(string); ok && pat == "%"+input+"%" {
				t.Fatalf("输入 %q 因空段回退为字面量 LIKE（args=%v）", input, args)
			}
		}
		if strings.Contains(input, ",") && input != "IP 访问控制," && !strings.Contains(got, " OR ") {
			t.Fatalf("输入 %q 的有效段未 OR 连接: %q", input, got)
		}
	}
}

// 历史/导入的 id:5 行（绕过模式占位的信任名单 DetectionOnly 规则，现网发射
// 恒 pass,nolog 不产事件——只可能来自历史或带外写入）必须被「信任名单」族
// 命中、不被「IP 访问控制」族命中：族筛选与 triggerTypeForRule /
// attackFamilyClassOf 共用同一张 id→家族表。
func TestRuleTriggeredFilterSQL_legacyTrustBypassIdFive(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE rule_triggered_trust_probe (rule_triggered TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"2", "3", "4", "5", "7", "8", "12", "14"} {
		if _, err := db.DB.Exec(`INSERT INTO rule_triggered_trust_probe (rule_triggered) VALUES (?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	matchSet := func(t *testing.T, family string) map[string]bool {
		t.Helper()
		var args []any
		cond := ruleTriggeredFilterSQL(family, &args)
		matched := map[string]bool{}
		rows, err := db.DB.Query(`SELECT rule_triggered FROM rule_triggered_trust_probe WHERE `+cond, args...)
		if err != nil {
			t.Fatalf("query %q family filter: %v", family, err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			matched[id] = true
		}
		return matched
	}

	trust := matchSet(t, "信任名单")
	for _, id := range []string{"3", "5", "12"} {
		if !trust[id] {
			t.Errorf("信任名单 family 必须命中历史 id:%s: %v", id, trust)
		}
	}
	for _, id := range []string{"2", "4", "7", "8", "14"} {
		if trust[id] {
			t.Errorf("信任名单 family 不得命中 %s: %v", id, trust)
		}
	}

	acl := matchSet(t, "IP 访问控制")
	for _, id := range []string{"2", "4", "7"} {
		if !acl[id] {
			t.Errorf("IP 访问控制 family 必须命中 %s: %v", id, acl)
		}
	}
	for _, id := range []string{"3", "5", "12", "8", "14"} {
		if acl[id] {
			t.Errorf("IP 访问控制 family 不得命中信任名单 id:%s: %v", id, acl)
		}
	}
}
