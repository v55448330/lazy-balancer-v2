package services

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 三族触发规则的 SQL GLOB 形态（internal/handlers/security.go 事件筛选侧）与
// services 侧 Go 谓词是同一集合的两种编码——本钉测用向量表验证「同真同假」，
// 并回读 handlers 源文件钉住被测谓词文本，防两侧任何一侧静默改写段界。
//
// 已知且有意保留的窄差异（不进向量表，防误报）：GLOB 按字符形态匹配，Go 侧
// Atoi 宽松解析（"+810016"/前导零被当同一 id）——宽松形态只存在于带外构造，
// 事件写入侧 rule_triggered 恒为引擎发射的规范十进制串。豁免段 810000-810015
// 与伪装段基址 850000 本身不可由编码器产出（policyID≥1），同样不进向量表。

// 被测的 SQL 形态（与 handlers 源文件逐字节一致，见 TestSecurityEventFamilyGlob_sourcePinned）。
const (
	customFamilyGlobTestCopy  = `(rule_triggered GLOB '[0-9][0-9][0-9][0-9][0-9]' OR rule_triggered GLOB '[1-7][0-9][0-9][0-9][0-9][0-9]' OR rule_triggered GLOB '1[0-9][0-9][0-9][0-9][0-9][0-9]*' OR rule_triggered GLOB '[3-6][0-9][0-9][0-9][0-9][0-9][0-9]*')`
	geoipFamilyGlobTestCopy   = `rule_triggered GLOB '80[0-9][0-9][0-9][0-9]'`
	crawlerFamilyGlobTestCopy = `rule_triggered GLOB '8[1-9][0-9][0-9][0-9][0-9]'`
)

func TestSecurityEventFamilyGlob_sourcePinned(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "handlers", "security.go"))
	if err != nil {
		t.Fatalf("read handlers source: %v", err)
	}
	text := string(src)
	for name, copy := range map[string]string{
		"customRuleFamilyCondition": `const customRuleFamilyCondition = "` + customFamilyGlobTestCopy + `"`,
		"geoipFamilyCondition":      `const geoipFamilyCondition = "` + geoipFamilyGlobTestCopy + `"`,
		"crawlerFamilyCondition":    `const crawlerFamilyCondition = "` + crawlerFamilyGlobTestCopy + `"`,
	} {
		if !strings.Contains(text, copy) {
			t.Errorf("handlers 源码中未找到 %s 的被钉形态 %s——GLOB 文本已漂移，须与向量表同步修订", name, copy)
		}
	}
}

// TestSecurityEventFamilyGlob_agreesWithGoPredicates 向量表：每行对三族 SQL
// 形态与 services 侧 Go 谓词断言同真同假。
//   - 自定义族：securityEventsRuleIsCustomFamily（[10000,800000) ∪ ≥1000000，
//     覆盖 id+10000 发射段/合成段/OR 分支高段）。
//   - GeoIP 普通预检族：decodePrecheckRuleID 判族 = GeoIP（800001-809999，
//     SQL 形态 80xxxx 同域）。
//   - 爬虫两族：decode 判族 ∈ {豁免, 伪装}（810016-899999 可编码集）。
//   - 爬虫豁免（精确对）：IsCrawlerExemptRuleID ↔ services 单源
//     CrawlerExemptRuleIDSQLPredicate（[810016,849999] 编码回环口径）。
func TestSecurityEventFamilyGlob_agreesWithGoPredicates(t *testing.T) {
	orBranchDBParent := strconv.Itoa(3000000 + 10042*64 + 3)       // OR 分支（DB 父发射 id 10042，序号 3）
	orBranchSynthetic := strconv.Itoa(3000000 + 1000001*64 + 0)    // OR 分支（合成父，67xxxxxx）
	exemptSQL := CrawlerExemptRuleIDSQLPredicate("rule_triggered") // services 单源，免复制
	vectors := []struct {
		id                 string
		custom, geoip      bool
		crawlerTwo, exempt bool
	}{
		{"12345", true, false, false, false},           // 自定义发射段下缘（DB id 2345）
		{"9999", false, false, false, false},           // 发射下限之下（4 位）
		{"99999", true, false, false, false},           // 5 位上缘
		{"100000", true, false, false, false},          // 6 位 1 开头（DB id 90000）
		{"799999", true, false, false, false},          // 6 位 7 开头上缘
		{"800123", false, true, false, false},          // GeoIP 普通预检代表
		{"809999", false, true, false, false},          // 80 段上缘
		{"810016", false, false, true, true},           // 豁免段首 id（pid1/idx0）
		{"849999", false, false, true, true},           // 豁免段末 id（pid2499/idx15）
		{"850001", false, false, true, false},          // 伪装段首 id——豁免谓词必须排除
		{"899999", false, false, true, false},          // 伪装段末 id（pid49999）
		{"900000", false, false, false, false},         // CRS 下缘（三族之外）
		{"999999", false, false, false, false},         // CRS 上缘（三族之外）
		{"1000003", true, false, false, false},         // 本地合成段
		{orBranchDBParent, true, false, false, false},  // OR 分支 7 位 3 开头
		{orBranchSynthetic, true, false, false, false}, // OR 分支 8 位 6 开头（尾 * 覆盖长度）
		{"not-a-rule", false, false, false, false},     // 非数值 token
		{"", false, false, false, false},               // 空 token
	}

	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TABLE probe (rule_triggered TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	for _, v := range vectors {
		if _, err := database.Exec(`INSERT INTO probe (rule_triggered) VALUES (?)`, v.id); err != nil {
			t.Fatalf("insert %q: %v", v.id, err)
		}
	}
	matchSet := func(t *testing.T, cond string) map[string]bool {
		t.Helper()
		rows, err := database.Query(`SELECT rule_triggered FROM probe WHERE ` + cond)
		if err != nil {
			t.Fatalf("eval %s: %v", cond, err)
		}
		defer rows.Close()
		set := map[string]bool{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scan: %v", err)
			}
			set[id] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows: %v", err)
		}
		return set
	}
	customSQL := matchSet(t, customFamilyGlobTestCopy)
	geoipSQL := matchSet(t, geoipFamilyGlobTestCopy)
	crawlerSQL := matchSet(t, crawlerFamilyGlobTestCopy)
	exemptSQLSet := matchSet(t, exemptSQL)

	goCrawlerTwo := func(id string) bool {
		family, _, _, ok := decodePrecheckRuleID(id)
		return ok && (family == precheckRuleFamilyCrawlerExempt || family == precheckRuleFamilyCrawlerSpoof)
	}
	goGeoip := func(id string) bool {
		family, _, _, ok := decodePrecheckRuleID(id)
		return ok && family == precheckRuleFamilyGeoIP
	}
	for _, v := range vectors {
		if customSQL[v.id] != v.custom || securityEventsRuleIsCustomFamily(v.id) != v.custom {
			t.Errorf("自定义族 %q: SQL=%v Go=%v, want %v（双编码必须同真同假）", v.id, customSQL[v.id], securityEventsRuleIsCustomFamily(v.id), v.custom)
		}
		if geoipSQL[v.id] != v.geoip || goGeoip(v.id) != v.geoip {
			t.Errorf("GeoIP 族 %q: SQL=%v Go=%v, want %v（双编码必须同真同假）", v.id, geoipSQL[v.id], goGeoip(v.id), v.geoip)
		}
		if crawlerSQL[v.id] != v.crawlerTwo || goCrawlerTwo(v.id) != v.crawlerTwo {
			t.Errorf("爬虫两族 %q: SQL=%v Go=%v, want %v（双编码必须同真同假）", v.id, crawlerSQL[v.id], goCrawlerTwo(v.id), v.crawlerTwo)
		}
		if exemptSQLSet[v.id] != v.exempt || IsCrawlerExemptRuleID(v.id) != v.exempt {
			t.Errorf("爬虫豁免 %q: SQL=%v Go=%v, want %v（双编码必须同真同假）", v.id, exemptSQLSet[v.id], IsCrawlerExemptRuleID(v.id), v.exempt)
		}
	}
	// 对抗形态只进「豁免精确对」：IsCrawlerExemptRuleID 与
	// CrawlerExemptRuleIDSQLPredicate 两侧都按严格字符形态编码（GLOB 六位
	// 数字锚定长度+字符集 / Go 侧 len+charset 校验），宽松解析形态（符号
	// 前缀/前导零/尾随空白）两侧必须一致拒绝。三族判定谓词走 Atoi 宽松
	// 解析，见文件头窄差异披露，不在本循环。此时主向量集已物化，向同一
	// 表补插对抗行不影响既有断言。
	for _, id := range []string{"+810016", " 810016", "0810016", "810016 "} {
		if IsCrawlerExemptRuleID(id) {
			t.Errorf("IsCrawlerExemptRuleID(%q)=true, want false（严格 6 位形态）", id)
		}
		var hits int
		if err := database.QueryRow(`SELECT COUNT(*) FROM probe WHERE rule_triggered = ? AND `+exemptSQL, id).Scan(&hits); err != nil {
			t.Fatalf("eval adversarial %q: %v", id, err)
		}
		if hits != 0 {
			t.Errorf("豁免 SQL 谓词命中宽松形态 %q, want 不命中", id)
		}
	}
}
