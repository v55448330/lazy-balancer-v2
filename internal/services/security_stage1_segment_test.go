package services

import (
	"strconv"
	"strings"
	"testing"
)

// 一致性钉：Stage1PrecheckSegmentSQL / Stage1PrecheckIDSQLList 与
// Go 谓词 IsStage1PrecheckID 三处同源——固定族、GeoIP 段任一处漏改即在此失败。
func TestStage1PrecheckSegmentSQL_matchesGoPredicate(t *testing.T) {
	// 1) Go 谓词固定族 {2,4,7,8,14} 必须逐项在 SQL 清单中（带引号形态），
	//    且 SQL 清单必须内联进段谓词（防止两常量分叉）。
	fixedIDs := []int{2, 4, 7, 8, 14}
	for _, id := range fixedIDs {
		if !IsStage1PrecheckID(id) {
			t.Fatalf("IsStage1PrecheckID(%d)=false，固定族失守", id)
		}
		quoted := "'" + strconv.Itoa(id) + "'"
		if !strings.Contains(Stage1PrecheckIDSQLList, quoted) {
			t.Fatalf("Stage1PrecheckIDSQLList 缺固定族 id %d：%s", id, Stage1PrecheckIDSQLList)
		}
		if !strings.Contains(Stage1PrecheckSegmentSQL, quoted) {
			t.Fatalf("Stage1PrecheckSegmentSQL 未内联固定族 id %d：%s", id, Stage1PrecheckSegmentSQL)
		}
	}

	// 2) SQL 清单恰为 8 项（"（8 段）"）——数量漂移即暴露新增/漏删。
	if got := strings.Count(Stage1PrecheckIDSQLList, ",") + 1; got != 8 {
		t.Fatalf("Stage1PrecheckIDSQLList 项数=%d，want 8：%s", got, Stage1PrecheckIDSQLList)
	}
	// 防御性包含的 3/5/12（SQL 计入阶段 1，Go 谓词不判 true——nolog pass 不产事件）。
	for _, id := range []int{3, 5, 12} {
		if !strings.Contains(Stage1PrecheckIDSQLList, "'"+strconv.Itoa(id)+"'") {
			t.Fatalf("Stage1PrecheckIDSQLList 缺防御性 id %d：%s", id, Stage1PrecheckIDSQLList)
		}
	}

	// 3) GeoIP 段：段谓词含 6 位 8 开头形态（GLOB 字符集锚定，非 LIKE——
	//    非数字脏行不得因前缀碰巧匹配而误入段）；谓词对段内为 true、段外（上界）为 false。
	if !strings.Contains(Stage1PrecheckSegmentSQL, "GLOB '8[0-9][0-9][0-9][0-9][0-9]'") {
		t.Fatalf("Stage1PrecheckSegmentSQL 未含 GeoIP 段形态（GLOB 定长锚定）：%s", Stage1PrecheckSegmentSQL)
	}
	if strings.Contains(Stage1PrecheckSegmentSQL, "LIKE '8%'") || strings.Contains(Stage1PrecheckSegmentSQL, "LIKE '150%'") || strings.Contains(Stage1PrecheckSegmentSQL, "LIKE '151%'") {
		t.Fatalf("Stage1PrecheckSegmentSQL 仍含未锚定 LIKE 形态：%s", Stage1PrecheckSegmentSQL)
	}
	for _, id := range []int{geoipPrecheckRuleBase, geoipPrecheckRuleBase + 1, geoipPrecheckRuleBase + 99999} {
		if !IsStage1PrecheckID(id) {
			t.Fatalf("IsStage1PrecheckID(%d)=false，GeoIP 段失守", id)
		}
	}
	for _, id := range []int{geoipPrecheckRuleBase - 1, geoipPrecheckRuleBase + 100000} {
		if IsStage1PrecheckID(id) {
			t.Fatalf("IsStage1PrecheckID(%d)=true，超出 GeoIP 段界", id)
		}
	}
}

// 真执行钉：把整段 Stage1PrecheckSegmentSQL 送进真实 SQLite 执行（不是子串
// 形状断言）——删掉 LENGTH(rule_triggered)=6 后 '80'/'80000'/'8000000' 会落进
// 阶段 1 段，逐值对账即刻失败。同时显式断言 6 位防护子串仍在。
func TestStage1PrecheckSegmentSQL_executesAgainstSQLite(t *testing.T) {
	if !strings.Contains(Stage1PrecheckSegmentSQL, "LENGTH(rule_triggered)=6") {
		t.Fatalf("段谓词缺少 6 位长度防护：%s", Stage1PrecheckSegmentSQL)
	}
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`CREATE TABLE stage1_probe (rule_triggered TEXT)`); err != nil {
		t.Fatal(err)
	}
	values := []string{
		// 固定族（含防御性 3/5/12）与近邻非成员
		"2", "3", "4", "5", "7", "8", "12", "14", "1", "6", "9", "10", "11", "13", "15",
		// GeoIP 段界内/外 + 短文本/超长文本（长度防护）
		"800000", "800001", "899999", "900000", "80", "80000", "8000000", "",
		// ACL/黑名单链段界内（GLOB 锚定后必须命中）
		"1500000", "1500002", "1509999", "1510000", "1510002", "1519999",
		// 非数字脏行（带外写入形态）：前缀碰巧同段但含字母——LIKE 会放行，GLOB 必须拒绝
		"150abc", "151x", "8xx", "80000a",
	}
	for _, v := range values {
		if _, err := database.Exec(`INSERT INTO stage1_probe (rule_triggered) VALUES (?)`, v); err != nil {
			t.Fatalf("insert %q: %v", v, err)
		}
	}
	rows, err := database.Query(`SELECT rule_triggered FROM stage1_probe WHERE ` + Stage1PrecheckSegmentSQL)
	if err != nil {
		t.Fatalf("阶段 1 段谓词在 SQLite 执行失败: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got[v] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		want := false
		if n, convErr := strconv.Atoi(v); convErr == nil {
			want = IsStage1PrecheckEventID(n)
		}
		if got[v] != want {
			t.Fatalf("值 %q 在段谓词中命中=%v, want %v（SQL 与 Go 谓词分叉）", v, got[v], want)
		}
	}
}

// 三集合对账：事件分段耗时选值谓词 securityEventsIsPrecheckRule 必须与
// IsStage1PrecheckID/Stage1PrecheckIDSQLList 同集合——第三处字面量漏改
// （新增/删除预检 id 时）即在此失败。
func TestStage1PrecheckSegmentSQL_eventDurationPredicateReconciled(t *testing.T) {
	// SQL 清单 8 项（含防御性 3/5/12）逐一对事件口径为 true。
	for _, id := range []int{2, 3, 4, 5, 7, 8, 12, 14} {
		if !securityEventsIsPrecheckRule(strconv.Itoa(id)) {
			t.Fatalf("securityEventsIsPrecheckRule(%d)=false，与 SQL 清单分叉", id)
		}
	}
	// 近邻非成员不得混入。
	for _, id := range []int{0, 1, 6, 9, 10, 11, 13, 15, 100} {
		if securityEventsIsPrecheckRule(strconv.Itoa(id)) {
			t.Fatalf("securityEventsIsPrecheckRule(%d)=true，越出预检族", id)
		}
	}
	// GeoIP 段：段内 true、段界外 false（与段谓词 GLOB 定长锚定同口径）。
	for _, id := range []int{geoipPrecheckRuleBase, geoipPrecheckRuleBase + 12345, geoipPrecheckRuleLimit - 1} {
		if !securityEventsIsPrecheckRule(strconv.Itoa(id)) {
			t.Fatalf("securityEventsIsPrecheckRule(%d)=false，GeoIP 段失守", id)
		}
	}
	for _, id := range []int{geoipPrecheckRuleBase - 1, geoipPrecheckRuleLimit} {
		if securityEventsIsPrecheckRule(strconv.Itoa(id)) {
			t.Fatalf("securityEventsIsPrecheckRule(%d)=true，超出 GeoIP 段界", id)
		}
	}
}

// 真执行钉：非数字脏行（带外写入形态）不得因前缀碰巧同段而误入阶段 1 段
// （LIKE '150%' 会放行 '150abc'，GLOB 字符集锚定必须拒绝）。
func TestStage1PrecheckSegmentSQL_rejectsNonNumericRows(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("CREATE TABLE stage1_probe (rule_triggered TEXT)"); err != nil {
		t.Fatal(err)
	}
	values := []string{
		"1500000", "1500002", "1509999", "1510000", "1510002", "1519999", // ACL/黑名单链段界内
		"150abc", "151x", "8xx", "80000a", // 非数字脏行：LIKE 会放行，GLOB 必须拒绝
	}
	for _, v := range values {
		if _, err := database.Exec("INSERT INTO stage1_probe (rule_triggered) VALUES (?)", v); err != nil {
			t.Fatalf("insert %q: %v", v, err)
		}
	}
	rows, err := database.Query("SELECT rule_triggered FROM stage1_probe WHERE " + Stage1PrecheckSegmentSQL)
	if err != nil {
		t.Fatalf("阶段 1 段谓词在 SQLite 执行失败: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got[v] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		want := false
		if n, convErr := strconv.Atoi(v); convErr == nil {
			want = IsStage1PrecheckEventID(n)
		}
		if got[v] != want {
			t.Fatalf("值 %q 在段谓词中命中=%v, want %v（SQL 与 Go 谓词分叉）", v, got[v], want)
		}
	}
}
