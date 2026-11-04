package services

// 攻击口径（放行不计入攻击）Go 谓词与 SQL 谓词的一致性钉测：两形态被事件表
// 聚合（SQL）与 Go 侧逐行过滤（rollup 固化/事件流）分别消费，集合一旦分叉，
// 同一个窗口在面板不同卡片上会给出互相矛盾的总量。

import (
	"strconv"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// TestCrawlerExemptAttackScopeSQLMatchesGo 逐点对账：段界全覆盖 + 6 位全集
// 抽样 + 畸形文本，SQL 与 Go 判定必须完全一致。
func TestCrawlerExemptAttackScopeSQLMatchesGo(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	stmt, err := db.MetricsDB.Prepare(`SELECT ` + AttackEventSQLPredicate("rule_triggered", "action") + ` FROM (SELECT ? AS rule_triggered, ? AS action)`)
	if err != nil {
		t.Fatalf("prepare predicate query: %v", err)
	}
	defer stmt.Close()

	check := func(rule, action string) {
		t.Helper()
		var sqlCounts int
		if err := stmt.QueryRow(rule, action).Scan(&sqlCounts); err != nil {
			t.Fatalf("query predicate for rule=%q action=%q: %v", rule, action, err)
		}
		want := 0
		if SecurityEventCountsAsAttack(action, rule) {
			want = 1
		}
		if sqlCounts != want {
			t.Fatalf("rule=%q action=%q: SQL=%d Go=%d（口径分叉）", rule, action, sqlCounts, want)
		}
	}

	// 边界语义显式期望（不依赖 Go↔SQL 等值自证——两侧同时引入同一 off-by-one
	// 时等值断言仍绿）：豁免段 = [810016, 849999]（base+16 起、伪装段起点前），
	// 且只对 logged 生效。
	for _, tc := range []struct {
		rule, action string
		wantAttack   bool
	}{
		{"810015", SecurityEventActionLogged, true},  // 豁免段前最后一格
		{"810016", SecurityEventActionLogged, false}, // 豁免段首
		{"810031", SecurityEventActionLogged, false}, // 段内（旧 15 引擎末槽之后仍在段内）
		{"849999", SecurityEventActionLogged, false}, // 豁免段尾
		{"850000", SecurityEventActionLogged, true},  // 伪装段起点（实际 deny，计入攻击）
		{"810031", SecurityEventActionBlocked, true}, // blocked 恒计入攻击
	} {
		if got := SecurityEventCountsAsAttack(tc.action, tc.rule); got != tc.wantAttack {
			t.Fatalf("CountsAsAttack(%q,%q)=%v, want %v", tc.action, tc.rule, got, tc.wantAttack)
		}
	}

	// 段界全覆盖：普通 GeoIP 段尾、豁免段内起始前一格、段首、段内首个
	// 合法 id、段尾、伪装段起点、CRS 段首。
	for _, rule := range []string{
		"800001", "809999", "810000", "810015", "810016", "810017",
		"810031", "810032", "849999", "850000", "850001", "899999", "900000", "999999",
	} {
		for _, action := range []string{SecurityEventActionBlocked, SecurityEventActionLogged} {
			check(rule, action)
		}
	}

	// 6 位全集抽样（含非豁免段与任意数字组合，步长避开 16 的整数倍以覆盖
	// 段内各类槽位）。
	for n := 100000; n <= 999999; n += 787 {
		check(strconv.Itoa(n), SecurityEventActionLogged)
	}

	// 畸形/宽松形态：长度非 6、带符号、空白、前导零、非数字、空串。
	for _, rule := range []string{
		"", " ", "81001", "8100160", "+810016", "-810016", " 810016", "810016 ",
		"0810016", "081001", "81O016", "八1016", "810016.0", "810016\n",
	} {
		for _, action := range []string{SecurityEventActionBlocked, SecurityEventActionLogged} {
			check(rule, action)
		}
	}

	// blocked 的放行族事件必须计入（不隐藏真实拦截）。
	check("810016", SecurityEventActionBlocked)
	// logged 的放行族事件不计入。
	check("810016", SecurityEventActionLogged)
}

// TestAttackScopeCountsAnyNonCrawlerPass 非放行族的 logged 事件仍计入攻击
// （检测模式下的 WAF 命中是攻击面的一部分）。
func TestAttackScopeCountsAnyNonCrawlerPass(t *testing.T) {
	for _, rule := range []string{"", "8", "942100", "800005", "850001", "429", "10001"} {
		if !SecurityEventCountsAsAttack(SecurityEventActionLogged, rule) {
			t.Fatalf("rule %q: logged 事件应计入攻击口径", rule)
		}
	}
}

// TestTrustDetectLoggedEventExcludedFromAttackScope 保留检测事件（2026-11-04
// 语义）不计入攻击口径：id:12 logged 是「命中信任名单」的可见性记录（独立
// 轻量检测事务、pass 恒不拦截），与「已验证爬虫放行 logged 不计入」同例。
// blocked 形态（生产不可达——pass 恒不中断）保持计入；近似 id（1/2/112/
// 带空白变体）不得被误排除。Go 判据与 SQL 谓词逐点对账（同 TestCrawlerExempt
// AttackScopeSQLMatchesGo 的口径分叉防线）。
func TestTrustDetectLoggedEventExcludedFromAttackScope(t *testing.T) {
	if SecurityEventCountsAsAttack(SecurityEventActionLogged, "12") {
		t.Fatal("id:12 logged（保留检测）必须排除出攻击口径——信任名单命中是可见性记录，不是攻击")
	}
	if !SecurityEventCountsAsAttack(SecurityEventActionBlocked, "12") {
		t.Fatal("id:12 blocked 形态必须保持计入攻击（防御性口径：pass 恒不中断，出现即畸形）")
	}

	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.SetDB(oldDB)
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	stmt, err := db.MetricsDB.Prepare(`SELECT ` + AttackEventSQLPredicate("rule_triggered", "action") + ` FROM (SELECT ? AS rule_triggered, ? AS action)`)
	if err != nil {
		t.Fatalf("prepare predicate query: %v", err)
	}
	defer stmt.Close()
	for _, tc := range []struct {
		rule, action string
		wantAttack   bool
	}{
		{"12", SecurityEventActionLogged, false},
		{"12", SecurityEventActionBlocked, true},
		{"1", SecurityEventActionLogged, true},   // 近似 id 不误排
		{"2", SecurityEventActionLogged, true},   // 近似 id 不误排
		{"112", SecurityEventActionLogged, true}, // 近似 id 不误排
		{"12 ", SecurityEventActionLogged, true}, // 空白变体不误排
		{" 12", SecurityEventActionLogged, true}, // 空白变体不误排
		{"13", SecurityEventActionLogged, true},  // 混合信任 id:3 照旧计入
	} {
		var sqlCounts int
		if err := stmt.QueryRow(tc.rule, tc.action).Scan(&sqlCounts); err != nil {
			t.Fatalf("query predicate for rule=%q action=%q: %v", tc.rule, tc.action, err)
		}
		if got := SecurityEventCountsAsAttack(tc.action, tc.rule); got != tc.wantAttack {
			t.Fatalf("CountsAsAttack(%q,%q)=%v, want %v（Go 判据漂移）", tc.action, tc.rule, got, tc.wantAttack)
		}
		if (sqlCounts == 1) != tc.wantAttack {
			t.Fatalf("rule=%q action=%q: SQL=%d, want attack=%v（SQL 谓词漂移）", tc.rule, tc.action, sqlCounts, tc.wantAttack)
		}
	}
}
