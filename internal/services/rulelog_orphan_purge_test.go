package services

// 规则访问日志的周期兜底：规则删除/导入差集/集群差集三个事件型删除入口任一
// 失败即永久残留（单规则含轮转副本上限约 6×caddy_log_size_mb），故 log-cleanup
// 按「存活规则清单」求差兜底，与 metrics 孤儿清理同构。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// seedRuleLogFiles 在规则日志目录写入活动文件 + 三形态轮转副本。
func seedRuleLogFiles(t *testing.T, dir, component string) []string {
	t.Helper()
	names := []string{
		component + ".log",
		component + ".log.1",
		component + "-2026-01-02T03-04-05.123-size.log.gz",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("seed rule log %s: %v", name, err)
		}
	}
	return names
}

// Given 存活规则与已删除规则各有一族日志文件，另有一个外来文件。
// When 执行孤儿规则日志清理。
// Then 只删已删除规则的活动文件与全部轮转副本；存活规则与外来文件保留。
func TestPurgeOrphanRuleLogs_deletesRemovedRuleKeepsLiveAndForeign(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_live','live','http',18093,1)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	liveFiles := seedRuleLogFiles(t, dir, "lb_live")
	orphanFiles := seedRuleLogFiles(t, dir, "lb_gone")
	foreign := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(foreign, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := PurgeOrphanRuleLogs(context.Background())

	if result.ScanError != "" {
		t.Fatalf("ScanError=%q, want 空", result.ScanError)
	}
	if len(result.Purged) != 1 || result.Purged[0] != "lb_gone" {
		t.Fatalf("Purged=%v, want [lb_gone]", result.Purged)
	}
	for _, name := range orphanFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("孤儿规则日志 %s 未删除（err=%v）", name, err)
		}
	}
	for _, name := range liveFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("存活规则日志 %s 被误删: %v", name, err)
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("外来文件被误删: %v", err)
	}
}

// Given 存活规则清单读不出来（lb_rules 不可读）。When 执行孤儿清理。
// Then 一个文件都不删，失败进结果错误面——无法区分「规则已删除」与「清单读
// 不出来」时删除会清掉存活规则的日志。
func TestPurgeOrphanRuleLogs_survivesRuleListReadFailureWithoutDeleting(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	names := seedRuleLogFiles(t, dir, "lb_any")
	if _, err := database.Exec(`ALTER TABLE lb_rules RENAME TO lb_rules_unreadable`); err != nil {
		t.Fatalf("注入清单读失败: %v", err)
	}

	result := PurgeOrphanRuleLogs(context.Background())

	if result.ScanError == "" {
		t.Fatal("存活规则清单读失败必须进 ScanError（不得静默当作无孤儿）")
	}
	if len(result.Purged) != 0 {
		t.Fatalf("清单不可读时不得删除任何文件，实际清理 %v", result.Purged)
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("清单读失败时文件 %s 被误删: %v", name, err)
		}
	}
	if err := (RuntimeCleanupResult{RuleLogs: result}).Err(); err == nil {
		t.Fatal("扫描失败必须进 log-cleanup 错误面（任务落 failed）")
	}
}

// Given 扫描完成后规则日志目录路径被普通文件占据（删除路径返回 ENOTDIR）。
// When 执行孤儿清理。Then 失败计数进结果与错误面，摘要不得称完成。
func TestPurgeOrphanRuleLogs_removeFailureSurfaces(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	names := seedRuleLogFiles(t, dir, "lb_stuck")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_kept','kept','http',18094,1)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 复用既有删除前测试缝，确保目录扫描成功后才注入路径故障；错误
	// 因此必来自 RemoveRuleLogFiles 的 ENOTDIR，而非 ScanError，root 亦有效。
	ruleLogOrphanPurgeBeforeRemoveForTest = func() { ruleLogDir = blocked }
	t.Cleanup(func() { ruleLogOrphanPurgeBeforeRemoveForTest = nil })

	result := PurgeOrphanRuleLogs(context.Background())

	if result.ScanError != "" {
		t.Fatalf("故障必须发生在删除阶段而非扫描阶段: %s", result.ScanError)
	}
	if result.RemoveFailed != 1 {
		t.Fatalf("RemoveFailed=%d, want 1（Purged=%v）", result.RemoveFailed, result.Purged)
	}
	if len(result.Purged) != 0 {
		t.Fatalf("删除失败不得计入已清理：%v", result.Purged)
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("删除失败后原文件 %s 必须保留: %v", name, err)
		}
	}
	res := RuntimeCleanupResult{RuleLogs: result}
	if err := res.Err(); err == nil {
		t.Fatal("删除失败必须进 log-cleanup 错误面（任务落 failed）")
	}
	if summary := res.RuleLogs.Summary(); !containsAll(summary, "删除失败", "1 个") {
		t.Fatalf("摘要未披露删除失败：%s", summary)
	}
}

// 库未初始化时不得在 nil *sql.DB 上查询 panic（与 PurgeOrphanMetricsHistory
// 同口径）；语义=不删除并把跳过原因写进错误面（静默零值会让「本轮清理全停」
// 与「无事可做」同形，关停竞态/嵌入形态下排障无从区分）。
func TestPurgeOrphanRuleLogs_nilDBSkipsWithoutDeleting(t *testing.T) {
	oldDB, oldMetrics, oldAudit := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	db.DB, db.MetricsDB, db.AuditDB = nil, nil, nil
	db.SetDB(nil)
	t.Cleanup(func() {
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetrics, oldAudit
		db.SetDB(oldCurrent)
	})

	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	names := seedRuleLogFiles(t, dir, "lb_nodb")

	result := PurgeOrphanRuleLogs(context.Background())
	if result.ScanError == "" {
		t.Fatalf("nil 库必须把跳过原因写进 ScanError（清理不得静默跳过），实际 %+v", result)
	}
	if len(result.Purged) != 0 || result.RemoveFailed != 0 {
		t.Fatalf("nil 库必须不删除任何文件，实际 %+v", result)
	}
	if err := result.purgedErr(); err == nil {
		t.Fatal("nil 库跳过必须进错误面（任务终态可见）")
	}
	if err := (RuntimeCleanupResult{RuleLogs: result}).Err(); err == nil {
		t.Fatal("RuntimeCleanupResult.Err() 必须携带 nil 库跳过原因")
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("nil 库时文件 %s 被误删: %v", name, err)
		}
	}
}

// 任务取消后不得继续删除：已处理条目保留计数，未处理条目计入 Remaining。
func TestPurgeOrphanRuleLogs_honorsContextCancellation(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_kept','kept','http',18095,1)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	first := seedRuleLogFiles(t, dir, "lb_orphan_a")
	second := seedRuleLogFiles(t, dir, "lb_orphan_b")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ruleLogOrphanPurgeBeforeRemoveForTest = func() { cancel() }
	t.Cleanup(func() { ruleLogOrphanPurgeBeforeRemoveForTest = nil })

	result := PurgeOrphanRuleLogs(ctx)
	if result.ScanError != "" {
		t.Fatalf("取消不是扫描失败: %q", result.ScanError)
	}
	if len(result.Purged) != 0 {
		t.Fatalf("已取消的清理不得删除任何规则，实际 %v", result.Purged)
	}
	if result.Remaining != 2 {
		t.Fatalf("Remaining=%d, want 2（未处理条目交下轮）", result.Remaining)
	}
	for _, name := range append(append([]string{}, first...), second...) {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("取消后文件 %s 被误删: %v", name, err)
		}
	}
}

// 规则日志文件名还原：活动文件、移位副本、timberjack 时间戳副本与编码 ID
// 三形态单源；非本族文件返回 false（不得清理）。
func TestRuleLogComponentOf_recognizesLogFamilyShapes(t *testing.T) {
	cases := []struct {
		name      string
		component string
		ok        bool
	}{
		{name: "lb_abc.log", component: "lb_abc", ok: true},
		{name: "lb_abc.log.1", component: "lb_abc", ok: true},
		{name: "lb_abc.log.12.gz", component: "lb_abc", ok: true},
		{name: "lb_abc-2026-01-02T03-04-05.123-size.log", component: "lb_abc", ok: true},
		{name: "lb_abc-2026-01-02T03-04-05-size_1.log.gz", component: "lb_abc", ok: true},
		{name: "lb_abc-123.log", component: "lb_abc-123", ok: true},
		{name: "%6c622e646f74.log", component: "%6c622e646f74", ok: true},
		{name: "notes.txt", component: "", ok: false},
		{name: "lb_abc.log.tmp", component: "", ok: false},
	}
	for _, tc := range cases {
		got, ok := ruleLogComponentOf(tc.name)
		if ok != tc.ok || got != tc.component {
			t.Fatalf("ruleLogComponentOf(%q)=(%q,%v), want (%q,%v)", tc.name, got, ok, tc.component, tc.ok)
		}
	}
	if got := decodeFileComponent("%6c622e646f74"); got != "lb.dot" {
		t.Fatalf("编码主体还原=%q, want lb.dot", got)
	}
}

// containsAll 报告 s 是否包含全部子串（测试断言用）。
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// 构造形态的 caddy_id（以完整时间戳 + reason 结尾，字母表内、备份导入可达）
// 让它的活动文件在词法上属于前缀规则的轮转副本族。孤儿判定必须以「完整主体
// 是否为存活规则」优先反解，否则前缀规则已删除时该存活规则的日志被当孤儿清掉。
func TestPurgeOrphanRuleLogs_keepsLiveRuleWhoseIDLooksLikeRotationCopy(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))

	const lookalikeID = "lb_xyz-20260102T03-04-05-size"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES (?,?,?,?,1)`, lookalikeID, "lookalike", "http", 18097); err != nil {
		t.Fatalf("seed lookalike rule: %v", err)
	}
	liveFile := lookalikeID + ".log"
	if err := os.WriteFile(filepath.Join(dir, liveFile), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("seed %s: %v", liveFile, err)
	}

	result := PurgeOrphanRuleLogs(context.Background())

	if result.ScanError != "" {
		t.Fatalf("ScanError=%q, want 空", result.ScanError)
	}
	if len(result.Purged) != 0 {
		t.Fatalf("Purged=%v, want 空（存活规则的活文件不得判孤儿）", result.Purged)
	}
	if _, err := os.Stat(filepath.Join(dir, liveFile)); err != nil {
		t.Fatalf("存活规则 %s 的活动日志被孤儿清理误删: %v", lookalikeID, err)
	}
}
