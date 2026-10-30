package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// 自动封禁成功写路径复核（与威胁/爬虫族同一写门 updateRunWriteGate）：
// 候选评估到 merge 写库之间的降级窗口——从节点 merge 会写主库名单。

// armPendingReloadHook 借「暂存重载强制收敛」回调注入角色翻转（执行序：
// flush 在候选评估/merge 之前——钩子里降级等价于 merge 前降级窗口）。
func armPendingReloadHook(t *testing.T, hook func()) {
	t.Helper()
	oldFn := autobanReloader
	autobanReloader = func() error { hook(); return nil }
	autobanMu.Lock()
	autobanReloadPending = true
	autobanMu.Unlock()
	t.Cleanup(func() { autobanReloader = oldFn })
}

func seedAutobanCandidate(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_ip_lists (name, entries, system) VALUES (?, '[]', 1)`, AutobanPresetListName); err != nil {
		t.Fatalf("seed preset list: %v", err)
	}
	// 2026-10-30 阶段 3 口径后非数值 token 不再计数，候选前置喂 CRS 形态 id。
	autobanObserveEvent("203.0.113.5", "blocked", "942100")
}

// Given 达标候选在册，merge 前节点已降级（暂存重载钩子里置 is_master=0）。
// When RunAutobanCycle 走到成功写路径。
// Then 返回 ErrTaskSkipped、名单零写入（从节点零写）。
func TestRunAutobanCycle_demoteBeforeMerge_zeroWrite(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	seedAutobanCandidate(t)
	armPendingReloadHook(t, func() {
		if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Errorf("demote: %v", err)
		}
	})
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"})

	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（降级中止不写库）", err)
	}
	if entries := presetEntries(t); len(entries) != 0 {
		t.Fatalf("降级窗口写库：entries=%+v, want 空（从节点零写）", entries)
	}
}

// Given 达标候选在册，merge 前角色读取失败（global_config 行缺失）。
// Then 返回普通错误（非跳过哨兵——不可判定≠降级）、名单零写入。
func TestRunAutobanCycle_roleUndecidableBeforeMerge_failsLoudly(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	seedAutobanCandidate(t)
	armPendingReloadHook(t, func() {
		if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
			t.Errorf("break role row: %v", err)
		}
	})

	err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"})

	if err == nil || errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want 普通错误（角色不可判定按失败落定，非降级哨兵）", err)
	}
	if entries := presetEntries(t); len(entries) != 0 {
		t.Fatalf("角色不可判定写库：entries=%+v, want 空", entries)
	}
}

// 禁用收尾容量挤出留痕（与 Run 轮同款）：kept 超限（带外写入形态）触发挤出时，
// 必须落 WARN 任务日志行（含挤出身份后缀）+ 系统审计行——零留痕会让挤出
// 静默发生（被挤者无处核对、无法判定是否需手动加白/调容量）。
func TestAutobanDisableFlush_capacityEvictionLeavesWarnAndAudit(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, false, 1, 5, "1h", "all", false)
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 2
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	// 带外超限形态：3 条自动条目（容量=2）→ 禁用收尾 merge 挤出 1 条。
	expires := "2026-10-14 11:00:00"
	seeded := []models.IPListEntry{
		{Value: "198.51.100.1", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:00:00", ExpiresAt: expires},
		{Value: "198.51.100.2", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:01:00", ExpiresAt: expires},
		{Value: "198.51.100.3", Remark: autobanEntryRemark, CreatedAt: "2026-10-14 09:02:00", ExpiresAt: expires},
	}
	raw, err := json.Marshal(seeded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_ip_lists (name, entries, system) VALUES (?, '[]', 1)`, AutobanPresetListName); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE name=? AND system=1`, string(raw), AutobanPresetListName); err != nil {
		t.Fatal(err)
	}

	AutobanDisableFlush()

	if entries := presetEntries(t); len(entries) != 2 {
		t.Fatalf("挤出后名单 %d 条, want 2（容量收敛本身必须生效）", len(entries))
	}
	logText := readTaskLog(t, "autoban")
	if !strings.Contains(logText, "容量收敛") {
		t.Fatalf("禁用收尾挤出缺 WARN 任务日志行:\n%s", logText)
	}
	// 挤出身份后缀（被挤者点名）：三条候选同前缀 .1/.2/.3，只有 .1（最早
	// 创建、稳定序首个）被挤——点名断言必须区分具体条值，否则前缀命中即绿。
	if !strings.Contains(logText, "挤出 IP 198.51.100.1") {
		t.Fatalf("WARN 行必须点名被挤条目 198.51.100.1（最早创建者）:\n%s", logText)
	}
	if strings.Contains(logText, "198.51.100.2") || strings.Contains(logText, "198.51.100.3") {
		t.Fatalf("未挤出条目不得出现在容量收敛身份后缀:\n%s", logText)
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='容量收敛' AND detail LIKE '%禁用收尾%'`).Scan(&auditCount); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("容量收敛审计行=%d, want 1（禁用收尾挤出必须留系统审计）", auditCount)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='容量收敛'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, fmt.Sprintf("上限 %d", 2)) {
		t.Fatalf("审计明细缺容量上限口径: %q", detail)
	}
}
