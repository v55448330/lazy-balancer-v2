package services

// 排程读取族的两个单源 helper：
//  ① scheduleRead 收敛「读两列 + 归一 + 读失败/恢复留痕」——此前五处读取各写
//     一份，事务内变体（versionTableScheduleTx）漏了留痕，写事务里排程读失败
//     零信号：自动更新静默停摆后没人知道为什么。
//  ② slotAssign 收敛「严格算槽 → 拼 next_update 赋值片段与参数」——成功门
//     trigger 出现两次、推进门一次，六个同族函数此前各自拼 []any。

import (
	"errors"
	"strings"
	"testing"
)

// 事务内读取失败必须留痕（首报一次，恢复补一条）——与事务外读取同口径。
func TestVersionTableScheduleTx_logsReadFailureOnceAndRecovers(t *testing.T) {
	database := setupIsolatedDB(t)
	isolateMetricsState(t)
	ResetLogStateTransitionForTest("schedule-read-security_crs_version")
	out := captureLogf(t)

	readInTx := func(wantErr bool) {
		t.Helper()
		tx, err := database.Begin()
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		_, _, readErr := versionTableScheduleTx(tx, "security_crs_version")
		if wantErr && readErr == nil {
			t.Fatal("表不可读时必须上抛错误（写路径不兜默认排程）")
		}
		if !wantErr && readErr != nil {
			t.Fatalf("表恢复后读取应成功: %v", readErr)
		}
	}

	// 归一读取需要真实行；失败态用改名制造（表不可读）。
	if _, err := database.Exec("INSERT INTO security_crs_version (id,version) VALUES (1,'v4.28.0')"); err != nil {
		t.Fatalf("seed version row: %v", err)
	}
	if _, err := database.Exec("ALTER TABLE security_crs_version RENAME TO security_crs_version_bak"); err != nil {
		t.Fatalf("inject read failure: %v", err)
	}
	readInTx(true)
	readInTx(true)
	if got := strings.Count(out.String(), "读取配置失败（schedule-read-security_crs_version）"); got != 1 {
		t.Fatalf("事务内连续读失败留痕次数=%d, want 1（状态转换去重）: %q", got, out.String())
	}

	if _, err := database.Exec("ALTER TABLE security_crs_version_bak RENAME TO security_crs_version"); err != nil {
		t.Fatalf("restore table: %v", err)
	}
	out.Reset()
	readInTx(false)
	if !strings.Contains(out.String(), "读取配置已恢复（schedule-read-security_crs_version）") {
		t.Fatalf("事务内读取恢复后必须补一条恢复留痕: %q", out.String())
	}
}

func TestSlotAssign_shapesArgsAndFailsSafe(t *testing.T) {
	const slotValue = "2026-10-30 04:00:00"
	succeed := func() (string, error) { return slotValue, nil }

	// 成功门：gate SQL 里 trigger 判据出现两次（auto/manual）+ 槽值。
	sqlText, args, err := slotAssign("GATE_SQL", "auto", 2, succeed)
	if err != nil {
		t.Fatalf("success gate: %v", err)
	}
	if sqlText != "GATE_SQL" {
		t.Fatalf("赋值片段=%q, want 原样返回 gate SQL", sqlText)
	}
	if len(args) != 3 || args[0] != "auto" || args[1] != "auto" || args[2] != slotValue {
		t.Fatalf("成功门参数=%#v, want [auto auto %s]", args, slotValue)
	}

	// 推进门：只判一次 trigger。
	sqlText, args, err = slotAssign("ADVANCE_SQL", "manual", 1, succeed)
	if err != nil {
		t.Fatalf("advance gate: %v", err)
	}
	if sqlText != "ADVANCE_SQL" || len(args) != 2 || args[0] != "manual" || args[1] != slotValue {
		t.Fatalf("推进门=%q %#v, want ADVANCE_SQL [manual %s]", sqlText, args, slotValue)
	}

	// 无 trigger 判据的门（版本表推进门只判 auto_update）：参数只有槽值。
	sqlText, args, err = slotAssign("ADVANCE_SQL", "", 0, succeed)
	if err != nil {
		t.Fatalf("no-trigger gate: %v", err)
	}
	if sqlText != "ADVANCE_SQL" || len(args) != 1 || args[0] != slotValue {
		t.Fatalf("无 trigger 门=%q %#v, want ADVANCE_SQL [%s]", sqlText, args, slotValue)
	}

	// 算槽失败：返回 no-op 片段 + 错误（预约保持旧值，绝不写空槽）。
	fail := func() (string, error) { return "", errors.New("schedule unavailable") }
	sqlText, args, err = slotAssign("GATE_SQL", "auto", 2, fail)
	if err == nil {
		t.Fatal("算槽失败必须上抛错误")
	}
	if sqlText != noopSlotAssignSQL || args != nil {
		t.Fatalf("算槽失败必须返回 no-op 片段且无参数: %q %#v", sqlText, args)
	}
}
