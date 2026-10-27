package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 审计日志目录必须在首次 ApplyConfigOnStartup 前
// 保证存在——coraza v3.7.0 NewWAF→serialWriter.Init OpenFile 不建父目录,目录
// 缺失=Provision 致命=/load 拒收。导出 helper 供 main.go 启动早期调用。
func TestEnsureWafAuditDir_createsDirectory(t *testing.T) {
	// Given: 不存在的嵌套目录
	dir := filepath.Join(t.TempDir(), "logs", "waf-audit")
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldPath })

	// When
	if err := EnsureWafAuditDir(); err != nil {
		t.Fatalf("EnsureWafAuditDir: %v", err)
	}

	// Then: 目录已创建
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("dir %s not created: %v", dir, err)
	}
	// 幂等:重复调用不报错
	if err := EnsureWafAuditDir(); err != nil {
		t.Fatalf("EnsureWafAuditDir second call: %v", err)
	}
}

// 待补采标记损坏必须与「标记读错误」同口径中止本轮。
// 旧实现清除损坏标记后返回 (nil,nil)——恰好等于「无标记」，调用方继续
// .1→.2 移位，该轮转窗口的事件再无补采依据（上轮补采失败 + 标记损坏的双故障
// 下安全事件永久丢失），与同函数注释「避免被静默当作无标记后继续轮转」相反。
func TestRotateAuditLog_corruptPendingMarkerDefersRotation(t *testing.T) {
	// Given：活文件已过阈值、存在 .1 归档、待补采标记损坏（半写 JSON）
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldSizeBytes := auditLogPath, auditLogSizeBytes
	auditLogPath = logPath
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() { auditLogPath, auditLogSizeBytes = oldLogPath, oldSizeBytes })
	if err := os.WriteFile(logPath, []byte("live-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("pending-archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := securityEventsPendingDeltaPath()
	if err := os.WriteFile(marker, []byte(`{"path": "broken`), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	_, err := rotateAuditLogIfNeeded(context.Background())

	// Then：本轮中止并返回错误（下轮重试），不得当作无标记继续轮转
	if err == nil {
		t.Fatal("标记损坏必须让轮转中止并返回错误（旧实现清除后返回 nil,nil）")
	}
	for path, want := range map[string]string{
		logPath:        "live-content",
		logPath + ".1": "pending-archive",
	} {
		got, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read preserved file %s: %v", path, rerr)
		}
		if string(got) != want {
			t.Fatalf("%s=%q, want %q（补采责任未知时不得移位/覆盖归档）", path, got, want)
		}
	}
	if _, serr := os.Stat(logPath + ".2"); !os.IsNotExist(serr) {
		t.Fatalf(".1 不得移入 .2，stat err=%v", serr)
	}
	// 标记保留在盘上：人工可诊断/恢复，下一轮仍按失败中止（不静默丢补采责任）
	if _, serr := os.Stat(marker); serr != nil {
		t.Fatalf("损坏标记必须保留（不得静默清除）: %v", serr)
	}
}

// 轮转必须先复制到暂存名 .1.new、成功后才移位归档：持续复制失败（磁盘满/
// 只读挂载/IO 错误）不得改变归档代际。旧序先 .4→.5 … .1→.2 再复制，每 2s
// tick 蚕食一代——.1..5 全存在时约 4 个 tick 即丢掉 4 代审计证据。
func TestRotateAuditLog_copyFailureKeepsArchiveGenerations(t *testing.T) {
	// Given：活文件超阈 + 5 代归档全部存在（真实库使复制前闸门可追平尾部）
	initServicesDB(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, filepath.Join(dir, "security_events.offset")
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy
	})
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", logPath, i), []byte(fmt.Sprintf("gen-%d", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	auditLogCopyFile = func(string, string) error { return errors.New("injected copy failure") }

	// When：连续 5 个 tick 都复制失败
	for tick := 1; tick <= 5; tick++ {
		if _, err := rotateAuditLogIfNeeded(context.Background()); err == nil {
			t.Fatalf("第 %d 个 tick：copy 失败必须返回错误", tick)
		}
	}

	// Then：归档代际与内容原样保留，活文件未截断，暂存不留残
	for i := 1; i <= 5; i++ {
		got, err := os.ReadFile(fmt.Sprintf("%s.%d", logPath, i))
		if err != nil {
			t.Fatalf("复制失败后归档 .%d 丢失: %v", i, err)
		}
		if want := fmt.Sprintf("gen-%d", i); string(got) != want {
			t.Fatalf(".%d=%q, want %q（复制失败不得移位/覆盖归档）", i, got, want)
		}
	}
	if _, err := os.Stat(logPath + ".6"); !os.IsNotExist(err) {
		t.Fatalf(".5 不得移位为 .6, stat err=%v", err)
	}
	if _, err := os.Stat(logPath + ".1.new"); !os.IsNotExist(err) {
		t.Fatalf("暂存文件必须清理, stat err=%v", err)
	}
	if got, err := os.ReadFile(logPath); err != nil || string(got) != securityEventsFixtureBlocked+"\n" {
		t.Fatalf("活文件被改动: %q err=%v", got, err)
	}
}

// 成功路径：当前日志先落暂存，随后归档移位、暂存提升为 .1——新 .1 是新归档，
// 旧 .1 让位到 .2，暂存不留残。
func TestRotateAuditLog_promotesStagedArchiveAfterShift(t *testing.T) {
	// 真实库：归档补采依赖安全事件库句柄，依赖缺失时轮转按「补采未完成」
	// 留痕（pending 标记保留），本用例钉的是完整成功路径。
	initServicesDB(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, filepath.Join(dir, "security_events.offset")
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy
	})
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("gen-1"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	if _, err := rotateAuditLogIfNeeded(context.Background()); err != nil {
		t.Fatalf("正常轮转不应报错: %v", err)
	}

	// Then
	if got, err := os.ReadFile(logPath + ".1"); err != nil || string(got) != securityEventsFixtureBlocked+"\n" {
		t.Fatalf(".1 必须是本轮新归档: %q err=%v", got, err)
	}
	if got, err := os.ReadFile(logPath + ".2"); err != nil || string(got) != "gen-1" {
		t.Fatalf("旧 .1 必须让位到 .2: %q err=%v", got, err)
	}
	if _, err := os.Stat(logPath + ".1.new"); !os.IsNotExist(err) {
		t.Fatalf("暂存文件必须已被提升（不得留残）, stat err=%v", err)
	}
	if info, err := os.Stat(logPath); err != nil || info.Size() != 0 {
		t.Fatalf("活文件必须已截断: size=%v err=%v", info, err)
	}
}

// 归档代检查的 stat 只允许把 NotExist 视为「该代不存在」：权限/IO 错误下
// 归档可能仍存在，继续 shift/promote 会覆盖仍有效的 .1（丢一代审计证据）。
// 用自指符号链接注入 ELOOP（stat 失败但不是缺失）。
func TestRotateAuditLog_statErrorAbortsBeforeOverwritingArchives(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, filepath.Join(dir, "security_events.offset")
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	resetPendingDeltaCorruptStreakForTest()
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("archive-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 自指符号链接：os.Stat 返回 ELOOP（非 NotExist）。
	if err := os.Symlink(logPath+".3", logPath+".3"); err != nil {
		t.Fatal(err)
	}

	_, err := rotateAuditLogIfNeeded(context.Background())
	if err == nil {
		t.Fatal("stat 非 NotExist 错误必须中止本轮并返回错误")
	}
	got, rerr := os.ReadFile(logPath + ".1")
	if rerr != nil || string(got) != "archive-one" {
		t.Fatalf(".1=%q err=%v，stat 异常时不得覆盖仍在的归档", got, rerr)
	}
	if _, serr := os.Stat(logPath + ".1.new"); !os.IsNotExist(serr) {
		t.Fatalf("中止必须清理暂存归档 .1.new，stat err=%v", serr)
	}
}

// .1 未能让位时中止：.2 为非空目录使 .1→.2 的 rename 失败（上级链 .2/.3/.4/.5
// 同样被占住，逐级 shift 全部失败），本轮必须中止且保留 .1 与 .2 现场。
func TestRotateAuditLog_shiftFailureForFirstGenerationAbortsAndKeepsArchives(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, filepath.Join(dir, "security_events.offset")
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	resetPendingDeltaCorruptStreakForTest()
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("archive-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, gen := range []string{".2", ".3", ".4", ".5"} {
		p := logPath + gen
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "keep"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	_, err := rotateAuditLogIfNeeded(context.Background())
	if err == nil {
		t.Fatal(".1 未能让位必须中止本轮并返回错误")
	}
	got, rerr := os.ReadFile(logPath + ".1")
	if rerr != nil || string(got) != "archive-one" {
		t.Fatalf(".1=%q err=%v，中止后必须保留上一代归档", got, rerr)
	}
	if st, serr := os.Stat(logPath + ".2"); serr != nil || !st.IsDir() {
		t.Fatalf(".2 现场必须保留, stat=%v err=%v", st, serr)
	}
	if _, serr := os.Stat(logPath + ".1.new"); !os.IsNotExist(serr) {
		t.Fatalf("中止必须清理暂存归档 .1.new，stat err=%v", serr)
	}
}

// 损坏的待补采标记在连续 N 轮不可解析后隔离为 .corrupt-<ts> 并继续轮转——
// 单轮仍 fail-closed 保留现场，否则 audit.log 永久不轮转（无界增长）。
func TestRotateAuditLog_corruptPendingMarkerQuarantinedAfterThreshold(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, filepath.Join(dir, "security_events.offset")
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	resetPendingDeltaCorruptStreakForTest()
	t.Cleanup(resetPendingDeltaCorruptStreakForTest)

	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := securityEventsPendingDeltaPath()
	if err := os.WriteFile(marker, []byte(`{"path": "broken`), 0o644); err != nil {
		t.Fatal(err)
	}

	for round := 1; round < pendingDeltaCorruptQuarantineRounds; round++ {
		if _, err := rotateAuditLogIfNeeded(context.Background()); err == nil {
			t.Fatalf("第 %d 轮损坏标记必须 fail-closed 中止", round)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("第 %d 轮不得提前隔离标记: %v", round, err)
		}
	}
	// 第 N 轮：损坏标记被隔离，轮转继续推进（后续偏移写入可能因测试环境目录
	// 只读失败——隔离动作本身必须已发生，归档必须已生成）。
	_, err := rotateAuditLogIfNeeded(context.Background())
	quarantined, _ := filepath.Glob(marker + ".corrupt-*")
	if len(quarantined) != 1 {
		t.Fatalf("隔离文件=%v, want 恰一个 .corrupt-<ts>（连续 %d 轮损坏后必须隔离, rotate err=%v）", quarantined, pendingDeltaCorruptQuarantineRounds, err)
	}
	// 本轮轮转可能重新写出**合法**的待补采标记（补采依赖不可用时按设计保留，
	// 供下轮重试）——若存在，其载荷必须可解析且指向归档，不得残留损坏字节。
	if raw, rerr := os.ReadFile(marker); rerr == nil {
		var pending securityEventsPendingDelta
		if jerr := json.Unmarshal(raw, &pending); jerr != nil || pending.Path == "" {
			t.Fatalf("轮转后残留的标记必须是合法待补采载荷: %q (err=%v)", raw, jerr)
		}
	}
	if _, serr := os.Stat(logPath + ".1"); serr != nil {
		t.Fatalf("隔离后轮转必须继续（.1 归档应存在）: %v (rotate err=%v)", serr, err)
	}
}

// 补采依赖（安全事件库句柄）不可用时，补采是 no-op——不得把「未补采」当
// 「补采成功」删除 pending 安全网：该轮转窗口的事件只在 .1，标记一旦删除即
// 永久丢失。依赖恢复后下一轮重试补采并删除标记。
func TestRotateAuditLog_keepsPendingMarkerWhenIngestDepsUnavailable(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	oldLogPath, oldOffsetPath := auditLogPath, securityEventsOffsetPath
	auditLogPath = filepath.Join(dir, "audit.log")
	securityEventsOffsetPath = filepath.Join(dir, "security_events.offset")
	t.Cleanup(func() { auditLogPath, securityEventsOffsetPath = oldLogPath, oldOffsetPath })
	resetPendingDeltaCorruptStreakForTest()
	t.Cleanup(resetPendingDeltaCorruptStreakForTest)

	// Given：.1 归档 + 指向它的待补采标记
	archive := auditLogPath + ".1"
	if err := os.WriteFile(archive, []byte(`{"transaction_id":"a"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := securityEventsWritePendingDelta(securityEventsPendingDelta{Path: archive, Offset: 0, Size: 25}); err != nil {
		t.Fatal(err)
	}
	marker := securityEventsPendingDeltaPath()
	// 指标库句柄缺失＝补采依赖不可用（补采函数此时返回 0,nil）
	readyMetrics := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = readyMetrics })

	// When
	if _, err := rotateAuditLogIfNeeded(context.Background()); err == nil {
		t.Fatal("补采未完成必须返回错误（不得当作成功继续轮转）")
	}

	// Then：安全网保留
	if _, serr := os.Stat(marker); serr != nil {
		t.Fatalf("补采未完成时 pending 标记不得删除: %v", serr)
	}

	// When：依赖恢复后再跑一轮
	db.MetricsDB = readyMetrics
	if _, err := rotateAuditLogIfNeeded(context.Background()); err != nil {
		t.Fatalf("依赖恢复后补采应成功: %v", err)
	}

	// Then：补采完成，标记删除
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatalf("补采成功后标记必须删除, stat err=%v", serr)
	}
}

// 持续写入下轮转仍须截断：截断判据是「摄取到达偏移」，不是本轮补采前的文件
// 大小。审计日志每事务追写，copy 之后与每次 stat→ingest 窗口内随时有新字节；
// 旧实现拿每轮补采前的 stat 与全部补采后的 stat 比较，只要窗口内到达一条
// 事件条件即恒真——每 2s 全量复制并移位归档却永不 truncate，活文件无界增长、
// 磁盘放大 ~6×，且 rotErr 恒 nil、健康位与任务日志零痕迹。
func TestRotateAuditLog_continuousWritesStillTruncate(t *testing.T) {
	// Given：小阈值 + 已超阈的活文件 + 可用的安全事件库
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	oldCopyFile, oldIngestHook := auditLogCopyFile, auditLogRotationBeforeTailIngest
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
		auditLogCopyFile, auditLogRotationBeforeTailIngest = oldCopyFile, oldIngestHook
	})

	seq := 0
	appendDoc := func() {
		seq++
		doc := strings.Replace(securityEventsFixtureClean, "tx-clean-1", fmt.Sprintf("tx-stream-%d", seq), 1) + "\n"
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(doc); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	docLen := int64(len(securityEventsFixtureClean) + 1)
	for range 4 {
		appendDoc()
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Coraza 在 copy 完成后追写（照旧必须在 .1 之外），以及在本轮 stat→补采
	// 窗口内追写——两个窗口正是持续写入必然命中的位置。
	auditLogCopyFile = func(src, dst string) error {
		if err := copyAuditLogTo(src, dst); err != nil {
			return err
		}
		appendDoc()
		return nil
	}
	ingestWindowAppends := 0
	auditLogRotationBeforeTailIngest = func() {
		appendDoc()
		ingestWindowAppends++
	}

	// When：连续 30 个 tick，每 tick 活文件都有新写入
	const ticks = 30
	truncated := 0
	var archiveFinal int64
	for tick := range ticks {
		appendDoc()
		if _, err := rotateAuditLogIfNeeded(context.Background()); err != nil {
			t.Fatalf("tick %d: %v（持续写入不得让轮转报错/停摆）", tick, err)
		}
		live, err := os.Stat(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if live.Size() == 0 {
			truncated++
		}
		if archiveInfo, aerr := os.Stat(logPath + ".1"); aerr == nil {
			archiveFinal = archiveInfo.Size()
		}
	}

	// Then：活文件确实被截断；.1 尺寸与单次轮转窗口同量级、不随 tick 累积
	if truncated == 0 {
		t.Fatal("30 个 tick 内活文件从未被截断：持续写入把「已摄取」误判成「仍有未摄取字节」")
	}
	if want := 8 * docLen; archiveFinal > want {
		t.Fatalf(".1 size=%d, want ≤%d（归档不得随 tick 数累积增长）", archiveFinal, want)
	}
	// 截断不得丢事件：轮转前与 copy 后的追写每 tick 各一条，补采窗口内的追写
	// 按实际轮数计——全部必须已入库（窗口内追写若被误判为「未摄取」而残留，
	// 下一轮拷贝会重复解析，行数随即偏离）。
	var rows int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE transaction_id LIKE 'tx-stream-%'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if want := 4 + ticks*2 + ingestWindowAppends; rows != want {
		t.Fatalf("rows=%d, want %d（截断前必须已摄取窗口内追写）", rows, want)
	}
}

// TestPendingDeltaArchiveReplaced_sizeGuard 标记里的归档大小必须是活字段：
// 当前 .1 小于记录窗口说明归档被外部替换/截短，旧 Offset 补采已无意义。
func TestPendingDeltaArchiveReplaced_sizeGuard(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "audit.log.1")
	if err := os.WriteFile(archive, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}

	if pendingDeltaArchiveReplaced(&securityEventsPendingDelta{Path: archive, Offset: 0, Size: 5}) {
		t.Fatal("同尺寸归档不得判为被替换")
	}
	if !pendingDeltaArchiveReplaced(&securityEventsPendingDelta{Path: archive, Offset: 4, Size: 9}) {
		t.Fatal("归档小于记录窗口必须判为被替换（旧偏移无意义）")
	}
	if pendingDeltaArchiveReplaced(&securityEventsPendingDelta{Path: archive, Offset: 4}) {
		t.Fatal("Size=0 为旧版标记，不做判定")
	}
	if pendingDeltaArchiveReplaced(nil) {
		t.Fatal("nil 标记不得判为被替换")
	}
}

// 截断推迟必须返回可识别哨兵：此前该分支返回 rotErr（通常 nil），调用方无法
// 区分「本轮无需轮转」与「归档已复制但活文件未截断、每 2s 全量复制」——健康位
// 与 log-cleanup 摘要都会把后者当成功。
func TestRotateAuditLog_truncateDeferredReturnsSentinel(t *testing.T) {
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, filepath.Join(dir, "security_events.offset")
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy
	})

	// 一条合法审计文档；复制完成后追写超阈空白（模拟 Coraza 在 copy 之后持续
	// 写入）：归档已就位，但「摄取到达偏移」停在文档末尾、剩余字节超过空白
	// 豁免上限 → 本轮不截断（延迟，下次 tick 重试）。
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureClean+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	auditLogCopyFile = func(src, dst string) error {
		if err := copyAuditLogTo(src, dst); err != nil {
			return err
		}
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(bytes.Repeat([]byte("\n"), 2<<20))
		return err
	}

	// When
	_, err := rotateAuditLogIfNeeded(context.Background())

	// Then
	if !errors.Is(err, errAuditRotationDeferred) {
		t.Fatalf("err=%v, want errAuditRotationDeferred（截断推迟必须与「无需轮转」区分）", err)
	}
	live, statErr := os.Stat(logPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if live.Size() == 0 {
		t.Fatal("截断推迟分支不得截断活文件（尾部事件尚未确认摄取）")
	}
	if _, aerr := os.Stat(logPath + ".1"); aerr != nil {
		t.Fatalf("归档应已就位（副本语义未变）: %v", aerr)
	}
}

// 持续写入下的推迟路径不得复制：复制前闸门不通过时每 tick 只做增量摄取，
// 不复制、不移位、不改归档代际，告警同消息 60s 内只放行一条——旧实现每 2s
// 全量复制 + 移位归档却永不 truncate（磁盘放大 ~6×、活文件无界增长）。流量
// 停歇（尾部写完后）同一轮转必须一次成功：归档=轮转前全部字节、活文件截断、
// 两笔事务均入库（零丢失）。
func TestRotateAuditLog_deferredDoesNotCopyOrShift(t *testing.T) {
	initServicesDB(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	// 告警限流按固定时钟计数：20 轮推迟只允许一条 warn。
	oldClock := auditFailureLogClock
	auditFailureLogClock = func() time.Time { return time.Unix(1790000000, 0) }
	auditFailureLogMu.Lock()
	oldTimes := auditFailureLogTimes
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	var buf syncBuffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = oldTimes
		auditFailureLogMu.Unlock()
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy
	})

	// 活文件：完整事务 A（tick 已摄取）+ 写者正在分多次 write 落盘的事务（截断点
	// 深入 uri 字符串内部，尾部永远差最后一段）——持续写入下截断判据不成立的
	// 确定性形态。
	fixtureT := securityEventsFixtureClean
	split := strings.Index(fixtureT, `"uri": "/upload`)
	if split <= 0 {
		t.Fatalf("fixture split point not found")
	}
	split += len(`"uri": "/upload`)
	head, tail := fixtureT[:split], fixtureT[split:]
	chunk := strings.Repeat("a", 64<<10)
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"+head), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	copies := 0
	auditLogCopyFile = func(src, dst string) error {
		copies++
		if err := copyAuditLogTo(src, dst); err != nil {
			return err
		}
		// copy 之后写者继续写下一段：尾部保持不可摄取（旧实现因此每 tick 全量
		// 复制却永不 truncate）。
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(chunk)
		return err
	}
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// When：20 个 tick 尾部都追不平
	const ticks = 20
	for range ticks {
		if _, rerr := rotateAuditLogIfNeeded(context.Background()); !errors.Is(rerr, errAuditRotationDeferred) {
			t.Fatalf("尾部未追平必须返回 deferred 哨兵, err=%v", rerr)
		}
	}

	// Then：零复制、归档代际不动、活文件原样；告警一条；已摄取事件不丢。
	if copies != 0 {
		t.Fatalf("推迟路径不得复制（磁盘放大）: copies=%d over %d ticks", copies, ticks)
	}
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("推迟路径不得改动活文件（零丢失前提）")
	}
	if _, serr := os.Stat(logPath + ".1.new"); !os.IsNotExist(serr) {
		t.Fatalf("推迟路径不得留暂存归档, stat err=%v", serr)
	}
	if _, serr := os.Stat(logPath + ".1"); !os.IsNotExist(serr) {
		t.Fatalf("推迟路径不得生成/移位归档, stat err=%v", serr)
	}
	if got := strings.Count(buf.String(), "live tail not fully ingested before copy"); got != 1 {
		t.Fatalf("推迟告警条数=%d, want 1（同消息 60s 窗口内不得每 tick 刷一条）", got)
	}
	var rows int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE transaction_id='tx-blocked-1'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d, want 1（推迟期间已摄取事件不得丢失）", rows)
	}

	// When：流量停歇（尾部补完）后同一轮转
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(tail + "\n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// 写者收尾：后续不再追写（复制钩子恢复真实行为，不再制造 churn）。
	auditLogCopyFile = func(src, dst string) error {
		copies++
		return copyAuditLogTo(src, dst)
	}
	if _, rerr := rotateAuditLogIfNeeded(context.Background()); rerr != nil {
		t.Fatalf("尾部补完后轮转必须成功: %v", rerr)
	}

	// Then：一次复制、活文件截断、归档=轮转前全部内容、两事务均入库。
	if copies != 1 {
		t.Fatalf("完整轮转只允许一次复制, copies=%d", copies)
	}
	live, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if live.Size() != 0 {
		t.Fatalf("live size=%d, want 0（轮转成功必须截断）", live.Size())
	}
	archive, err := os.ReadFile(logPath + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if want := string(before) + tail + "\n"; string(archive) != want {
		t.Fatalf("归档内容长度=%d, want %d（轮转前全部字节必须入档，零丢失）", len(archive), len(want))
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE transaction_id IN ('tx-blocked-1','tx-clean-1')`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("rows=%d, want 2（A + 补完的事务）", rows)
	}
}

// Given 摄取偏移落后活文件尾部（复制前闸门触发并追平）。When 轮转完成。
// Then 归档（.1）补采起点抬到闸门的 reached——闸门刚解析提交的区间不得在
// 轮转后从 .1 二次解析（每次固定多付一遍 ≤8MiB JSON 解码，去重只保证不重复
// 成行，不省 CPU）。
func TestRotateAuditLog_gateIngestAdvancesRotatedIngestStart(t *testing.T) {
	// Given：可用事件库 + 已摄取到 EOF 的活文件 + 小阈值
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	oldHook := auditLogRotatedIngestFrom
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func(context.Context) int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
		auditLogRotatedIngestFrom = oldHook
	})

	appendDoc := func(seq int) {
		doc := strings.Replace(securityEventsFixtureClean, "tx-clean-1", fmt.Sprintf("tx-gate-%d", seq), 1) + "\n"
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(doc); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for seq := range 2 {
		appendDoc(seq)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	offsetBefore, err := securityEventsReadOffset(offsetPath)
	if err != nil {
		t.Fatalf("read offset: %v", err)
	}

	// When：再追写两条（offset 落后 → 闸门需先补采），然后轮转
	for seq := 2; seq < 4; seq++ {
		appendDoc(seq)
	}
	liveInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if liveInfo.Size() <= offsetBefore {
		t.Fatalf("活文件 %d 字节未超过已摄取偏移 %d，闸门不会触发（断言失效）", liveInfo.Size(), offsetBefore)
	}
	var ingestFrom int64 = -1
	auditLogRotatedIngestFrom = func(from int64) { ingestFrom = from }
	if _, err := rotateAuditLogIfNeeded(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Then：归档补采起点=闸门 reached（追平时的活文件大小），而非旧偏移
	if ingestFrom < 0 {
		t.Fatal("归档补采未执行（观测钩子未被调用）")
	}
	if ingestFrom <= offsetBefore {
		t.Fatalf("归档补采起点=%d, want > %d（闸门已提交的区间不得二次解析）", ingestFrom, offsetBefore)
	}
	if ingestFrom != liveInfo.Size() {
		// JSON 解码器停在最后一条文档末尾：闸门 reached 可能落在文档间空白
		// （尾随换行）之前 —— 等价断言是「起点之后的剩余字节只有空白」。
		// 活文件此时已被截断，同内容在 .1 归档里。
		if ingestFrom > liveInfo.Size() || !auditLogTailOnlyWhitespace(logPath+".1", ingestFrom, liveInfo.Size()) {
			t.Fatalf("归档补采起点=%d, want 闸门追平后的位置（活文件 %d 字节；剩余字节必须只有空白）", ingestFrom, liveInfo.Size())
		}
	}
}
