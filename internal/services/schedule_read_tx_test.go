package services

import (
	"bytes"
	"log"
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func initScheduleTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 后台循环句柄（db.GetDB）同样复位——Close 只置 nil，不还原旧值。
		db.SetDB(oldCurrent)
	})
	isolateMetricsState(t)
}

// 版本表族排程保存必须事务化——INSERT 初始化行与
// UPDATE 排程要么同时生效、要么同时回滚，不得留「行已建、排程未生效、
// next_update 为空」的中间态。
func TestSetVersionTableSchedule_isAtomicOnUpdateFailure(t *testing.T) {
	initScheduleTestDB(t)
	useShanghaiLocation(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_crs_schedule BEFORE UPDATE ON security_crs_version
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM security_crs_version`); err != nil {
		t.Fatalf("clear version row: %v", err)
	}

	// When：UPDATE 被触发器拒绝
	err := SetCRSSchedule(allWeek(), "04:00")

	// Then：报错且初始化行随事务回滚（不得留下「行已建、排程未生效」形态）
	if err == nil {
		t.Fatal("SetCRSSchedule error=nil, want 触发器拒绝后报错")
	}
	var count int
	if qerr := db.DB.QueryRow("SELECT COUNT(*) FROM security_crs_version").Scan(&count); qerr != nil {
		t.Fatalf("count rows: %v", qerr)
	}
	if count != 0 {
		t.Fatalf("version rows=%d, want 0（INSERT 必须随事务回滚）", count)
	}

	// 回归形状：去掉触发器后同一调用成功且排程生效。
	if _, err := db.DB.Exec("DROP TRIGGER reject_crs_schedule"); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if err := SetCRSSchedule(allWeek(), "04:30"); err != nil {
		t.Fatalf("SetCRSSchedule: %v", err)
	}
	var hhmm string
	if err := db.DB.QueryRow("SELECT schedule_time FROM security_crs_version WHERE id=1").Scan(&hhmm); err != nil {
		t.Fatalf("read schedule_time: %v", err)
	}
	if hhmm != "04:30" {
		t.Fatalf("schedule_time=%q, want 04:30", hhmm)
	}
}

// 自动更新开关的两步写必须事务化（与排程保存同构）：INSERT 成功而 UPDATE
// 失败会留「行已建、auto_update=1、next_update 空」的中间态——开关显示已开、
// 任务永不触发，且失败只经一次 handler 响应留痕。
func TestSetVersionTableAutoUpdate_rollsBackOnUpdateFailure(t *testing.T) {
	initScheduleTestDB(t)
	useShanghaiLocation(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_crs_auto_update BEFORE UPDATE ON security_crs_version
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM security_crs_version`); err != nil {
		t.Fatalf("clear version row: %v", err)
	}

	// When：UPDATE 被触发器拒绝
	err := SetCRSAutoUpdate(true)

	// Then：报错且初始化行随事务回滚（不得留空 next_update 的中间态）
	if err == nil {
		t.Fatal("SetCRSAutoUpdate error=nil, want 触发器拒绝后报错")
	}
	var count int
	if qerr := db.DB.QueryRow("SELECT COUNT(*) FROM security_crs_version").Scan(&count); qerr != nil {
		t.Fatalf("count rows: %v", qerr)
	}
	if count != 0 {
		t.Fatalf("version rows=%d, want 0（INSERT 必须随事务回滚）", count)
	}

	// 回归形状：去掉触发器后同一调用成功且槽位已武装。
	if _, err := db.DB.Exec("DROP TRIGGER reject_crs_auto_update"); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if err := SetCRSAutoUpdate(true); err != nil {
		t.Fatalf("SetCRSAutoUpdate: %v", err)
	}
	var next string
	if err := db.DB.QueryRow("SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1").Scan(&next); err != nil {
		t.Fatalf("read next_update: %v", err)
	}
	if next == "" {
		t.Fatal("开启自动更新后 next_update 必须已落槽（空槽=任务永不触发）")
	}
}

// 排程读取失败必须留痕（首报 warn）且不得 panic——
// 此前三处读错误全部静默，库不可读时自动更新静默停摆且排障零信号。
func TestScheduleReaders_logReadFailure(t *testing.T) {
	initScheduleTestDB(t)
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	if _, err := db.DB.Exec("DROP TABLE security_crs_version"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, err := db.DB.Exec("DROP TABLE security_threat_sources"); err != nil {
		t.Fatalf("drop threat sources: %v", err)
	}

	// When：版本表/任务级排程读取全部命中错误
	days, hhmm := versionTableSchedule("security_crs_version")
	if len(days) == 0 || hhmm == "" {
		t.Fatalf("版本表读失败应回落默认排程, got %v %q", days, hhmm)
	}
	crawlerDays, crawlerHHMM := globalTaskSchedule("does_not_exist")
	if len(crawlerDays) == 0 || crawlerHHMM == "" {
		t.Fatalf("任务级排程读失败应回落默认排程, got %v %q", crawlerDays, crawlerHHMM)
	}

	// Then：失败留痕（含表/列名，首报一条）
	if !strings.Contains(logs.String(), "读取配置失败") {
		t.Fatalf("logs=%q, want 含「读取配置失败」", logs.String())
	}

	// 畸形形状：nil 库守卫——读侧走原子句柄 db.GetDB()，必须摘除原子句柄才
	// 能覆盖 nil 分支。只清 db.DB 时读侧仍持有旧句柄，用例只会证明「查询报错
	// →回落」，将来删掉 nil 守卫仍会绿（鉴别力缺失）。不得 panic，返回默认排程。
	db.SetDB(nil)
	wantDays := ParseScheduleDays(db.DefaultScheduleDays)
	if days, hhmm := globalTaskSchedule("threat"); !reflect.DeepEqual(days, wantDays) || hhmm != db.DefaultScheduleTime {
		t.Fatalf("nil 库应返回默认排程, got %v %q", days, hhmm)
	}
	if days, hhmm := versionTableSchedule("security_crs_version"); !reflect.DeepEqual(days, wantDays) || hhmm != db.DefaultScheduleTime {
		t.Fatalf("nil 库版本表排程应回落默认, got %v %q", days, hhmm)
	}
}

// Given 同步侧句柄（db.DB）持有非默认排程，后台原子句柄（db.GetDB）被摘除。
// When tick/后台读侧入口（EnabledFn/NextSlotFn 的数据源）读取。
// Then 全部按「库不可读」fail-safe 返回（默认排程 / 空槽 / 未知状态）——
// 读侧不得回落同步句柄：两来源分裂时后台循环会读到另一个库（静默空转或
// 排程错位）。本用例以「摘除原子句柄后返回值翻转」为判据。
func TestScheduleReadPathsUseAtomicHandle(t *testing.T) {
	initScheduleTestDB(t)
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1,'v-test',1)`); err != nil {
		t.Fatalf("seed version row: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET schedule_days='1', schedule_time='09:30', next_update='2999-01-01 00:00:00' WHERE id=1`); err != nil {
		t.Fatalf("seed version schedule: %v", err)
	}
	// 源名取内置注册表名：威胁族槽域=运行域（注册表三源），注册表外启用行
	// 不参与「最早槽」（见 earliestThreatNextUpdate）。注册表源在 db 初始化时
	// 已播种，故按 UPSERT 覆写排程而不是裸 INSERT（否则 UNIQUE 冲突）。
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (name, update_enabled, next_update)
		VALUES ('ustc',1,'2999-01-02 00:00:00')
		ON CONFLICT(name) DO UPDATE SET update_enabled=1, next_update=excluded.next_update`); err != nil {
		t.Fatalf("seed threat source: %v", err)
	}

	// 夹具前提：未摘句柄时读侧返回库中非默认值（否则下方的翻转断言无区分力）。
	if days, hhmm := CRSSchedule(); len(days) != 1 || days[0] != 1 || hhmm != "09:30" {
		t.Fatalf("夹具前提不成立：CRSSchedule=%v/%q", days, hhmm)
	}
	if got := versionTableNextUpdate("security_crs_version"); got != "2999-01-01 00:00:00" {
		t.Fatalf("夹具前提不成立：next_update=%q", got)
	}
	if got := earliestThreatNextUpdate(); got != "2999-01-02 00:00:00" {
		t.Fatalf("夹具前提不成立：earliest threat=%q", got)
	}

	// When 后台句柄被摘除（同步句柄仍完整可读）
	db.SetDB(nil)

	// Then 读侧一律 fail-safe，且不得回落到同步句柄
	if days, hhmm := CRSSchedule(); len(days) != 7 || hhmm != "04:00" {
		t.Fatalf("CRSSchedule=%v/%q，want 默认排程（读侧必须走原子句柄）", days, hhmm)
	}
	if days, hhmm := ThreatSchedule(); len(days) != 7 || hhmm != "04:00" {
		t.Fatalf("ThreatSchedule=%v/%q，want 默认排程", days, hhmm)
	}
	if got := versionTableNextUpdate("security_crs_version"); got != "" {
		t.Fatalf("versionTableNextUpdate=%q，want 空槽（原子句柄缺失按未排程处理）", got)
	}
	if enabled, known := versionTableAutoUpdateState("security_crs_version"); enabled || known {
		t.Fatalf("versionTableAutoUpdateState=(%v,%v)，want (false,false)", enabled, known)
	}
	if got := earliestThreatNextUpdate(); got != "" {
		t.Fatalf("earliestThreatNextUpdate=%q，want 空", got)
	}

	// 时区重排同样不得写同步句柄：原子句柄缺失时整段 no-op。
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET next_update='2999-01-03 00:00:00' WHERE id=1`); err != nil {
		t.Fatalf("reset version next_update: %v", err)
	}
	RearmScheduleSlotsAfterTimezoneChange()
	var after string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1`).Scan(&after); err != nil {
		t.Fatalf("read next_update: %v", err)
	}
	if after != "2999-01-03 00:00:00" {
		t.Fatalf("时区重排写入了同步句柄（next_update=%q），应整段 no-op", after)
	}
}
