package services

import (
	"bytes"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// snapshotLocationState 记录并还原「双写」时区状态：ConfigureLocation 同时写
// currentLocation 与任务引擎（taskengine.SetLocation）。只还原 currentLocation
// 会让引擎时区永久停在用例值——后续用例的任务槽/时间断言差若干小时（顺序相关
// 污染，-shuffle 下随机红）。引擎没有读访问器，故保存的是同一个 *time.Location。
func snapshotLocationState(t *testing.T) {
	t.Helper()
	oldLoc := CurrentLocation()
	t.Cleanup(func() {
		currentLocation.Store(oldLoc)
		taskengine.SetLocation(oldLoc)
	})
}

func TestRefreshLocation_updates_current_location_without_mutating_timeLocal(t *testing.T) {
	// Given
	snapshotLocationState(t) // refreshLocation 写 currentLocation + 任务引擎，必须同源还原
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 后台刷新链读 currentDB（db.GetDB），Close 已置 nil——只恢复 db.DB 会
		// 让时区 worker 在 nil 句柄上空转（与 initServicesDB 同构）。
		db.SetDB(oldCurrent)
	})
	if _, err := db.DB.Exec("UPDATE global_config SET timezone='UTC' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}
	localBefore := time.Local

	// When
	err := refreshLocation()

	// Then
	if err != nil {
		t.Fatalf("refresh location: %v", err)
	}
	if time.Local != localBefore {
		t.Fatal("runtime timezone refresh mutated time.Local")
	}
	if CurrentLocation() != time.UTC {
		t.Fatalf("current location=%v, want UTC", CurrentLocation())
	}
}

func TestApplicationLogWriterFiltersRawStandardLogsAtConfiguredThreshold(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		message string
		want    bool
	}{
		{name: "info allows ordinary lines", level: "info", message: "startup complete", want: true},
		{name: "warn drops ordinary lines", level: "warn", message: "startup complete", want: false},
		{name: "warn allows warning lines", level: "warn", message: "Warning: degraded startup", want: true},
		{name: "error drops warning lines", level: "error", message: "Warning: degraded startup", want: false},
		{name: "error allows error lines", level: "error", message: "ERROR: startup failed", want: true},
	}
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var output bytes.Buffer
			if err := ConfigureLogLevel(test.level); err != nil {
				t.Fatal(err)
			}
			logger := log.New(NewApplicationLogWriter(&output), "", 0)

			// When
			logger.Print(test.message)

			// Then
			if strings.Contains(output.String(), test.message) != test.want {
				t.Fatalf("output=%q want_visible=%v", output.String(), test.want)
			}
		})
	}
}

// DB 初始化完成点即时刷新时区——init 期 worker 首查时
// DB 未就绪恒空转，配置时区此前最长要等 30s ticker 才生效（FixedZone+8 占位
// 窗口）。ApplyLogLevel 是 main 在 db.Initialize 完成后的首个 services 装配点
// （亦为集群导入 users 节后的调用点），在此追加一次即时 refreshLocation。
func TestApplyLogLevel_refreshesTimezoneImmediately(t *testing.T) {
	snapshotLocationState(t) // currentLocation + 任务引擎同源还原（ApplyLogLevel 两处都写）
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 后台刷新链读 currentDB（db.GetDB），Close 已置 nil——只恢复 db.DB 会
		// 让时区 worker 在 nil 句柄上空转（与 initServicesDB 同构）。
		db.SetDB(oldCurrent)
	})
	if _, err := db.DB.Exec("UPDATE global_config SET timezone='America/New_York' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}

	// When：DB 就绪后的装配点调用（不等 30s ticker）
	ApplyLogLevel()

	// Then：DST 时区立即生效
	if got := CurrentLocation().String(); got != "America/New_York" {
		t.Fatalf("current location=%q, want America/New_York（DB 就绪后必须即时刷新，不得等 ticker）", got)
	}
}

// applicationLogWriter 透传 sink 的真实返回值——短写
// 返回 len(p) 偏离 io.Writer 契约（装饰器不得替 sink 谎报写入量）。
func TestApplicationLogWriter_writeReturnsSinkWrittenCount(t *testing.T) {
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })
	if err := ConfigureLogLevel("warn"); err != nil { // 进入过滤分支（info 直通分支本就透传）
		t.Fatal(err)
	}
	sink := &shortWriteSink{n: 3}
	w := NewApplicationLogWriter(sink)
	// 载荷带 WARN 前缀——warn 档放行进入写入分支（不带前缀会在过滤分支被丢弃，
	// 触达不到 sink）。
	n, err := w.Write([]byte("WARN hello world"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 3 {
		t.Fatalf("Write returned %d, want sink's 3（短写必须如实返回 written）", n)
	}
}

// 多行 payload 被逐行过滤后 out 短于 p 时，必须返回
// (len(p), nil)——sink 已写满被保留内容即代表入参全部被消费。旧实现返回
// sink 的 written(<len(p)) 且 err=nil，违反 io.Writer 契约（短写敏感消费者
// 会当成截断）。sink 自身短写则按契约报 io.ErrShortWrite。
func TestApplicationLogWriter_multilineFilterHonorsWriterContract(t *testing.T) {
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })
	if err := ConfigureLogLevel("warn"); err != nil {
		t.Fatal(err)
	}
	payload := []byte("WARNING: kept\nordinary dropped\nERROR: kept too\n")

	t.Run("filtered payload reports full consumption", func(t *testing.T) {
		var output bytes.Buffer
		n, err := NewApplicationLogWriter(&output).Write(payload)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("Write returned %d, want len(p)=%d（过滤掉的行也算已消费）", n, len(payload))
		}
		if got, want := output.String(), "WARNING: kept\nERROR: kept too\n"; got != want {
			t.Fatalf("output=%q, want %q", got, want)
		}
	})

	t.Run("sink short write surfaces io.ErrShortWrite", func(t *testing.T) {
		n, err := NewApplicationLogWriter(&shortWriteSink{n: 3}).Write(payload)
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("err=%v, want io.ErrShortWrite", err)
		}
		if n != 0 {
			t.Fatalf("n=%d, want 0（无法映射回入参字节）", n)
		}
	})
}

// shortWriteSink 恒短写返回 (n, nil) 的 sink。
type shortWriteSink struct{ n int }

func (s *shortWriteSink) Write(p []byte) (int, error) {
	if s.n > len(p) {
		return len(p), nil
	}
	return s.n, nil
}

// 多行 payload（Logf 消息内嵌换行）必须逐行按级别过滤
// 后重组——只看首行会让 warn/error 档整体放行后续低级别行（级别过滤被绕过）。
func TestApplicationLogWriter_filtersEachLineOfMultilinePayload(t *testing.T) {
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })

	t.Run("warn keeps warn and error lines only", func(t *testing.T) {
		if err := ConfigureLogLevel("warn"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		payload := []byte("WARNING: degraded\nordinary info line\nERROR: boom\n")
		if _, err := NewApplicationLogWriter(&output).Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := output.String(), "WARNING: degraded\nERROR: boom\n"; got != want {
			t.Fatalf("output=%q, want 仅 warn/error 行（info 行必须逐行滤除）", got)
		}
	})

	t.Run("error keeps error lines only", func(t *testing.T) {
		if err := ConfigureLogLevel("error"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		payload := []byte("WARNING: degraded\nERROR: boom\nstill ordinary\n")
		if _, err := NewApplicationLogWriter(&output).Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := output.String(), "ERROR: boom\n"; got != want {
			t.Fatalf("output=%q, want 仅 error 行", got)
		}
	})

	t.Run("single line path unchanged", func(t *testing.T) {
		if err := ConfigureLogLevel("warn"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if _, err := NewApplicationLogWriter(&output).Write([]byte("WARN hello\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := output.String(), "WARN hello\n"; got != want {
			t.Fatalf("output=%q, want 单行原样透传", got)
		}
	})
}

// 时区刷新路径必须与写侧同一校验器：空/空白时区（LoadLocation("")=UTC 合法）
// 不得静默把全站切到 UTC——刷新失败保留旧时区并返回错误（状态机留痕）。
func TestRefreshLocation_rejectsBlankTimezone(t *testing.T) {
	initServicesDB(t)
	snapshotLocationState(t) // ConfigureLocation 写双状态，必须同源还原
	if _, err := ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatalf("seed location: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET timezone='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	err := refreshLocation()

	// Then：拒绝空串、保留旧时区
	if err == nil {
		t.Fatal("空时区必须被拒绝（LoadLocation(\"\") 会静默返回 UTC）")
	}
	if got := CurrentLocation().String(); got != "Asia/Shanghai" {
		t.Fatalf("时区被静默切走: %q, want Asia/Shanghai", got)
	}
}

// ConfigureLocation 是第二写入口：空串必须显式拒绝（time.LoadLocation("")
// 合法返回 UTC——放行会静默把全站展示/审计窗口切 UTC）。
func TestConfigureLocation_rejectsBlankName(t *testing.T) {
	snapshotLocationState(t)
	oldLoc := CurrentLocation()
	for _, name := range []string{"", "   "} {
		if _, err := ConfigureLocation(name); err == nil {
			t.Fatalf("ConfigureLocation(%q) 必须拒绝空/空白时区", name)
		}
	}
	if got := CurrentLocation(); got != oldLoc {
		t.Fatalf("拒绝后不得改动当前时区: %v → %v", oldLoc, got)
	}
}

// 日志级别读失败必须留痕（状态转换口径：首报一次、恢复补一条），不得静默
// 降级到 info。
func TestApplyLogLevel_logsReadFailureOnceAndRecovers(t *testing.T) {
	snapshotLocationState(t) // currentLocation + 任务引擎同源还原
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 后台刷新链读 currentDB（db.GetDB），Close 已置 nil——只恢复 db.DB 会
		// 让时区 worker 在 nil 句柄上空转（与 initServicesDB 同构）。
		db.SetDB(oldCurrent)
	})
	// 整表隔离用单源 helper（保存并还原全表 + FIFO 键序）——手工
	// `metricsStateFailed = map[string]bool{}` 会丢弃其它族（collect/
	// timezone-refresh/schedule-read-*）的键，跨用例串扰。
	isolateMetricsState(t)

	if _, err := db.DB.Exec("ALTER TABLE global_config RENAME TO global_config_bak"); err != nil {
		t.Fatalf("inject read failure: %v", err)
	}
	out := captureLogf(t)
	ApplyLogLevel()
	ApplyLogLevel()
	if got := strings.Count(out.String(), "读取日志级别配置失败"); got != 1 {
		t.Fatalf("连续读失败留痕次数=%d, want 1（状态转换去重）: %q", got, out.String())
	}

	if _, err := db.DB.Exec("ALTER TABLE global_config_bak RENAME TO global_config"); err != nil {
		t.Fatalf("restore table: %v", err)
	}
	out.Reset()
	ApplyLogLevel()
	if !strings.Contains(out.String(), "读取日志级别配置已恢复") {
		t.Fatalf("恢复后必须补一条恢复留痕: %q", out.String())
	}
}
