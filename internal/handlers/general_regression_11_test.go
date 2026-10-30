package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 修复前 autoBackupTriggerMu 只串行手动触发，定时在途时 TryLock 必成功并
// 回 202「已开始」，随后后台撞引擎单飞仅写 warn，对用户完全不可见（零动作）。
func TestRunAutoBackupNow_scheduledInFlightReturns409(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	wireAutoBackupEngineForTest(t, h)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	services.SetAutoBackupExecutor(func(ctx context.Context, trigger, operator string, engineRunID int64) error {
		started <- struct{}{}
		<-release
		return nil
	})
	t.Cleanup(func() { services.SetAutoBackupExecutor(nil) })

	te := services.TaskEngine()
	done := make(chan error, 1)
	go func() {
		_, err := te.RunSync("auto-backup", "schedule", "system")
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("定时备份桩未启动")
	}

	// When：定时备份在途时手动触发
	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/run", "/auto-backup/run", "", h.RunAutoBackupNow)

	// Then：同步 409（而非 202「已开始」+ 后台静默丢弃）
	if response.Code != http.StatusConflict {
		close(release)
		t.Fatalf("定时备份在途时手动触发 status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "正在执行") {
		close(release)
		t.Fatalf("body=%s, want 明确「正在执行」提示", response.Body.String())
	}
	close(release)
	<-done
}

// 「上次执行」展示必须取最近一次 success 备份行（last_success_at）；水位线
// 单独回传 last_run（调度内部语义），不得再被前端当作「上次执行」。
func TestAutoBackupSettings_lastSuccessAtSeparatedFromWatermark(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run='2026-10-01T03:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// Given：仅水位线、从未成功备份
	payload := struct {
		Data struct {
			LastRun       *string `json:"last_run"`
			LastSuccessAt *string `json:"last_success_at"`
		} `json:"data"`
	}{}
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Data.LastRun == nil {
		t.Fatal("last_run 水位线应继续回传（调度语义）")
	}
	if payload.Data.LastSuccessAt != nil {
		t.Fatalf("从未成功备份时 last_success_at=%v, want null（不得用水位线冒充执行事实）", *payload.Data.LastSuccessAt)
	}

	// And：失败行不得充当「上次成功备份」
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type, created_at) VALUES ('lbbak-auto-fail.lbbak','failed','schedule','2026-10-02 03:00:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type, created_at) VALUES ('lbbak-auto-ok.lbbak','success','schedule','2026-09-15 03:00:00')`); err != nil {
		t.Fatal(err)
	}
	response = serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	payload.Data.LastSuccessAt = nil
	payload.Data.LastRun = nil
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 口径：取最近 success 行的 created_at，响应形态为 UTC 墙钟串
	//（与 /audit-logs、/certificates 同族），库内存储形态由驱动归一。
	var successCreated time.Time
	if err := db.DB.QueryRow(`SELECT created_at FROM auto_backups WHERE filename='lbbak-auto-ok.lbbak'`).Scan(&successCreated); err != nil {
		t.Fatalf("read success created_at: %v", err)
	}
	wantCreated := successCreated.UTC().Format("2006-01-02 15:04:05")
	if payload.Data.LastSuccessAt == nil || *payload.Data.LastSuccessAt != wantCreated {
		got := "<nil>"
		if payload.Data.LastSuccessAt != nil {
			got = *payload.Data.LastSuccessAt
		}
		t.Fatalf("last_success_at=%s, want 最近 success 行 %q（失败行不得入选）", got, wantCreated)
	}
}

// 取消必须在落盘前生效（检查点）——修复前 demote 中在途备份仍会跑完并记
// success。取消返回 ctx 错误，不落 failed 行、不写文件。
func TestRunAutoBackupOnce_cancelledContextWritesNothing(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := h.RunAutoBackupOnce(ctx, "schedule", "system", 1)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err=%v, want context canceled", err)
	}
	matches, _ := filepath.Glob(filepath.Join(h.cfg.BackupDir, "*"))
	if len(matches) != 0 {
		t.Fatalf("取消后不得写文件, got %v", matches)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("取消后不得落 auto_backups 行, rows=%d", rows)
	}
	for _, action := range []string{"备份失败", "自动备份"} {
		if got := countAutoBackupAudit(t, action); got != 0 {
			t.Fatalf("取消路径 %s 审计=%d, want 0", action, got)
		}
	}
}

// 写失败不得留下临时文件（残留会让 auto_backups 行 → prune 永不回收；修复前
// 仅 Rename 失败分支清理）。
func TestRunAutoBackupOnce_writeFailureLeavesNoTmp(t *testing.T) {
	// 写失败注入走落盘缝（autoBackupWriteFile）：不依赖文件系统权限语义——
	// root / 容器内 chmod 0500 不阻断写入，权限位形态会让该回归在 CI 假红
	// （或被跳过而彻底失去覆盖）。注入形态任何身份都可跑。
	t.Run("injected", func(t *testing.T) {
		h := newAutoBackupTestHandlers(t)
		dir := h.cfg.BackupDir
		orig := autoBackupWriteFile
		autoBackupWriteFile = func(string, []byte) error { return os.ErrPermission }
		t.Cleanup(func() { autoBackupWriteFile = orig })

		// When
		if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1); err == nil {
			t.Fatal("落盘失败应返回错误")
		}

		// Then：失败后不得留下 success 行（失败行是允许的终态留痕），
		// 目录内无 .tmp 残留。
		var successRows int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='success'`).Scan(&successRows); err != nil {
			t.Fatal(err)
		}
		if successRows != 0 {
			t.Fatalf("写盘失败后仍有 success 行 %d 条", successRows)
		}
		if matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(matches) != 0 {
			t.Fatalf("写失败后残留 tmp=%v, want 零", matches)
		}
	})

	// 权限位形态保留为附加子用例，但先探测 0500 是否真的拦截写入（root 下
	// 不拦截 → skip 并说明语义已由注入子用例覆盖）。
	t.Run("readonly-dir", func(t *testing.T) {
		h := newAutoBackupTestHandlers(t)
		dir := h.cfg.BackupDir
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod backup dir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		probe := filepath.Join(dir, ".write-probe")
		if err := os.WriteFile(probe, []byte("x"), 0o600); err == nil {
			_ = os.Remove(probe)
			t.Skip("当前身份不受目录权限位约束（root/容器内），写失败语义已由 injected 子用例覆盖")
		}

		// When
		if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1); err == nil {
			t.Fatal("只读备份目录下应写盘失败")
		}

		// Then：目录内无 .tmp 残留
		if matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(matches) != 0 {
			t.Fatalf("写失败后残留 tmp=%v, want 零", matches)
		}
	})
}

// ABORT）时频率/范围/保留份数不得已生效（修复前先落库后写开关，返回 500
// 但设置已改）。
func TestUpdateAutoBackupSettings_atomicOnEnabledFailure(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily',
		auto_backup_time='03:00', auto_backup_day=1, auto_backup_keep=7, auto_backup_sections='["users","rules","security"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER u05_fail_enabled_update BEFORE UPDATE OF auto_backup_enabled ON global_config
		BEGIN SELECT RAISE(ABORT, 'injected enabled failure'); END`); err != nil {
		t.Fatal(err)
	}
	body := `{"enabled":false,"frequency":"monthly","time":"01:15","day":9,"keep":12,"sections":["users"]}`

	// When
	response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", body, h.UpdateAutoBackupSettings)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（开关写失败）", response.Code, response.Body.String())
	}

	// Then：设置保持原值（同事务回滚）
	var freq, hhmm, sections string
	var day, keep int
	if err := db.DB.QueryRow(`SELECT auto_backup_frequency, auto_backup_time, auto_backup_day, auto_backup_keep, auto_backup_sections FROM global_config WHERE id=1`).
		Scan(&freq, &hhmm, &day, &keep, &sections); err != nil {
		t.Fatal(err)
	}
	if freq != "daily" || hhmm != "03:00" || day != 1 || keep != 7 || sections != `["users","rules","security"]` {
		t.Fatalf("开关失败后设置已半保存: (%s,%s,%d,%d,%s)", freq, hhmm, day, keep, sections)
	}
}

// 角色查询失败必须 500 而非 403——「仅允许在主节点执行」会误导排障方向
// （与 requireAutoBackupMaster 先例同口径）。
func TestRequireMasterNode_roleQueryFailureReturns500(t *testing.T) {
	closed, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}
	orig := db.DB
	db.DB = closed
	t.Cleanup(func() { db.DB = orig })

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/log-cleanup/trigger", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("DB 故障时 status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "节点角色查询失败") {
		t.Fatalf("body=%s, want 明确的角色查询失败文案", response.Body.String())
	}
}
