package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func newAutoBackupTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	h := newBackupTestHandlers(t)
	h.cfg.BackupDir = t.TempDir()
	// 导入链要求「至少保留一个启用管理员」——备份/还原共用该前提
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return h
}

// wireAutoBackupEngineForTest：/auto-backup/run 经引擎
// RunSync——测试环境装配引擎+执行器（镜像 main.go 注入形态）。
func wireAutoBackupEngineForTest(t *testing.T, h *Handlers) {
	t.Helper()
	services.SetAutoBackupExecutor(func(ctx context.Context, trigger, operator string, engineRunID int64) error {
		_, err := h.RunAutoBackupOnce(ctx, trigger, operator, engineRunID)
		return err
	})
	// 判据与 initTaskEngineForTest 同源：nil 或已停止都必须重建。只判 nil 时
	// 会拿到前一用例停掉但未清全局指针的引擎，端点回 503「任务引擎已停止」。
	if te := services.TaskEngine(); te == nil || te.IsStopped() {
		services.InitTaskEngine("", t.TempDir()+"/app.log")
	}
	t.Cleanup(func() {
		services.StopTaskEngine()
		services.SetAutoBackupExecutor(nil)
	})
}

// waitForAutoBackupCondition 轮询等待后台备份/审计落行（异步触发后，
// 响应返回时后台任务可能尚未完成）。
func waitForAutoBackupCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("后台备份未在超时内完成")
}

func countAutoBackupAudit(t *testing.T, action string) int {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return count
}

// autoBackupAuditDetail 返回该动作最近一条审计的 detail（失败面复盘断言用）。
func autoBackupAuditDetail(t *testing.T, action string) string {
	t.Helper()
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&detail); err != nil {
		t.Fatalf("read audit detail for %q: %v", action, err)
	}
	return detail
}

func autoBackupRows(t *testing.T, where string, args ...any) []map[string]any {
	t.Helper()
	rows, err := db.DB.Query(`SELECT id, filename, status, trigger_type, size_bytes, sections, message FROM auto_backups `+where, args...)
	if err != nil {
		t.Fatalf("query auto_backups: %v", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int64
		var filename, status, triggerType, sections, message string
		var size int64
		if err := rows.Scan(&id, &filename, &status, &triggerType, &size, &sections, &message); err != nil {
			t.Fatalf("scan auto_backups: %v", err)
		}
		out = append(out, map[string]any{"id": id, "filename": filename, "status": status, "trigger_type": triggerType, "size_bytes": size, "sections": sections, "message": message})
	}
	return out
}

// engineRunID<=0 属绕过引擎的非法调用：必须显性报错且不写 task_runs
// （legacy RecordRunStart/Finish 直写旁路已删除——task_runs 唯一写方=引擎）。
func TestRunAutoBackupOnce_missingEngineRunIDRejectedWithoutTaskRuns(t *testing.T) {
	h := newAutoBackupTestHandlers(t)

	_, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 0)
	if err == nil || !strings.Contains(err.Error(), "engineRunID") {
		t.Fatalf("err=%v, want engineRunID 缺失显性错误", err)
	}
	var runs int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='auto-backup'`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("task_runs auto-backup 行数=%d, want 0（直写旁路不得复活）", runs)
	}
	var backups int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups`).Scan(&backups); err != nil {
		t.Fatal(err)
	}
	if backups != 0 {
		t.Fatalf("auto_backups 行数=%d, want 0（拒绝发生在任何写之前）", backups)
	}
}

func TestRunAutoBackupOnce_successWritesFileRowAndAudit(t *testing.T) {
	// Given: 主节点测试实例 + 可写备份目录
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_ab1','auto-backup-rule','http','ab.example.test',8080,1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	// When
	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}

	// Then: 目录出现 lbbak 文件且非空
	matches, err := filepath.Glob(filepath.Join(h.cfg.BackupDir, "lbbak-manual-*.lbbak"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("backup files=%v err=%v, want exactly 1 lbbak-manual-*.lbbak", matches, err)
	}
	info, err := os.Stat(matches[0])
	if err != nil || info.Size() == 0 {
		t.Fatalf("backup file stat err=%v size=%d, want non-empty", err, info.Size())
	}
	// 行:success + 真实大小 + 全 4 分类(默认全选，含节点拓扑)+ 摘要非空
	rows := autoBackupRows(t, "WHERE trigger_type='manual'")
	if len(rows) != 1 {
		t.Fatalf("manual rows=%d, want 1", len(rows))
	}
	row := rows[0]
	if row["status"] != "success" {
		t.Fatalf("status=%v, want success", row["status"])
	}
	if row["size_bytes"].(int64) != info.Size() {
		t.Fatalf("size_bytes=%v, want %d", row["size_bytes"], info.Size())
	}
	var sections []string
	if err := json.Unmarshal([]byte(row["sections"].(string)), &sections); err != nil || len(sections) != 4 || sections[0] != "users" || sections[1] != "rules" || sections[2] != "security" || sections[3] != "cluster" {
		t.Fatalf("sections=%q err=%v, want [users rules security cluster]", row["sections"], err)
	}
	if row["message"] == "" {
		t.Fatal("message 为空, want 各表行数摘要")
	}
	// 审计:手动备份
	if got := countAutoBackupAudit(t, "手动备份"); got != 1 {
		t.Fatalf("手动备份 audit rows=%d, want 1", got)
	}
}
func TestRunAutoBackupOnce_recordsRealAppVersion(t *testing.T) {
	// Given: 标记版本号——必须原样落 auto_backups.app_version（系统真实版本，
	// 不受 branding.json 版本覆盖影响，2026-09-21 用户裁定新增「版本号」列）
	h := newAutoBackupTestHandlers(t)
	h.cfg.Version = "v9.9.9-test"

	// When
	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}

	// Then: DB 列与 API 视图双口径
	var version string
	if err := db.DB.QueryRow(`SELECT app_version FROM auto_backups WHERE trigger_type='manual' ORDER BY id DESC LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("query app_version: %v", err)
	}
	if version != "v9.9.9-test" {
		t.Fatalf("app_version=%q, want %q", version, "v9.9.9-test")
	}
	row := db.DB.QueryRow(`SELECT ` + autoBackupRowColumns + ` FROM auto_backups WHERE trigger_type='manual' ORDER BY id DESC LIMIT 1`)
	view, err := scanAutoBackupRowView(row)
	if err != nil {
		t.Fatalf("scanAutoBackupRowView: %v", err)
	}
	if view.AppVersion != "v9.9.9-test" {
		t.Fatalf("view.AppVersion=%q, want %q", view.AppVersion, "v9.9.9-test")
	}
}

func TestRunAutoBackupOnce_failureRecordsFailedRowAndAudit(t *testing.T) {
	// Given: 备份目录路径被同名文件占据 → MkdirAll 必败
	h := newAutoBackupTestHandlers(t)
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.cfg.BackupDir = blocked

	// When
	_, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1)

	// Then: 返回错误 + failed 行 + 自动备份审计(失败留痕)
	if err == nil {
		t.Fatal("RunAutoBackupOnce 应返回错误")
	}
	rows := autoBackupRows(t, "WHERE trigger_type='schedule' AND status='failed'")
	if len(rows) != 1 {
		t.Fatalf("failed rows=%d, want 1", len(rows))
	}
	if msg := rows[0]["message"].(string); !strings.Contains(msg, "创建备份目录失败") {
		t.Fatalf("message=%q, want 含「创建备份目录失败」", msg)
	}
	if got := countAutoBackupAudit(t, "备份失败"); got != 1 {
		t.Fatalf("备份失败 audit rows=%d, want 1", got)
	}
}

// 原子写已完成 rename、仅父目录 fsync 失败时，最终文件已经存在；写失败
// 收尾必须删除它，连续调度不得积累没有数据库行的敏感备份。
func TestRunAutoBackupOnce_writeFailureRemovesFinalFile(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	oldWrite := autoBackupWriteFile
	autoBackupWriteFile = func(path string, payload []byte) error {
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			return err
		}
		return errors.New("parent directory fsync failed")
	}
	t.Cleanup(func() { autoBackupWriteFile = oldWrite })

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1); err == nil || !strings.Contains(err.Error(), "fsync") {
			t.Fatalf("attempt %d error=%v, want injected fsync failure", attempt, err)
		}
		matches, err := filepath.Glob(filepath.Join(h.cfg.BackupDir, "*.lbbak"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("attempt %d 遗留无行备份文件: %v", attempt, matches)
		}
	}
	if rows := autoBackupRows(t, "WHERE status='failed'"); len(rows) != 2 {
		t.Fatalf("failed rows=%d, want 2（失败行仍须留痕）", len(rows))
	}
}

func TestRunAutoBackupOnce_cancelCleanupFailureLogsFilename(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	ctx, cancel := context.WithCancel(context.Background())
	oldWrite := autoBackupWriteFile
	autoBackupWriteFile = func(path string, payload []byte) error {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(path, "payload"), payload, 0o600); err != nil {
			return err
		}
		cancel()
		return nil
	}
	t.Cleanup(func() { autoBackupWriteFile = oldWrite })
	logs := captureLog(t)

	_, err := h.RunAutoBackupOnce(ctx, "schedule", "system", 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if !strings.Contains(logs.String(), "取消后清理最终文件") || !strings.Contains(logs.String(), ".lbbak") {
		t.Fatalf("取消后删除失败必须 warn 并点名文件，logs=%q", logs.String())
	}
	if got := countAutoBackupAudit(t, "备份失败"); got != 0 {
		t.Fatalf("取消路径失败审计=%d, want 0", got)
	}
}

func TestRunAutoBackupOnce_rowFailureCleanupFailureLogsFilename(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	oldWrite := autoBackupWriteFile
	autoBackupWriteFile = func(path string, payload []byte) error {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(path, "payload"), payload, 0o600)
	}
	t.Cleanup(func() { autoBackupWriteFile = oldWrite })
	if _, err := db.DB.Exec(`DROP TABLE auto_backups`); err != nil {
		t.Fatalf("force backup row insert failure: %v", err)
	}
	logs := captureLog(t)

	_, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1)
	if err == nil || !strings.Contains(err.Error(), "备份记录写入失败") {
		t.Fatalf("err=%v, want row insertion failure", err)
	}
	if !strings.Contains(logs.String(), "落行失败后清理最终文件") || !strings.Contains(logs.String(), ".lbbak") {
		t.Fatalf("落行失败后删除失败必须 warn 并点名文件，logs=%q", logs.String())
	}
}

func TestPruneAutoBackups_trimsSuccessByKeepAndFailedAtTwenty(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	dir := h.cfg.BackupDir

	// Given: 5 个 success(带真实文件,created_at 递增)+ 25 个 failed
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("lbbak-auto-prune%d.lbbak", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, size_bytes, trigger_type) VALUES (?, datetime('2026-09-0'+?+' 03:00:00'), 'success', 7, 'schedule')`, name, string(rune('0'+i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 25 {
		if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, trigger_type, message) VALUES (?, datetime('now', ?), 'failed', 'schedule', 'x')`, fmt.Sprintf("lbbak-auto-fail%d.lbbak", i), fmt.Sprintf("-%d minutes", i)); err != nil {
			t.Fatal(err)
		}
	}

	// When
	pruneAutoBackups(context.Background(), dir, 2, 20)

	// Then: success 仅留最新 2 个(文件+行同删)
	rows := autoBackupRows(t, "WHERE status='success' ORDER BY created_at DESC")
	if len(rows) != 2 {
		t.Fatalf("success rows after prune=%d, want 2", len(rows))
	}
	if rows[0]["filename"] != "lbbak-auto-prune5.lbbak" || rows[1]["filename"] != "lbbak-auto-prune4.lbbak" {
		t.Fatalf("裁剪方向错误：幸存行=%v/%v，want 最新 prune5/prune4", rows[0]["filename"], rows[1]["filename"])
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "lbbak-auto-prune*.lbbak"))
	if len(matches) != 2 {
		t.Fatalf("success files after prune=%v, want 2", matches)
	}
	// failed 仅留最近 20
	var failed int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='failed'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 20 {
		t.Fatalf("failed rows after prune=%d, want 20", failed)
	}
}

func serveAutoBackupJSON(t *testing.T, h *Handlers, method, route, reqPath, body string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	response := httptest.NewRecorder()
	router := gin.New()
	router.Handle(method, route, handler)
	request := httptest.NewRequest(method, reqPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	return response
}

func TestUpdateAutoBackupSettings_validationMatrix(t *testing.T) {
	valid := `{"enabled":true,"frequency":"weekly","time":"02:30","day":3,"keep":5,"sections":["users","rules"]}`
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown frequency", body: `{"enabled":true,"frequency":"hourly","time":"02:30","day":3,"keep":5,"sections":["users","rules"]}`},
		{name: "empty frequency", body: `{"enabled":true,"frequency":"","time":"02:30","day":3,"keep":5,"sections":["users","rules"]}`},
		{name: "missing frequency", body: `{"enabled":true,"time":"02:30","day":3,"keep":5,"sections":["users","rules"]}`},
		{name: "daily missing day", body: `{"enabled":true,"frequency":"daily","time":"03:00","keep":5,"sections":["users","rules"]}`},
		{name: "time missing leading zero", body: `{"enabled":true,"frequency":"daily","time":"2:30","day":1,"keep":5,"sections":["users","rules"]}`},
		{name: "time hour overflow", body: `{"enabled":true,"frequency":"daily","time":"24:00","day":1,"keep":5,"sections":["users","rules"]}`},
		{name: "time minute overflow", body: `{"enabled":true,"frequency":"daily","time":"03:60","day":1,"keep":5,"sections":["users","rules"]}`},
		{name: "time malformed", body: `{"enabled":true,"frequency":"daily","time":"0300","day":1,"keep":5,"sections":["users","rules"]}`},
		{name: "keep zero", body: `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":0,"sections":["users","rules"]}`},
		{name: "keep beyond 30", body: `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":31,"sections":["users","rules"]}`},
		{name: "weekly day zero", body: `{"enabled":true,"frequency":"weekly","time":"03:00","day":0,"keep":5,"sections":["users","rules"]}`},
		{name: "weekly day beyond 7", body: `{"enabled":true,"frequency":"weekly","time":"03:00","day":8,"keep":5,"sections":["users","rules"]}`},
		{name: "monthly day zero", body: `{"enabled":true,"frequency":"monthly","time":"03:00","day":0,"keep":5,"sections":["users","rules"]}`},
		{name: "monthly day beyond 28", body: `{"enabled":true,"frequency":"monthly","time":"03:00","day":29,"keep":5,"sections":["users","rules"]}`},
		{name: "unknown section", body: `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":5,"sections":["users","nope"]}`},
		{name: "empty sections", body: `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":5,"sections":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newAutoBackupTestHandlers(t)
			response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", tt.body, h.UpdateAutoBackupSettings)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
		})
	}
	// 自检:合法载荷必须通过(矩阵有效性前提);保留份数上边界 30 必须通过
	// (2026-09-19 追加裁定:上限 100→30)。
	h := newAutoBackupTestHandlers(t)
	if response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", valid, h.UpdateAutoBackupSettings); response.Code != http.StatusOK {
		t.Fatalf("valid payload status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	h2 := newAutoBackupTestHandlers(t)
	boundary := `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":30,"sections":["users","rules"]}`
	if response := serveAutoBackupJSON(t, h2, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", boundary, h2.UpdateAutoBackupSettings); response.Code != http.StatusOK {
		t.Fatalf("keep=30 boundary status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func TestUpdateAutoBackupSettings_commitFailureUsesSharedSeam(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	forceCommitFailure(t)
	body := `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":5,"sections":["users"]}`
	response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", body, h.UpdateAutoBackupSettings)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want injected commit failure 500", response.Code, response.Body.String())
	}
	var keep int
	if err := db.DB.QueryRow(`SELECT auto_backup_keep FROM global_config WHERE id=1`).Scan(&keep); err != nil {
		t.Fatal(err)
	}
	if keep != autoBackupKeepDefault {
		t.Fatalf("提交失败后 keep=%d, want unchanged default %d", keep, autoBackupKeepDefault)
	}
}

// 超 16 KiB 请求体必须按 413 归因：此前 ShouldBindJSON 任一错误统一 400
// 「请求格式不正确」，把体积问题伪装成 JSON 语法问题（与同族端点 413 口径
// 分裂，客户端无法统一按「请求过大」处理）。
func TestUpdateAutoBackupSettings_oversizedBodyReturns413(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	// 填充必须落在 JSON 值内部：尾部空白在解析完对象后不再读取，不会触发
	// 体积上限。
	body := `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":5,"sections":["users"],"pad":"` +
		strings.Repeat("A", 17<<10) + `"}`
	response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", body, h.UpdateAutoBackupSettings)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "16 KiB") {
		t.Fatalf("body=%s, want 点名 16 KiB 上限", response.Body.String())
	}
}

// 「缺少必填字段」文案必须与实际的 nil 判断一致：sections 非指针、缺键即空
// 切片，走独立的「备份范围不能为空」归因——把它写进必填清单会让客户端按文案
// 排查错方向。
func TestUpdateAutoBackupSettings_missingFieldMessagesAttributeCorrectly(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	missingSections := `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":5}`
	response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", missingSections, h.UpdateAutoBackupSettings)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "备份范围不能为空") {
		t.Fatalf("status=%d body=%s, want 400 备份范围不能为空", response.Code, response.Body.String())
	}

	h2 := newAutoBackupTestHandlers(t)
	missingKeep := `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"sections":["users"]}`
	response = serveAutoBackupJSON(t, h2, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", missingKeep, h2.UpdateAutoBackupSettings)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "sections") {
		t.Fatalf("body=%s, 缺少必填字段文案不得把 sections 计入（缺键走另一条归因）", response.Body.String())
	}
}

// 保留份数上限收紧为 30 后,升级前保存的越界存量值(31-100)读侧必须回退
// 安全默认 7——prune 消费回退值,不得沿用越界保留。
func TestLoadAutoBackupKeepSetting_outOfRangeFallsBack(t *testing.T) {
	newAutoBackupTestHandlers(t)
	for _, stored := range []int{0, 31, 50, 100} {
		if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_keep=? WHERE id=1`, stored); err != nil {
			t.Fatal(err)
		}
		if got, known := loadAutoBackupKeepSetting(context.Background()); !known || got != 7 {
			t.Fatalf("stored keep=%d loaded=%d known=%v, want fallback 7 (known)", stored, got, known)
		}
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_keep=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got, known := loadAutoBackupKeepSetting(context.Background()); !known || got != 30 {
		t.Fatalf("stored keep=30 loaded=%d known=%v, want 30 (known)", got, known)
	}
}

// 三分类合并(2026-09-19 用户裁定):legacy sections 键(global_config→users、
// waf_files→security)在保存与读取双侧归一——旧值不再因「仅全局配置」被拒,
// 重存后落库值即收敛为当前分类键（现为 users/rules/security/cluster 四分类）。
func TestUpdateAutoBackupSettings_normalizesLegacySectionKeys(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	body := `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":5,"sections":["global_config","waf_files","rules","users"]}`

	response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", body, h.UpdateAutoBackupSettings)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy sections payload must save, got %d %s", response.Code, response.Body.String())
	}
	var sections string
	if err := db.DB.QueryRow(`SELECT auto_backup_sections FROM global_config WHERE id=1`).Scan(&sections); err != nil {
		t.Fatal(err)
	}
	if sections != `["users","security","rules"]` {
		t.Fatalf("stored sections=%s, want [\"users\",\"security\",\"rules\"] (deduped, order preserved)", sections)
	}
}

// 存量行旧 JSON(升级前保存的 5 键)读出即归一——调度器/导出器消费的是当前
// 分类口径,无需迁移存量行。
func TestLoadAutoBackupSectionsSetting_normalizesLegacyKeys(t *testing.T) {
	newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_sections='["users","global_config","rules","waf_files","security"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	got, err := loadAutoBackupSectionsSetting(context.Background())
	if err != nil {
		t.Fatalf("load legacy sections: %v", err)
	}
	want := []string{"users", "rules", "security"}
	if len(got) != len(want) {
		t.Fatalf("loaded sections=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("loaded sections=%v, want %v", got, want)
		}
	}
}

func TestRunAutoBackupOnce_rejectsDamagedSections(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_sections='{broken' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	_, err := h.RunAutoBackupOnce(context.Background(), "manual", "tester", 1)

	if err == nil || !strings.Contains(err.Error(), "备份范围") {
		t.Fatalf("RunAutoBackupOnce err=%v, want damaged-sections error", err)
	}
	var failed, succeeded int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='failed' AND message LIKE '%备份范围%'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='success'`).Scan(&succeeded); err != nil {
		t.Fatal(err)
	}
	if failed != 1 || succeeded != 0 {
		t.Fatalf("backup rows failed=%d success=%d, want 1/0", failed, succeeded)
	}
	if countAutoBackupAudit(t, "备份失败") == 0 {
		t.Fatal("damaged sections must leave a failure audit")
	}
}

func TestRunAutoBackupOnce_reportsSectionsReadFailure(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`DROP TABLE global_config`); err != nil {
		t.Fatal(err)
	}

	_, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1)

	if err == nil || !strings.Contains(err.Error(), "读取备份范围") {
		t.Fatalf("RunAutoBackupOnce err=%v, want sections read failure", err)
	}
}

// Given 引擎在「读取备份范围」窗口取消（角色降级/停止）。
// When RunAutoBackupOnce 返回。
// Then 按取消返回（context.Canceled），零 failed 行、零「备份失败」审计、零文件
// ——读取阶段与构建/写盘的取消口径必须同形，取消不是备份失败。
func TestRunAutoBackupOnce_cancelDuringSectionsReadLeavesNoFailedRowOrAudit(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	failedAuditsBefore := countAutoBackupAudit(t, "备份失败")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	previousHook := autoBackupBeforeSectionsReadHook
	autoBackupBeforeSectionsReadHook = func() { cancel() }
	t.Cleanup(func() { autoBackupBeforeSectionsReadHook = previousHook })

	_, err := h.RunAutoBackupOnce(ctx, "manual", "admin", 1)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled（读取阶段取消按取消返回）", err)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("auto_backups rows=%d, want 0（取消不得落 failed 行）", rows)
	}
	if got := countAutoBackupAudit(t, "备份失败"); got != failedAuditsBefore {
		t.Fatalf("备份失败审计 %d→%d，取消不得记备份失败", failedAuditsBefore, got)
	}
	entries, readErr := os.ReadDir(h.cfg.BackupDir)
	if readErr != nil {
		t.Fatalf("read backup dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("备份目录残留 %d 个文件，取消不得留下任何文件", len(entries))
	}
}

// Given 备份表被写坏到超过列表窗口（1 条 success 在最旧 + 250 条更新 failed）。
// When 读设置端点。
// Then 列表不超过窗口上限并标记 truncated，且 last_success_at 仍取真实最近
// success 行（不得因窗口截断而误报 null）。
func TestAutoBackupSettings_limitsListAndKeepsLastSuccessBeyondWindow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	const successCreatedAt = "2026-01-01 00:00:00"
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename,status,size_bytes,sections,trigger_type,message,app_version,created_at)
		VALUES ('old-success.lbbak','success',1,'[]','manual','','','` + successCreatedAt + `')`); err != nil {
		t.Fatalf("seed success row: %v", err)
	}
	for i := range 250 {
		if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename,status,size_bytes,sections,trigger_type,message,app_version,created_at)
			VALUES (?, 'failed', 0, '[]', 'schedule', '模拟失败', '', ?)`,
			fmt.Sprintf("failed-%03d.lbbak", i), fmt.Sprintf("2026-02-01 00:00:%02d", i%60)); err != nil {
			t.Fatalf("seed failed row %d: %v", i, err)
		}
	}

	response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			Backups          []json.RawMessage `json:"backups"`
			BackupsTruncated bool              `json:"backups_truncated"`
			LastSuccessAt    *string           `json:"last_success_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, response.Body.String())
	}
	if len(body.Data.Backups) != autoBackupListLimit {
		t.Fatalf("backups=%d, want %d（列表必须按窗口上限截断）", len(body.Data.Backups), autoBackupListLimit)
	}
	if !body.Data.BackupsTruncated {
		t.Fatal("backups_truncated=false，超窗口时必须显式标记截断")
	}
	if body.Data.LastSuccessAt == nil {
		t.Fatal("last_success_at=null，want 最近一次 success 行（不得因列表截断误报 null）")
	}
	if *body.Data.LastSuccessAt != successCreatedAt {
		t.Fatalf("last_success_at=%q, want %q", *body.Data.LastSuccessAt, successCreatedAt)
	}
}

func TestUpdateAutoBackupSettings_enableSetsWatermarkNotImmediateRun(t *testing.T) {
	// 2026-09-19 用户裁定:启用不得立即触发补跑——off→on 置水位线(=now),
	// 下一次执行=启用后的下一个到期槽;仅手动触发/停机跨槽补跑属预期。
	h := newAutoBackupTestHandlers(t)
	// Given: 既有陈旧 last_run + 关闭态
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=0, auto_backup_last_run='2026-08-01T03:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Minute)
	body := `{"enabled":true,"frequency":"monthly","time":"01:15","day":9,"keep":12,"sections":["users","global_config","rules","waf_files","security"]}`

	// When
	response := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", body, h.UpdateAutoBackupSettings)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var enabled bool
	var freq, hhmm string
	var day, keep int
	var sections string
	var lastRun *string
	if err := db.DB.QueryRow(`SELECT auto_backup_enabled, auto_backup_frequency, auto_backup_time, auto_backup_day, auto_backup_keep, auto_backup_sections, auto_backup_last_run FROM global_config WHERE id=1`).
		Scan(&enabled, &freq, &hhmm, &day, &keep, &sections, &lastRun); err != nil {
		t.Fatal(err)
	}
	if !enabled || freq != "monthly" || hhmm != "01:15" || day != 9 || keep != 12 {
		t.Fatalf("saved=(%v,%s,%s,%d,%d), want (true,monthly,01:15,9,12)", enabled, freq, hhmm, day, keep)
	}
	if !strings.Contains(sections, `"rules"`) || strings.Contains(sections, `"nope"`) {
		t.Fatalf("sections=%q", sections)
	}
	if lastRun == nil {
		t.Fatal("off→on 必须置水位线(last_run=now), got NULL")
	}
	watermark, err := time.Parse(time.RFC3339, *lastRun)
	if err != nil {
		t.Fatalf("last_run 非 RFC3339 形态 %q: %v", *lastRun, err)
	}
	if watermark.Before(before) {
		t.Fatalf("水位线 %v 早于测试开始 %v(不得回补启用前的旧槽)", watermark, before)
	}
}

func TestUpdateAutoBackupSettings_businessToggleSyncsEngineLoop(t *testing.T) {
	// Given：引擎以业务关闭态启动，auto-backup 调度同步关闭。
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	wireAutoBackupEngineForTest(t, h)
	te := services.TaskEngine()
	loopOn := func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "auto-backup" {
				return meta.LoopOn
			}
		}
		t.Fatal("auto-backup 未注册")
		return false
	}
	if loopOn() {
		t.Fatal("前置态错误：业务关闭时调度应关闭")
	}

	// When：经设置页启用，再经设置页关闭。
	enable := `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":7,"sections":["users","rules","security"]}`
	if resp := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", enable, h.UpdateAutoBackupSettings); resp.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", resp.Code, resp.Body.String())
	}
	// Then：off→on 立即 StartLoop，不需要重启。
	if !loopOn() {
		t.Error("设置页启用后 auto-backup LoopOn=false，定时备份将无法运行")
	}
	disable := `{"enabled":false,"frequency":"daily","time":"03:00","day":1,"keep":7,"sections":["users","rules","security"]}`
	if resp := serveAutoBackupJSON(t, h, http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", disable, h.UpdateAutoBackupSettings); resp.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", resp.Code, resp.Body.String())
	}
	// And：on→off 立即 StopLoop，展示与业务实态一致。
	if loopOn() {
		t.Error("设置页关闭后 auto-backup LoopOn=true，调度展示与业务实态分叉")
	}
}

func TestAutoBackupSettings_returnsSettingsAndRowsDesc(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	// Given: 两行备份(created_at 递增)
	for i := 1; i <= 2; i++ {
		if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, trigger_type) VALUES (?, datetime('2026-09-0'+?+' 03:00:00'), 'success', 'schedule')`, fmt.Sprintf("lbbak-auto-list%d.lbbak", i), string(rune('0'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='weekly', auto_backup_time='04:30', auto_backup_day=6, auto_backup_keep=9 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			Enabled   bool     `json:"enabled"`
			Frequency string   `json:"frequency"`
			Time      string   `json:"time"`
			Day       int      `json:"day"`
			Keep      int      `json:"keep"`
			Sections  []string `json:"sections"`
			Backups   []struct {
				Filename string `json:"filename"`
				Status   string `json:"status"`
			} `json:"backups"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	d := payload.Data
	if !d.Enabled || d.Frequency != "weekly" || d.Time != "04:30" || d.Day != 6 || d.Keep != 9 || len(d.Sections) != 4 {
		t.Fatalf("settings=(%v,%s,%s,%d,%d,%v)", d.Enabled, d.Frequency, d.Time, d.Day, d.Keep, d.Sections)
	}
	if len(d.Backups) != 2 || d.Backups[0].Filename != "lbbak-auto-list2.lbbak" {
		t.Fatalf("backups=%+v, want DESC 顺序且最新在前", d.Backups)
	}
}

// GET /settings/auto-backup 的 last_run 此前恒 null——
// auto_backup_last_run 扫描进 sql.NullString 后零消费（lastRunValue 零赋值）。
// 钉：库中有水位线时响应面回传同值；库中 NULL 时保持 null 形态（不写空串）。
func TestAutoBackupSettings_returnsLastRun(t *testing.T) {
	// Given: 库中既有水位线（off→on 或调度执行写入，RFC3339 形态）
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run='2026-10-01T03:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)

	// Then: DB 终态与响应面一致
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var stored *string
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == nil || *stored != "2026-10-01T03:00:00Z" {
		t.Fatalf("DB last_run=%v, want 2026-10-01T03:00:00Z", stored)
	}
	var payload struct {
		Data struct {
			LastRun *string `json:"last_run"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.LastRun == nil || *payload.Data.LastRun != *stored {
		t.Fatalf("last_run=%v, want 库中水位线值 %q", payload.Data.LastRun, *stored)
	}

	// And: 库中 NULL 时响应保持 null 形态（不写空串）
	h2 := newAutoBackupTestHandlers(t)
	response2 := serveAutoBackupJSON(t, h2, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h2.AutoBackupSettings)
	if response2.Code != http.StatusOK {
		t.Fatalf("null-form status=%d body=%s", response2.Code, response2.Body.String())
	}
	if !strings.Contains(response2.Body.String(), `"last_run":null`) {
		t.Fatalf("body=%s, want last_run null 形态", response2.Body.String())
	}
}

func TestRunAutoBackupNow_endpointRunsAndRespondsRow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	wireAutoBackupEngineForTest(t, h)
	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/run", "/auto-backup/run", "", h.RunAutoBackupNow)
	// 异步接受（202）+ 后台执行，结果落 auto_backups。
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s, want 202", response.Code, response.Body.String())
	}
	var filename, status string
	waitForAutoBackupCondition(t, 10*time.Second, func() bool {
		err := db.DB.QueryRow(`SELECT filename, status FROM auto_backups WHERE trigger_type='manual' ORDER BY id DESC LIMIT 1`).Scan(&filename, &status)
		return err == nil && status == "success"
	})
	if !strings.HasPrefix(filename, "lbbak-manual-") {
		t.Fatalf("filename=%q, want lbbak-manual- 前缀", filename)
	}
	waitForAutoBackupCondition(t, 5*time.Second, func() bool { return countAutoBackupAudit(t, "手动备份") == 1 })
}

func TestDeleteAutoBackup_removesFileAndRow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-del.lbbak"
	path := filepath.Join(h.cfg.BackupDir, name)
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	// When
	response := serveAutoBackupJSON(t, h, http.MethodDelete, "/auto-backup/:id", fmt.Sprintf("/auto-backup/%d", id), "", h.DeleteAutoBackup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("备份文件应随行删除: %v", err)
	}
	if rows := autoBackupRows(t, "WHERE id=?", id); len(rows) != 0 {
		t.Fatalf("行未删除: %v", rows)
	}
	if got := countAutoBackupAudit(t, "备份删除"); got != 1 {
		t.Fatalf("备份删除 audit rows=%d, want 1", got)
	}
	// 不存在 id → 404
	if response := serveAutoBackupJSON(t, h, http.MethodDelete, "/auto-backup/:id", "/auto-backup/999", "", h.DeleteAutoBackup); response.Code != http.StatusNotFound {
		t.Fatalf("missing id status=%d, want 404", response.Code)
	}
}

func TestDeleteAutoBackup_fileFailureKeepsRowAndWithholdsSuccessAudit(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-delete-blocked.lbbak"
	path := filepath.Join(h.cfg.BackupDir, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "child"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	response := serveAutoBackupJSON(t, h, http.MethodDelete, "/auto-backup/:id", fmt.Sprintf("/auto-backup/%d", id), "", h.DeleteAutoBackup)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（文件删除失败不得报成功）", response.Code, response.Body.String())
	}
	if rows := autoBackupRows(t, "WHERE id=?", id); len(rows) != 1 {
		t.Fatalf("文件删除失败后行必须保留供重试: %v", rows)
	}
	if got := countAutoBackupAudit(t, "备份删除"); got != 0 {
		t.Fatalf("失败路径成功审计=%d, want 0", got)
	}
	// 失败面必须留痕：删除族与还原/下载同口径，单个失败分支恰一条「删除失败」，
	// detail 携带备份 id 与文件名供按文件复盘。
	if got := countAutoBackupAudit(t, "删除失败"); got != 1 {
		t.Fatalf("删除失败审计=%d, want 1（失败分支必须经 failAutoBackupAccess 留痕）", got)
	}
	detail := autoBackupAuditDetail(t, "删除失败")
	for _, want := range []string{fmt.Sprintf("#%d", id), name} {
		if !strings.Contains(detail, want) {
			t.Fatalf("删除失败 detail=%q, want 含 %q", detail, want)
		}
	}
}

func TestDeleteAutoBackup_missingFileStillRemovesRow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-already-missing.lbbak"
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	response := serveAutoBackupJSON(t, h, http.MethodDelete, "/auto-backup/:id", fmt.Sprintf("/auto-backup/%d", id), "", h.DeleteAutoBackup)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（ErrNotExist 应容忍）", response.Code, response.Body.String())
	}
	if rows := autoBackupRows(t, "WHERE id=?", id); len(rows) != 0 {
		t.Fatalf("文件已缺失时行仍应删除: %v", rows)
	}
	if got := countAutoBackupAudit(t, "备份删除"); got != 1 {
		t.Fatalf("成功审计=%d, want 1", got)
	}
}

func TestDeleteAutoBackup_dbFailureReturns500(t *testing.T) {
	// Given 主节点 + auto_backups 表不可用（DB 故障形态）——
	// DB 故障与「备份不存在」不得混同为 404（排障方向误导）；ErrNoRows 404、
	// 其余响亮 500（dbQueryNotFound 分判，与 GetCurrentUser/requireAutoBackupMaster
	// 已立先例同口径）。
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec("DROP TABLE auto_backups"); err != nil {
		t.Fatalf("drop auto_backups: %v", err)
	}

	// When
	response := serveAutoBackupJSON(t, h, http.MethodDelete, "/auto-backup/:id", "/auto-backup/1", "", h.DeleteAutoBackup)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（DB 故障不得误报 404）", response.Code, response.Body.String())
	}
}

func TestDownloadAutoBackup_returnsFileBytesAndAudits(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-dl.lbbak"
	content := []byte("fake-lbbak-bytes")
	if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	// When
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/auto-backup/:id/download", fmt.Sprintf("/auto-backup/%d/download", id), "", h.DownloadAutoBackup)

	// Then: 字节与磁盘一致 + 审计
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Body.String() != string(content) {
		t.Fatalf("download bytes mismatch: %q", response.Body.String())
	}
	if got := countAutoBackupAudit(t, "备份下载"); got != 1 {
		t.Fatalf("备份下载 audit rows=%d, want 1", got)
	}
}

func TestDownloadAutoBackup_rejectsPathEscapeFilename(t *testing.T) {
	// Given: 行内文件名被带外改写为路径逃逸形态(深度防御——文件操作必须限定
	// 备份目录内)
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES ('../evil.lbbak', 'success', 'manual')`); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM auto_backups WHERE filename='../evil.lbbak'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// When/Then
	for _, tc := range []struct {
		method  string
		suffix  string
		handler gin.HandlerFunc
	}{
		{http.MethodGet, "/download", h.DownloadAutoBackup},
		{http.MethodDelete, "", h.DeleteAutoBackup},
		{http.MethodPost, "/restore", h.RestoreAutoBackup},
	} {
		path := fmt.Sprintf("/auto-backup/%d%s", id, tc.suffix)
		route := map[string]string{"": "/auto-backup/:id", "/download": "/auto-backup/:id/download", "/restore": "/auto-backup/:id/restore"}[tc.suffix]
		response := serveAutoBackupJSON(t, h, tc.method, route, path, "", tc.handler)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s %s status=%d, want 400(路径逃逸拒绝)", tc.method, path, response.Code)
		}
	}
	// 磁盘上级目录不应出现 evil.lbbak
	if _, err := os.Stat(filepath.Join(h.cfg.BackupDir, "..", "evil.lbbak")); err == nil {
		t.Fatal("路径逃逸文件被创建")
	}
}

func TestRestoreAutoBackup_restoresBackedUpState(t *testing.T) {
	// Given: 一条规则 + 手动备份;备份后删除规则
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_restore','restore-rule','http','restore.example.test',8080,1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_restore','127.0.0.1',9000,1,1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1); err != nil {
		t.Fatalf("run backup: %v", err)
	}
	var id int64
	var filename string
	if err := db.DB.QueryRow(`SELECT id, filename FROM auto_backups WHERE status='success' ORDER BY id DESC LIMIT 1`).Scan(&id, &filename); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_restore'`); err != nil {
		t.Fatal(err)
	}
	var ruleCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_restore'`).Scan(&ruleCount); err != nil {
		t.Fatal(err)
	}

	// When
	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/:id/restore", fmt.Sprintf("/auto-backup/%d/restore", id), "", h.RestoreAutoBackup)

	// Then: 200 + 规则回归 + 还原审计
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_restore'`).Scan(&ruleCount); err != nil {
		t.Fatal(err)
	}
	if ruleCount != 1 {
		t.Fatalf("restore 后规则数=%d, want 1", ruleCount)
	}
	if got := countAutoBackupAudit(t, "还原"); got < 1 {
		t.Fatalf("还原 audit rows=%d, want ≥1", got)
	}
}

func TestRestoreAutoBackup_missingFileReturns404(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES ('lbbak-manual-gone.lbbak', 'success', 'manual')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/:id/restore", fmt.Sprintf("/auto-backup/%d/restore", id), "", h.RestoreAutoBackup)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404(文件缺失)", response.Code, response.Body.String())
	}
}

func TestAutoBackupEndpoints_rejectSlaveNode(t *testing.T) {
	// 从节点镜像 ExportConfigBackup 的 IsMaster 门——全部端点 403
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	endpoints := []struct {
		method  string
		route   string
		path    string
		handler gin.HandlerFunc
	}{
		{http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", h.AutoBackupSettings},
		{http.MethodPut, "/settings/auto-backup", "/settings/auto-backup", h.UpdateAutoBackupSettings},
		{http.MethodPost, "/auto-backup/run", "/auto-backup/run", h.RunAutoBackupNow},
		{http.MethodDelete, "/auto-backup/:id", "/auto-backup/1", h.DeleteAutoBackup},
		{http.MethodGet, "/auto-backup/:id/download", "/auto-backup/1/download", h.DownloadAutoBackup},
		{http.MethodPost, "/auto-backup/:id/restore", "/auto-backup/1/restore", h.RestoreAutoBackup},
	}
	for _, ep := range endpoints {
		response := serveAutoBackupJSON(t, h, ep.method, ep.route, ep.path, `{}`, ep.handler)
		var api models.APIResponse
		_ = json.Unmarshal(response.Body.Bytes(), &api)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d, want 403", ep.method, ep.path, response.Code)
		}
	}
}

func TestRunAutoBackupOnce_concurrentRunRejected(t *testing.T) {
	// TryLock 并发守卫:执行中再次触发直接报错,不排队
	h := newAutoBackupTestHandlers(t)
	services.SetAutoBackupExecutor(func(ctx context.Context, trigger, operator string, engineRunID int64) error {
		_, err := h.RunAutoBackupOnce(ctx, trigger, operator, engineRunID)
		return err
	})
	t.Cleanup(func() { services.SetAutoBackupExecutor(nil) })
	if !autoBackupRunMu.TryLock() {
		t.Fatal("前置锁定失败")
	}
	_, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1)
	autoBackupRunMu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "正在执行") {
		t.Fatalf("err=%v, want 已有任务执行中报错", err)
	}
}

// RunAutoBackupOnce 成功落行后必须接线内务裁剪——
// keep=1 时连续两次执行仅保留最新 1 个 success(文件+行同删);failed 行按
// autoBackupFailedRowsKeep=20 上限保留(前端文案「失败记录另保留最近 20 条」)。
func TestRunAutoBackupOnce_prunesToKeepSetting(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	dir := h.cfg.BackupDir
	if _, err := db.DB.Exec("UPDATE global_config SET auto_backup_keep=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	// Given: 21 条 failed 存量(无文件,裁剪容忍文件缺失)
	for i := range 21 {
		if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, trigger_type, message) VALUES (?, datetime('now', ?), 'failed', 'schedule', 'x')`, fmt.Sprintf("lbbak-auto-stale-fail%d.lbbak", i), fmt.Sprintf("-%d minutes", i+1)); err != nil {
			t.Fatal(err)
		}
	}

	// When: keep=1 下连跑两次(同秒冲突由文件名 -2 后缀消化)
	firstRun, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	secondRun, err := h.RunAutoBackupOnce(context.Background(), "schedule", "system", 1)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if firstRun.Filename == "" || secondRun.Filename == "" {
		t.Fatalf("filename 缺失: first=%q second=%q", firstRun.Filename, secondRun.Filename)
	}

	// Then: 仅最新 1 个 success 行与文件幸存
	rows := autoBackupRows(t, "WHERE status='success' ORDER BY created_at DESC, id DESC")
	if len(rows) != 1 {
		t.Fatalf("success rows=%d, want 1(keep=1 裁剪后仅留最新)", len(rows))
	}
	survivor := rows[0]["filename"].(string)
	matches, err := filepath.Glob(filepath.Join(dir, "lbbak-auto-*.lbbak"))
	if err != nil || len(matches) != 1 || filepath.Base(matches[0]) != survivor {
		t.Fatalf("success files=%v err=%v, want exactly survivor %s", matches, err, survivor)
	}
	// 幸存者必须是「第二次执行」产出的那个文件，而不是较旧的首轮。
	// 不钉 "-2" 后缀：两轮是否落在同一秒取决于运行机器负载（全量包测试下
	// 跨秒是常态），按后缀断言会变成时间相关的假红；这里按执行序等价判定。
	if survivor != secondRun.Filename {
		t.Fatalf("keep=1 幸存者=%q, want 第二次执行产出 %q（首轮为 %q）", survivor, secondRun.Filename, firstRun.Filename)
	}
	if survivor == firstRun.Filename {
		t.Fatalf("keep=1 幸存者回落到首轮文件 %q（应保留最新一次）", survivor)
	}
	// failed 行按 20 上限一并裁剪
	var failed int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='failed'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 20 {
		t.Fatalf("failed rows=%d, want 20(autoBackupFailedRowsKeep)", failed)
	}
	var newestFailed, oldestFailed int
	if err := db.DB.QueryRow(`SELECT
		(SELECT COUNT(*) FROM auto_backups WHERE filename='lbbak-auto-stale-fail0.lbbak'),
		(SELECT COUNT(*) FROM auto_backups WHERE filename='lbbak-auto-stale-fail20.lbbak')`).Scan(&newestFailed, &oldestFailed); err != nil {
		t.Fatal(err)
	}
	if newestFailed != 1 || oldestFailed != 0 {
		t.Fatalf("failed 裁剪方向错误：最新 fail0=%d 最旧 fail20=%d, want 1/0", newestFailed, oldestFailed)
	}
}

// 裁剪时文件删除失败(非 ErrNotExist)必须保留 DB 行
// 下轮重试——此前行随 warn 一并删除,残留文件成孤儿永不再裁剪。
func TestPruneAutoBackups_fileRemovalOutcomes(t *testing.T) {
	// Given:三个 success 行——同名非空目录(Remove 返回 ENOTEMPTY)/文件缺失/
	// 正常文件,keep=0 全部进入裁剪
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	dir := t.TempDir()
	const blocked, missing, normal = "lbbak-manual-20260919-000001.lbbak", "lbbak-manual-20260919-000002.lbbak", "lbbak-manual-20260919-000003.lbbak"
	if err := os.MkdirAll(filepath.Join(dir, blocked), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, blocked, "keep.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, normal), []byte("backup"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{blocked, missing, normal} {
		if _, err := insertAutoBackupRow(context.Background(), filename, "success", 128, `["users"]`, "manual", "", "v9.9.9-test"); err != nil {
			t.Fatal(err)
		}
	}

	// When
	pruneAutoBackups(context.Background(), dir, 0, 20)

	// Then:删除失败的行保留下轮重试;缺失/正常删除的行照常清除
	if rows := autoBackupRows(t, "WHERE filename=?", blocked); len(rows) != 1 {
		t.Fatalf("blocked rows=%d, want 1(文件删除失败的行必须保留)", len(rows))
	}
	if rows := autoBackupRows(t, "WHERE filename=?", missing); len(rows) != 0 {
		t.Fatalf("missing rows=%d, want 0(文件缺失容忍删行)", len(rows))
	}
	if rows := autoBackupRows(t, "WHERE filename=?", normal); len(rows) != 0 {
		t.Fatalf("normal rows=%d, want 0(文件删除成功照常删行)", len(rows))
	}
}

// 用户反馈(2026-09-20):手动触发自动备份的审计操作人恒为 system——手动触发
// 应记当前登录用户,仅调度触发记 system(RunAutoBackupOnce 增操作者参数)。
func TestRunAutoBackupNow_auditOperatorIsCurrentUser(t *testing.T) {
	// Given: 主节点 + 已登录用户 operator-zhang
	h := newAutoBackupTestHandlers(t)
	wireAutoBackupEngineForTest(t, h)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auto-backup/run", func(c *gin.Context) {
		c.Set("username", "operator-zhang")
		h.RunAutoBackupNow(c)
	})

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auto-backup/run", nil)
	router.ServeHTTP(response, request)

	// Then: 202 接受且后台完成后「手动备份」审计行操作人为 operator-zhang
	// （修复前恒 system；自此响应先返回，审计行需等待后台执行）。
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s, want 202", response.Code, response.Body.String())
	}
	var username string
	waitForAutoBackupCondition(t, 10*time.Second, func() bool {
		return db.AuditDB.QueryRow(`SELECT username FROM audit_log WHERE action='手动备份' ORDER BY id DESC LIMIT 1`).Scan(&username) == nil
	})
	if username != "operator-zhang" {
		t.Fatalf("手动备份 audit username=%q, want operator-zhang(调度路径才记 system)", username)
	}
}

// Given 全局引擎被前一用例停成「已停止但非 nil」（只停实例、未清全局指针）。
// When 装配自动备份执行器并调用 /auto-backup/run。
// Then 装配必须重建引擎并受理（202）——判据只判 nil 时端点回 503
// 「任务引擎已停止」，全包运行结果随测试顺序变化。
func TestWireAutoBackupEngineForTest_replacesStoppedEngine(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	services.InitTaskEngine("", t.TempDir()+"/app.log").Stop()
	if te := services.TaskEngine(); te == nil || !te.IsStopped() {
		t.Fatal("前置态不成立：全局引擎应为 stopped 非 nil")
	}
	wireAutoBackupEngineForTest(t, h)
	if te := services.TaskEngine(); te == nil || te.IsStopped() {
		t.Fatal("装配必须替换已停止的全局引擎（否则 TriggerTaskAsync 恒 ErrEngineStopped）")
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auto-backup/run", h.RunAutoBackupNow)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/auto-backup/run", nil))
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s, want 202（不得沿用已停止引擎）", response.Code, response.Body.String())
	}
}

// 备份目录含私钥/凭证明文文件，目录权限必须 0700
// （MkdirAll 建目录时生效；指向已存在目录时为 no-op，故指向不存在的子目录）。
func TestRunAutoBackupOnce_backupDirPerm0700(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	h.cfg.BackupDir = filepath.Join(t.TempDir(), "backup-nested")

	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 1); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}
	info, err := os.Stat(h.cfg.BackupDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("backup dir perm=%o, want 700（目录内容含私钥与凭证明文）", perm)
	}
}

// backupListFailingConnector：global_config 设置行查询成功返回缺省值，
// auto_backups 列表查询「语句成功、迭代即失败」——注入 AutoBackupSettings
// 备份列表循环的 rows.Err() 故障。
type backupListFailingConnector struct{}

func (backupListFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return backupListFailingConn{}, nil
}

func (backupListFailingConnector) Driver() driver.Driver { return backupListFailingDriver{} }

type backupListFailingDriver struct{}

func (backupListFailingDriver) Open(string) (driver.Conn, error) {
	return backupListFailingConn{}, nil
}

type backupListFailingConn struct{}

func (backupListFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (backupListFailingConn) Close() error { return nil }

func (backupListFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (backupListFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "FROM global_config"):
		return &backupSettingsRow{}, nil
	case strings.Contains(query, "FROM auto_backups"):
		return backupFailingIterRows{}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
}

type backupSettingsRow struct{ done bool }

func (r *backupSettingsRow) Columns() []string {
	return []string{"enabled", "frequency", "time", "day", "keep", "sections", "last_run", "last_success_at"}
}

func (r *backupSettingsRow) Close() error { return nil }

func (r *backupSettingsRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	row := []driver.Value{int64(0), "daily", "03:00", int64(1), int64(7), nil, nil, nil}
	copy(dest, row)
	return nil
}

type backupFailingIterRows struct{}

func (backupFailingIterRows) Columns() []string {
	return []string{"id", "filename", "created_at", "status", "size_bytes", "sections", "trigger_type", "message", "app_version"}
}

func (backupFailingIterRows) Close() error { return nil }

func (backupFailingIterRows) Next([]driver.Value) error {
	return errors.New("注入的备份列表迭代失败")
}

func TestAutoBackupSettings_backupListIterationFailureReturns500(t *testing.T) {
	// Given：设置行可读、备份列表迭代失败（语句成功、迭代即败）
	h := newBackupTestHandlers(t)
	broken := sql.OpenDB(backupListFailingConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.DB
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	router := gin.New()
	router.GET("/settings/auto-backup", h.AutoBackupSettings)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/settings/auto-backup", nil))

	// Then：迭代错误显式 500（修复前部分列表 + 200 掩盖存储故障）
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取备份列表失败") {
		t.Fatalf("body=%s, want explicit backup-list failure message", response.Body.String())
	}
}

// 手动触发必须异步——慢备份（>60s 桩）不阻塞响应；
// 双击/并发触发 409。修复前同步 RunSync 在 main.go WriteTimeout(60s) 下
// 会被截断客户端连接，且第二个请求排队等待。
func TestRunAutoBackupNow_asyncReturnsBeforeSlowBackupCompletes(t *testing.T) {
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

	begin := time.Now()
	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/run", "/auto-backup/run", "", h.RunAutoBackupNow)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s, want 202", response.Code, response.Body.String())
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("慢备份不得阻塞响应, elapsed=%s", elapsed)
	}

	// 后台任务已启动（引擎 Run 进入桩）。
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("后台备份未启动")
	}

	// 双击：执行中再次触发 → 409（不排队）。
	second := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/run", "/auto-backup/run", "", h.RunAutoBackupNow)
	if second.Code != http.StatusConflict {
		close(release)
		t.Fatalf("second status=%d body=%s, want 409", second.Code, second.Body.String())
	}

	close(release)
	var status string
	waitForAutoBackupCondition(t, 10*time.Second, func() bool {
		return db.DB.QueryRow(`SELECT status FROM task_runs WHERE task_id='auto-backup' AND trigger='manual' ORDER BY id DESC LIMIT 1`).Scan(&status) == nil && status == "success"
	})
}

// 非 NotExist 的 Stat 故障不得被文件名分配器吞掉。
func TestNextAutoBackupFilename_statFailureIsNotAvailable(t *testing.T) {
	// Given 一个普通文件冒充备份目录；Stat 其子路径返回 ENOTDIR，而非
	// ErrNotExist。该故障不得被当作「文件名可用」继续走到后续 Rename。
	newAutoBackupTestHandlers(t)
	notDirectory := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(notDirectory, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)

	// When/Then 非 NotExist 的 Stat 错误必须 fail-visible。
	if _, err := nextAutoBackupFilename(context.Background(), notDirectory, "auto", now); err == nil || !strings.Contains(err.Error(), "检查备份文件名") {
		t.Fatalf("err=%v, want explicit stat failure", err)
	}
}

// 文件名分配器在 200 个变体全冲突时必须报错，
// 不得回退到基础名（可能已存在）——否则写盘会覆盖既有备份。
func TestNextAutoBackupFilename_errorsWhenAllVariantsTaken(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)
	base := "lbbak-auto-" + now.Format("20060102-150405")

	name, err := nextAutoBackupFilename(context.Background(), h.cfg.BackupDir, "auto", now)
	if err != nil {
		t.Fatalf("empty dir must allocate: %v", err)
	}
	if name != base+".lbbak" {
		t.Fatalf("name=%q, want %q", name, base+".lbbak")
	}

	for i := 0; i < 200; i++ {
		candidate := base + ".lbbak"
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d.lbbak", base, i+1)
		}
		if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, candidate), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := nextAutoBackupFilename(context.Background(), h.cfg.BackupDir, "auto", now); err == nil {
		t.Fatal("exhausted variants must return error instead of reusing an existing name")
	}
}

func TestNextAutoBackupFilename_skipsFilenameReservedByDatabaseRow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)
	base := "lbbak-auto-" + now.Format("20060102-150405")
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename,status,trigger_type) VALUES (?,'success','schedule')`, base+".lbbak"); err != nil {
		t.Fatal(err)
	}
	name, err := nextAutoBackupFilename(context.Background(), h.cfg.BackupDir, "auto", now)
	if err != nil {
		t.Fatal(err)
	}
	if name != base+"-2.lbbak" {
		t.Fatalf("DB 行已占名但文件缺失时 name=%q, want %q（不得让两行共享一份文件）", name, base+"-2.lbbak")
	}
}

// 注释承诺「取消不落 failed 行」，但写盘阶段
// （services.WriteAutoBackupFileSynced 无 ctx）出错时直接走 fail() —— 取消 +
// 写盘错误同时发生会落 failed 行与「备份失败」审计，而 task_runs 记 cancelled。
// 写盘错误归一 helper：ctx 已取消时必须按取消返回（与 同口径）。
func TestWriteAutoBackupPayload_canceledContextReturnsCancelError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "missing-subdir", "x.lbbak")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeAutoBackupPayload(ctx, target, []byte("payload")); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消态写盘错误=%v, want context.Canceled（不得落入 failed 行/失败审计）", err)
	}

	// 未取消时同一写盘错误必须原样上抛（错误归一不得吞掉真实磁盘故障）。
	if err := writeAutoBackupPayload(context.Background(), target, []byte("payload")); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("未取消写盘错误=%v, want 真实写盘错误（非取消）", err)
	}
}

// 行内 sections 损坏必须在列表披露：静默退化为空数组会把「范围未知」展示成
// 「该备份不含任何分类」（与设置读侧对同一列显式报错的口径分叉）。
func TestAutoBackupSettings_disclosesCorruptedRowSections(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type, sections) VALUES ('lbbak-corrupt.lbbak','success','schedule','{not-json')`); err != nil {
		t.Fatalf("seed corrupted row: %v", err)
	}

	response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			Backups []struct {
				Filename      string   `json:"filename"`
				Sections      []string `json:"sections"`
				SectionsError string   `json:"sections_error"`
			} `json:"backups"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Data.Backups) != 1 || payload.Data.Backups[0].Filename != "lbbak-corrupt.lbbak" {
		t.Fatalf("backups=%+v, want 仅损坏行", payload.Data.Backups)
	}
	row := payload.Data.Backups[0]
	if row.SectionsError == "" {
		t.Fatal("损坏的 sections 必须披露 sections_error（不得静默为空数组）")
	}
	if len(row.Sections) != 0 {
		t.Fatalf("sections=%v, want 空数组（键集沿用）", row.Sections)
	}
}

// 还原/下载/删除三端点在 BackupDir 为相对路径时必须 fail-fast 500 且不产生任何
// 文件操作（此前它们直接 filepath.Join —— 相对目录会在进程 CWD 下解析同名
// 文件，误删/误读非备份目录文件；写路径已有同口径入口守卫）。
func TestAutoBackupFileEndpoints_rejectRelativeBackupDir(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-relative.lbbak"
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	// CWD 下放一个同名文件：守卫失效时删除端点会把它删掉。
	cwdFile, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cwdFile, name)
	if err := os.WriteFile(target, []byte("must-survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(target) })
	h.cfg.BackupDir = "relative-backup-dir"

	cases := []struct {
		name   string
		method string
		route  string
		path   string
		serve  func(*gin.Context)
	}{
		{"还原", http.MethodPost, "/auto-backup/:id/restore", fmt.Sprintf("/auto-backup/%d/restore", id), h.RestoreAutoBackup},
		{"下载", http.MethodGet, "/auto-backup/:id/download", fmt.Sprintf("/auto-backup/%d/download", id), h.DownloadAutoBackup},
		{"删除", http.MethodDelete, "/auto-backup/:id", fmt.Sprintf("/auto-backup/%d", id), h.DeleteAutoBackup},
	}
	for _, test := range cases {
		response := serveAutoBackupJSON(t, h, test.method, test.route, test.path, "", test.serve)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "备份目录无效") {
			t.Fatalf("%s: status=%d body=%s, want 500 备份目录无效", test.name, response.Code, response.Body.String())
		}
	}
	// 相对目录期间不得有任何文件被删除/读取失败副作用——行与 CWD 文件仍在。
	if rows := autoBackupRows(t, "WHERE id=?", id); len(rows) != 1 {
		t.Fatalf("行被提前删除: %v", rows)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "must-survive" {
		t.Fatalf("CWD 同名文件被误操作: data=%q err=%v", string(data), err)
	}
}
