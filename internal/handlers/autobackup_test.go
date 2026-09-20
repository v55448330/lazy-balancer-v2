package handlers

import (
	"encoding/json"
	"fmt"
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

func countAutoBackupAudit(t *testing.T, action string) int {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return count
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

func TestRunAutoBackupOnce_successWritesFileRowAndAudit(t *testing.T) {
	// Given: 主节点测试实例 + 可写备份目录
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_ab1','auto-backup-rule','http','ab.example.test',8080,1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	// When
	if err := h.RunAutoBackupOnce("manual", "system"); err != nil {
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
	// 行:success + 真实大小 + 全 3 分类(三分类合并后的默认全选)+ 摘要非空
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
	if err := json.Unmarshal([]byte(row["sections"].(string)), &sections); err != nil || len(sections) != 3 || sections[0] != "users" || sections[1] != "rules" || sections[2] != "security" {
		t.Fatalf("sections=%q err=%v, want [users rules security]", row["sections"], err)
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
	if err := h.RunAutoBackupOnce("manual", "system"); err != nil {
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
	err := h.RunAutoBackupOnce("schedule", "system")

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
	pruneAutoBackups(dir, 2, 20)

	// Then: success 仅留最新 2 个(文件+行同删)
	if rows := autoBackupRows(t, "WHERE status='success' ORDER BY created_at DESC"); len(rows) != 2 {
		t.Fatalf("success rows after prune=%d, want 2", len(rows))
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

// 保留份数上限收紧为 30 后,升级前保存的越界存量值(31-100)读侧必须回退
// 安全默认 7——prune 消费回退值,不得沿用越界保留。
func TestLoadAutoBackupKeepSetting_outOfRangeFallsBack(t *testing.T) {
	newAutoBackupTestHandlers(t)
	for _, stored := range []int{0, 31, 50, 100} {
		if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_keep=? WHERE id=1`, stored); err != nil {
			t.Fatal(err)
		}
		if got := loadAutoBackupKeepSetting(); got != 7 {
			t.Fatalf("stored keep=%d loaded=%d, want fallback 7", stored, got)
		}
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_keep=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := loadAutoBackupKeepSetting(); got != 30 {
		t.Fatalf("stored keep=30 loaded=%d, want 30", got)
	}
}

// 三分类合并(2026-09-19 用户裁定):legacy sections 键(global_config→users、
// waf_files→security)在保存与读取双侧归一——旧值不再因「仅全局配置」被拒,
// 重存后落库值即收敛为当前三分类。
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
// 三分类口径,无需迁移存量行。
func TestLoadAutoBackupSectionsSetting_normalizesLegacyKeys(t *testing.T) {
	newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_sections='["users","global_config","rules","waf_files","security"]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	got := loadAutoBackupSectionsSetting()
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
	if !d.Enabled || d.Frequency != "weekly" || d.Time != "04:30" || d.Day != 6 || d.Keep != 9 || len(d.Sections) != 3 {
		t.Fatalf("settings=(%v,%s,%s,%d,%d,%v)", d.Enabled, d.Frequency, d.Time, d.Day, d.Keep, d.Sections)
	}
	if len(d.Backups) != 2 || d.Backups[0].Filename != "lbbak-auto-list2.lbbak" {
		t.Fatalf("backups=%+v, want DESC 顺序且最新在前", d.Backups)
	}
}

func TestRunAutoBackupNow_endpointRunsAndRespondsRow(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/run", "/auto-backup/run", "", h.RunAutoBackupNow)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			ID       int64  `json:"id"`
			Status   string `json:"status"`
			Filename string `json:"filename"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.ID == 0 || payload.Data.Status != "success" || !strings.HasPrefix(payload.Data.Filename, "lbbak-manual-") {
		t.Fatalf("data=%+v, want 新增 success 行", payload.Data)
	}
	if got := countAutoBackupAudit(t, "手动备份"); got != 1 {
		t.Fatalf("手动备份 audit rows=%d, want 1", got)
	}
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
	if err := h.RunAutoBackupOnce("manual", "system"); err != nil {
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
	services.SetAutoBackupExecutor(h.RunAutoBackupOnce)
	t.Cleanup(func() { services.SetAutoBackupExecutor(nil) })
	if !autoBackupRunMu.TryLock() {
		t.Fatal("前置锁定失败")
	}
	err := h.RunAutoBackupOnce("manual", "system")
	autoBackupRunMu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "正在执行") {
		t.Fatalf("err=%v, want 已有任务执行中报错", err)
	}
}

// SYS41-1(第 41 轮审计):RunAutoBackupOnce 成功落行后必须接线内务裁剪——
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
	if err := h.RunAutoBackupOnce("schedule", "system"); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := h.RunAutoBackupOnce("schedule", "system"); err != nil {
		t.Fatalf("second run: %v", err)
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
	// failed 行按 20 上限一并裁剪
	var failed int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE status='failed'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 20 {
		t.Fatalf("failed rows=%d, want 20(autoBackupFailedRowsKeep)", failed)
	}
}

// SYSB43-1(第 43 轮):裁剪时文件删除失败(非 ErrNotExist)必须保留 DB 行
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
		if _, err := insertAutoBackupRow(filename, "success", 128, `["users"]`, "manual", "", "v9.9.9-test"); err != nil {
			t.Fatal(err)
		}
	}

	// When
	pruneAutoBackups(dir, 0, 20)

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

	// Then: 200 且「手动备份」审计行操作人为 operator-zhang(修复前恒 system)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var username string
	if err := db.AuditDB.QueryRow(`SELECT username FROM audit_log WHERE action='手动备份' ORDER BY id DESC LIMIT 1`).Scan(&username); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if username != "operator-zhang" {
		t.Fatalf("手动备份 audit username=%q, want operator-zhang(调度路径才记 system)", username)
	}
}
