package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 安全事件统计行(2026-09-14 用户裁定):SizeBytes=真实审计日志文件大小
// (非 metrics.db 库文件);DBBytes=metrics.db 容量(同行展示);LimitRows=
// 事件上限(进度条语义=条数/上限)。
func TestGetLogStats_securityEventsRow(t *testing.T) {
	h := newBackupTestHandlers(t)
	dataDir := t.TempDir()
	h.cfg.DataDir = dataDir
	oldWafLog := wafAuditLogFile
	wafAuditLogFile = filepath.Join(dataDir, "logs", "waf-audit", "audit.log")
	t.Cleanup(func() { wafAuditLogFile = oldWafLog })
	// Given: metrics.db 文件 + waf-audit 日志目录(新路径 /app/logs/waf-audit)
	if err := os.WriteFile(filepath.Join(dataDir, "lazy-balancer-metrics.db"), make([]byte, 7000), 0o644); err != nil {
		t.Fatal(err)
	}
	auditDir := filepath.Join(dataDir, "logs", "waf-audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditDir, "audit.log"), make([]byte, 3000), 0o644); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Logs []struct {
				Key       string `json:"key"`
				SizeBytes int64  `json:"size_bytes"`
				DBBytes   *int64 `json:"db_bytes"`
				LimitRows *int64 `json:"limit_rows"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var sec *struct {
		Key       string `json:"key"`
		SizeBytes int64  `json:"size_bytes"`
		DBBytes   *int64 `json:"db_bytes"`
		LimitRows *int64 `json:"limit_rows"`
	}
	for i := range resp.Data.Logs {
		if resp.Data.Logs[i].Key == "security_events" {
			sec = &resp.Data.Logs[i]
		}
	}
	if sec == nil {
		t.Fatal("security_events row missing")
	}
	// Then: SizeBytes=审计日志文件(3000),不是 metrics.db(7000)
	if sec.SizeBytes != 3000 {
		t.Fatalf("size_bytes=%d, want 3000 (real audit log files, not metrics.db)", sec.SizeBytes)
	}
	// Then: DBBytes=metrics.db 容量
	if sec.DBBytes == nil || *sec.DBBytes != 7000 {
		t.Fatalf("db_bytes=%v, want 7000 (metrics.db)", sec.DBBytes)
	}
	// Then: LimitRows=事件上限 100 万
	if sec.LimitRows == nil || *sec.LimitRows != 1000000 {
		t.Fatalf("limit_rows=%v, want 1000000", sec.LimitRows)
	}
}

// L1-66-02 读侧同源：certjob 统计跟随 {任务日志目录}/certjobs（与写入端
// CertJobLogPath 同源）。曾读写死 /app/logs 根——B3 惰性化后写入端已迁
// tasks/certjobs/，读侧不同源则统计恒 0B。
func TestGetLogStats_certJobRowFollowsTaskLogDir(t *testing.T) {
	h := newBackupTestHandlers(t)
	base := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(base, "logs", "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })

	dir := filepath.Join(base, "logs", "tasks", "certjobs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "certjob-lb_x.log"), make([]byte, 2000), 0o644); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?caddy_id=lb_x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Logs []struct {
				Key       string `json:"key"`
				SizeBytes int64  `json:"size_bytes"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var cj *struct {
		Key       string `json:"key"`
		SizeBytes int64  `json:"size_bytes"`
	}
	for i := range resp.Data.Logs {
		if resp.Data.Logs[i].Key == "certjob" {
			cj = &resp.Data.Logs[i]
		}
	}
	if cj == nil {
		t.Fatal("certjob row missing")
	}
	if cj.SizeBytes != 2000 {
		t.Fatalf("certjob size_bytes=%d, want 2000（读侧须与写入端同源 tasks/certjobs/）", cj.SizeBytes)
	}
}

func TestGetLogStats_eachTaskUsesOwnRealFileSize(t *testing.T) {
	// Given：三个不同大小的任务日志文件
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	tasksDir := filepath.Join(t.TempDir(), "tasks")
	h.cfg.LogFile = filepath.Join(filepath.Dir(tasksDir), "app.log")
	taskengine.SetLogDir(tasksDir)
	t.Cleanup(func() { taskengine.SetLogDir("") })
	certDir := filepath.Join(tasksDir, "certjobs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var jobID int
	if err := db.DB.QueryRow(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_x','x.example','queued') RETURNING id`).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	files := map[string]int{
		"crawlerbot-update.log": 5,
		"threat.log":            10,
		filepath.Join("certjobs", "certjob-lb_x.log"): 15,
	}
	for name, size := range files {
		if err := os.WriteFile(filepath.Join(tasksDir, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if active, _, _ := dirBytes(filepath.Join(tasksDir, "crawlerbot-update.log")); active != 5 {
		t.Fatalf("探针路径文件大小=%d want 5", active)
	}
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Logs []struct {
				Key          string `json:"key"`
				Name         string `json:"name"`
				SizeBytes    int64  `json:"size_bytes"`
				KeepCount    int    `json:"keep_count"`
				ConfigSource string `json:"config_source"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	byKey := map[string]struct {
		Key          string `json:"key"`
		Name         string `json:"name"`
		SizeBytes    int64  `json:"size_bytes"`
		KeepCount    int    `json:"keep_count"`
		ConfigSource string `json:"config_source"`
	}{}
	for _, row := range resp.Data.Logs {
		byKey[row.Key] = row
	}
	certJobKey := "task:cert-job:" + strconv.Itoa(jobID)
	for key, want := range map[string]int{"task:crawlerbot-update": 5, "task:threat": 10, certJobKey: 15} {
		row, ok := byKey[key]
		if !ok {
			t.Errorf("缺少逐任务统计行 %s", key)
			continue
		}
		if row.SizeBytes != int64(want) {
			t.Errorf("%s size_bytes=%d want %d", key, row.SizeBytes, want)
		}
		if row.ConfigSource == "统一任务日志（tasks/*.log）" {
			t.Errorf("%s 仍使用通配符聚合口径: %s", key, row.ConfigSource)
		}
	}
	if byKey["task:crawlerbot-update"].KeepCount != 1 || byKey[certJobKey].KeepCount != 5 {
		t.Errorf("归档份数策略错误: crawler=%d certjob=%d", byKey["task:crawlerbot-update"].KeepCount, byKey[certJobKey].KeepCount)
	}
}
