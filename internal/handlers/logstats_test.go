package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	oldLogDir := taskengine.LogDir() // U08-F13：保存旧值，cleanup 无条件恢复（原置空——跨用例污染）
	taskengine.SetLogDir(tasksDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
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

// U08-F01：安全事件行的保留文案改由 services.SecurityEventsRetentionSummary
// 单源生成——显式 security_events_retention_days 生效（此前恒复用审计月数
// 文案，显式设置被无视），且该行补 LimitBytes（审计写入侧 audit_log_size_mb）。
func TestGetLogStats_securityEventsRetentionUsesExplicitSettings(t *testing.T) {
	h := newBackupTestHandlers(t)
	oldWafLog := wafAuditLogFile
	wafAuditLogFile = filepath.Join(t.TempDir(), "audit.log")
	t.Cleanup(func() { wafAuditLogFile = oldWafLog })
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=3, security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?key=security_events", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Logs []struct {
				Key           string `json:"key"`
				LimitBytes    *int64 `json:"limit_bytes"`
				RetentionNote string `json:"retention_note"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Logs) != 1 || resp.Data.Logs[0].Key != "security_events" {
		t.Fatalf("logs=%+v, want exactly security_events row", resp.Data.Logs)
	}
	row := resp.Data.Logs[0]
	if !strings.Contains(row.RetentionNote, "30 天") {
		t.Errorf("retention_note=%q, want 显式 30 天（不得复用审计月数文案）", row.RetentionNote)
	}
	if row.LimitBytes == nil || *row.LimitBytes != 10*1024*1024 {
		t.Errorf("limit_bytes=%v, want 默认 audit_log_size_mb=10MB", row.LimitBytes)
	}

	// 回归形态：未显式设置时回退旧通道月表述。
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?key=security_events", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Logs) != 1 || !strings.Contains(resp.Data.Logs[0].RetentionNote, "3 个月") {
		t.Errorf("retention_note=%q, want 回退月表述「3 个月」", resp.Data.Logs[0].RetentionNote)
	}
}

// U08-F07：key/keys 收窄——任务监控弹框只取单行，缺省保持旧全量形状。
func TestGetLogStats_keyFilterNarrowsRows(t *testing.T) {
	h := newBackupTestHandlers(t)
	oldWafLog := wafAuditLogFile
	wafAuditLogFile = filepath.Join(t.TempDir(), "audit.log")
	t.Cleanup(func() { wafAuditLogFile = oldWafLog })
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)

	get := func(query string) []string {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				Logs []struct {
					Key string `json:"key"`
				} `json:"logs"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(resp.Data.Logs))
		for _, row := range resp.Data.Logs {
			keys = append(keys, row.Key)
		}
		return keys
	}

	if keys := get("?key=certjob"); len(keys) != 1 || keys[0] != "certjob" {
		t.Fatalf("key=certjob → %v, want 仅 certjob 一行", keys)
	}
	keys := get("?keys=audit,threat_update")
	if len(keys) != 2 || keys[0] != "audit" || keys[1] != "threat_update" {
		t.Fatalf("keys=audit,threat_update → %v, want 两行", keys)
	}
	if all := get(""); len(all) < 10 {
		t.Fatalf("缺省应保持全量形状，got %d 行", len(all))
	}
}

// U08-F07：聚合一次 ReadDir——200 文件的 certjobs 目录单次请求只枚举一次
// （原逐文件 dirBytes 在其内部再 ReadDir，O(N²)）。
func TestGetLogStats_aggregateDirReadsOnce(t *testing.T) {
	h := newBackupTestHandlers(t)
	base := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(base, "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	certDir := filepath.Join(base, "tasks", "certjobs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 200 {
		if err := os.WriteFile(filepath.Join(certDir, "certjob-lb_"+strconv.Itoa(i)+".log"), make([]byte, 10), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var readDirCalls int
	oldReadDir := logStatsReadDir
	logStatsReadDir = func(dir string) ([]os.DirEntry, error) {
		readDirCalls++
		return os.ReadDir(dir)
	}
	t.Cleanup(func() { logStatsReadDir = oldReadDir })

	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?key=certjob", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if readDirCalls != 1 {
		t.Fatalf("certjobs 聚合 ReadDir 调用=%d, want 1（O(N²) 形态未收敛）", readDirCalls)
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
	if len(resp.Data.Logs) != 1 || resp.Data.Logs[0].SizeBytes != 2000 {
		t.Fatalf("certjob 聚合=%+v, want 单行 2000B", resp.Data.Logs)
	}
}

// U08-F12：聚合累加归档份数，且 .gz 归档不再冒充活跃文件。
func TestGetLogStats_aggregateCountsRotationsAndGzAsArchive(t *testing.T) {
	h := newBackupTestHandlers(t)
	base := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(base, "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	certDir := filepath.Join(base, "tasks", "certjobs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int{
		"certjob-lb_a.log":    100,
		"certjob-lb_a.log.1":  50,
		"certjob-lb_a.log.gz": 30,
	} {
		if err := os.WriteFile(filepath.Join(certDir, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?key=certjob", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Logs []struct {
				Key          string `json:"key"`
				SizeBytes    int64  `json:"size_bytes"`
				RotatedBytes int64  `json:"rotated_bytes"`
				RotatedCount int    `json:"rotated_count"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Logs) != 1 {
		t.Fatalf("logs=%+v, want 单行", resp.Data.Logs)
	}
	row := resp.Data.Logs[0]
	if row.SizeBytes != 100 {
		t.Errorf("size_bytes=%d, want 100（.gz 不计活跃）", row.SizeBytes)
	}
	if row.RotatedBytes != 80 || row.RotatedCount != 2 {
		t.Errorf("rotated=%d/%d, want 80/2（移位副本 + .gz 归档）", row.RotatedBytes, row.RotatedCount)
	}
}
