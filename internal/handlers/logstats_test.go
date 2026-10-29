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
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func TestLogRotatedBackups_matchServiceWriters(t *testing.T) {
	// 契约以服务端导出的数值钉住（此前读取 services 源码
	// 文本——常量改类型/加注释/第三个 writer 出现时会误红或漏验）。写侧与
	// 展示层的保留份数必须同源同值。
	if logRotatedBackups != services.CertJobLogMaxRotatedFiles() {
		t.Fatalf("handler logRotatedBackups=%d, services 写侧=%d", logRotatedBackups, services.CertJobLogMaxRotatedFiles())
	}
	if logRotatedBackups != services.CaddyLogRollKeep() {
		t.Fatalf("handler logRotatedBackups=%d, Caddy 日志 roll_keep=%d", logRotatedBackups, services.CaddyLogRollKeep())
	}
}

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

// 读侧同源：certjob 统计跟随 {任务日志目录}/certjobs（与写入端
// CertJobLogPath 同源）。曾读写死 /app/logs 根——惰性化后写入端已迁
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
	oldLogDir := taskengine.LogDir() // 保存旧值，cleanup 无条件恢复（原置空——跨用例污染）
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
	if active, _, _ := dirBytesWithEntries(filepath.Join(tasksDir, "crawlerbot-update.log"), nil); active != 5 {
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

// 安全事件行的保留文案改由 services.SecurityEventsRetentionSummary
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

	// 回归形态：未显式设置时使用安全事件独立默认 90 天，不再回退审计月数。
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?key=security_events", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Logs) != 1 || !strings.Contains(resp.Data.Logs[0].RetentionNote, "90 天") {
		t.Errorf("retention_note=%q, want 独立默认「90 天」", resp.Data.Logs[0].RetentionNote)
	}
}

// key/keys 收窄——任务监控弹框只取单行，缺省保持旧全量形状。
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

// 聚合一次 ReadDir——200 文件的 certjobs 目录单次请求只枚举一次
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

type countingLogStatsDirEntry struct {
	name      string
	info      os.FileInfo
	infoCalls *int
}

func (entry countingLogStatsDirEntry) Name() string      { return entry.name }
func (entry countingLogStatsDirEntry) IsDir() bool       { return false }
func (entry countingLogStatsDirEntry) Type() os.FileMode { return 0 }
func (entry countingLogStatsDirEntry) Info() (os.FileInfo, error) {
	(*entry.infoCalls)++
	return entry.info, nil
}

func TestAggregateDirStats_skipsInfoForUnmatchedEntries(t *testing.T) {
	dir := t.TempDir()
	newEntry := func(name string, size int) countingLogStatsDirEntry {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return countingLogStatsDirEntry{name: name, info: info, infoCalls: new(int)}
	}
	active := newEntry("app.log", 3)
	rotated := newEntry("app.log.1", 5)
	unmatched := newEntry("other.log", 7)

	stats := aggregateDirStatsWithEntries(dir, []os.DirEntry{active, rotated, unmatched}, func(name string) bool {
		return name == "app.log" || name == "app.log.1"
	})

	if got := *unmatched.infoCalls; got != 0 {
		t.Fatalf("非匹配文件 Info 调用=%d, want 0", got)
	}
	if *active.infoCalls != 1 || *rotated.infoCalls != 1 {
		t.Fatalf("匹配文件 Info 调用 active=%d rotated=%d, want 1/1", *active.infoCalls, *rotated.infoCalls)
	}
	if got := stats["app.log"]; got.Active != 3 || got.Rotated != 5 || got.RotCount != 1 {
		t.Fatalf("聚合结果=%+v, want active=3 rotated=5 count=1", got)
	}
}

// 聚合累加归档份数，且.gz 归档不再冒充活跃文件。
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

// 审计日志路径随 ConfigureWafDirs 按 data_dir 派生，
// 而 handlers 包 init 早于 main 的派生调用——包级固化会指向陈旧的 /app 路径。
// 解析必须运行期进行：注入值优先，否则取 services.AuditLogPath()。
func TestResolvedWafAuditLogFile_tracksDerivedPath(t *testing.T) {
	oldWafLog := wafAuditLogFile
	t.Cleanup(func() { wafAuditLogFile = oldWafLog })

	wafAuditLogFile = ""
	if got, want := resolvedWafAuditLogFile(), services.AuditLogPath(); got != want {
		t.Fatalf("空注入值必须跟随 services.AuditLogPath(): got=%q want=%q", got, want)
	}
	injected := filepath.Join(t.TempDir(), "audit.log")
	wafAuditLogFile = injected
	if got := resolvedWafAuditLogFile(); got != injected {
		t.Fatalf("注入值必须优先: got=%q want=%q", got, injected)
	}
}

// 单行轮询（?key=certjob）不得读取与所选行无关的配置列。
func TestGetLogStats_singleRowRequestSkipsUnrelatedConfigReads(t *testing.T) {
	h := newBackupTestHandlers(t)
	probe := &prepareProbe{}
	wrapHandlerDBWithProbe(t, probe)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/logs/stats?key=certjob", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, column := range []string{"audit_retention_months", "security_events_retention_days", "security_events_row_cap"} {
		if count := probe.count(column); count != 0 {
			t.Errorf("%s 在单行请求下被读取 %d 次, want 0（阈值必须按 want 门控）", column, count)
		}
	}
	if probe.count("task_log_size_mb") != 1 {
		t.Errorf("task_log_size_mb 读取次数=%d, want 1（所选行的阈值仍需一次）", probe.count("task_log_size_mb"))
	}

	// 回归形态：全量请求仍读且只读一次（安全事件策略一次查询同时取两列）。
	full := &prepareProbe{}
	wrapHandlerDBWithProbe(t, full)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/logs/stats", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("full status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if count := full.count("security_events_retention_days"); count != 1 {
		t.Errorf("全量请求 security_events_retention_days 读取 %d 次, want 1", count)
	}
	if count := full.count("security_events_row_cap"); count != 1 {
		t.Errorf("全量请求 security_events_row_cap 读取 %d 次, want 1", count)
	}
	if count := full.count("audit_retention_months"); count != 1 {
		t.Errorf("全量请求 audit_retention_months 读取 %d 次, want 1", count)
	}
}

// 运行日志行与 caddy 聚合行默认同读 /app/logs：一次请求内该目录只枚举一次
// （此前各枚举一次，重复 ReadDir/stat，且两次枚举间发生轮转时同一响应的两行
// 会来自不同目录快照）。
func TestGetLogStats_sharedLogsDirEnumeratedOnce(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.LogFile = "/app/logs/lazy-balancer.log"

	var fixedDirReads int
	oldReadDir := logStatsReadDir
	logStatsReadDir = func(dir string) ([]os.DirEntry, error) {
		if filepath.Clean(dir) == "/app/logs" {
			fixedDirReads++
			return []os.DirEntry{}, nil
		}
		return os.ReadDir(dir)
	}
	t.Cleanup(func() { logStatsReadDir = oldReadDir })

	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?key=runtime,caddy", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fixedDirReads != 1 {
		t.Fatalf("/app/logs 枚举 %d 次, want 1（运行行与 caddy 聚合必须共享请求级缓存）", fixedDirReads)
	}
}

// 全量请求对同一 tasks 目录只枚举一次（四类已知任务行 + 逐任务行共享缓存）；
// 失败形态同样只尝试一次——此前每个任务都重读，故障窗口退化为 O(N) 次失败
// syscall，且失败零留痕。
func TestGetLogStats_taskDirEnumeratedOncePerRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failDir bool
	}{
		{name: "success"},
		{name: "read failure", failDir: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetLogStatsVolumeStateForTest()
			h := newBackupTestHandlers(t)
			base := t.TempDir()
			tasksDir := filepath.Join(base, "tasks")
			oldLogDir := taskengine.LogDir()
			taskengine.SetLogDir(tasksDir)
			t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
			if err := os.MkdirAll(tasksDir, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"crs.log", "ip2region.log", "threat.log", "crawlerbot-update.log"} {
				if err := os.WriteFile(filepath.Join(tasksDir, name), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			var tasksDirReads int
			oldReadDir := logStatsReadDir
			logStatsReadDir = func(dir string) ([]os.DirEntry, error) {
				if filepath.Clean(dir) != filepath.Clean(tasksDir) {
					return os.ReadDir(dir)
				}
				tasksDirReads++
				if tc.failDir {
					return nil, os.ErrPermission
				}
				return os.ReadDir(dir)
			}
			t.Cleanup(func() { logStatsReadDir = oldReadDir })
			logs := captureLog(t)

			router := gin.New()
			router.GET("/logs/stats", h.GetLogStats)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if tasksDirReads != 1 {
				t.Fatalf("tasks 目录枚举次数=%d, want 1（四类已知行与逐任务行必须共享缓存）", tasksDirReads)
			}
			if tc.failDir && !strings.Contains(logs.String(), "日志体量读取失败") {
				t.Fatalf("目录读失败必须留痕, logs=%q", logs.String())
			}
		})
	}
}

// 操作日志行是纯 DB 行（audit_log 表 + 保留期每日清理），没有轮转归档概念：
// 前端据 db_backed 标记渲染「库内定期清理」，不再把 keep_count=0 读成
// 「暂无归档」（那种读法会被误读成归档失败）。文件族行必须不带该标记。
func TestGetLogStats_auditRowMarkedDBBacked(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats?keys=audit,runtime", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			Logs []map[string]any `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode stats: %v body=%s", err, rec.Body.String())
	}
	byKey := map[string]map[string]any{}
	for _, item := range payload.Data.Logs {
		if key, ok := item["key"].(string); ok {
			byKey[key] = item
		}
	}
	audit, ok := byKey["audit"]
	if !ok {
		t.Fatalf("audit 行缺席: %s", rec.Body.String())
	}
	if audit["db_backed"] != true {
		t.Fatalf("audit db_backed=%v, want true（DB 行无归档概念）", audit["db_backed"])
	}
	if runtimeRow, ok := byKey["runtime"]; ok {
		if backed, present := runtimeRow["db_backed"]; present && backed == true {
			t.Fatalf("runtime 行 db_backed=%v, want 缺席/false（文件轮转族）", backed)
		}
	}
}
