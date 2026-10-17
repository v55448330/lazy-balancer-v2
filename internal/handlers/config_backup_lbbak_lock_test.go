package handlers

// 第 66 轮审计修复——L6-66-01（users 空表拒绝）、L6-66-03（预览单侧缺失
// 建模）、L6-66-04（CRS 日志时序）、F-B1（未登记威胁条目告警）、L6-66-02
// handlers 侧探针（applyLbbakWafFiles 文件相位入 wafFileMu）。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"lazy-balancer-v2/internal/taskengine"
)

// buildLbbakWithExtraThreatEntry 手工组包：manifest 只登记 config.json，
// tar 内额外携带 manifest 未登记的 threat/ustc.iplist 条目（F-B1 形态——
// 旧备份/损坏包可能产出，导入不拒绝但必须告警）。
func buildLbbakWithExtraThreatEntry(t *testing.T, backupJSON string, threatData []byte) []byte {
	t.Helper()
	manifest := map[string]any{
		"format": "lbbak",
	}
	sum := sha256.Sum256([]byte(backupJSON))
	manifest["checksum"] = map[string]string{"config.json": hex.EncodeToString(sum[:])}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	entries := map[string][]byte{
		"manifest.json":      manifestJSON,
		"config.json":        []byte(backupJSON),
		"threat/ustc.iplist": threatData,
	}
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for _, name := range []string{"manifest.json", "config.json", "threat/ustc.iplist"} {
		data := entries[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// postLbbakValidate 以 tar.gz 体投递预览端点，返回响应记录器。
func postLbbakValidate(t *testing.T, h *Handlers, body []byte, query string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	req := httptest.NewRequest(http.MethodPost, "/config/validate"+query, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeValidateResponse 解析预览响应 data 段。
func decodeValidateResponse(t *testing.T, rec *httptest.ResponseRecorder) importValidateResponse {
	t.Helper()
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode validate response: %v body=%s", err, rec.Body.String())
	}
	return envelope.Data
}

// ── L6-66-02 handlers 侧：applyLbbakWafFiles 文件相位必须受 wafFileMu 互斥 ──

// Given wafFileMu 被预持（模拟并发的三库更新器文件相位）。
// When applyLbbakWafFiles 执行威胁库 .iplist 落盘+编译文件相位。
// Then 必须阻塞至锁释放。
func TestApplyLbbakWafFiles_blocks_while_waf_file_lock_held(t *testing.T) {
	_ = newBackupTestHandlers(t) // 初始化 db.AuditDB（recordAudit 落审计）与 caddy stub
	dir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(dir)
	defer restore()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/config/import", nil)

	payload := &lbbakPayload{ThreatIplists: map[string][]byte{"ustc": []byte("1.2.3.4\n")}}
	services.WafFileLock().Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = applyLbbakWafFiles(c, "导入", payload, "test-tag")
	}()
	select {
	case <-done:
		services.WafFileLock().Unlock()
		t.Fatal("applyLbbakWafFiles 在 wafFileMu 被预持期间完成——lbbak 文件相位未入锁")
	case <-time.After(300 * time.Millisecond):
	}
	services.WafFileLock().Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后 applyLbbakWafFiles 10s 内未完成")
	}
}

// ── L6-67-01（第 67 轮）：lbbak 导出侧 BuildWafFileBundle 读相位必须受 wafFileMu 互斥 ──

// Given wafFileMu 被预持（模拟并发的三库更新器/lbbak 导入文件写相位）。
// When buildLbbakExport 勾选「安全防护」分类（触发 BuildWafFileBundle 读 CRS
// 树/xdb/威胁 .fast）执行导出。
// Then 必须阻塞至锁释放——读侧不入锁会在写者交换树/重写 .fast 中途打出残缺
// bundle（manifest sha256 按内存字节自洽仍通过，还原后 WAF 静默降级）。
// 回归形状：锁释放后导出完成且载荷完整（无锁竞争时导出正常产出）。
func TestBuildLbbakExport_blocks_while_waf_file_lock_held(t *testing.T) {
	h := newBackupTestHandlers(t)
	crsDir, _ := overrideTestWafPaths(t)
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.29.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "REQUEST-901.conf"), []byte("SecRule a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	type exportResult struct {
		payload          []byte
		includesWafFiles bool
		err              error
	}
	services.WafFileLock().Lock()
	done := make(chan exportResult, 1)
	go func() {
		payload, _, _, includesWafFiles, err := h.buildLbbakExport(context.Background(), []string{"security"})
		done <- exportResult{payload, includesWafFiles, err}
	}()
	select {
	case <-done:
		services.WafFileLock().Unlock()
		t.Fatal("buildLbbakExport 在 wafFileMu 被预持期间完成——导出读相位未入锁")
	case <-time.After(300 * time.Millisecond):
	}
	services.WafFileLock().Unlock()
	var res exportResult
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后 buildLbbakExport 10s 内未完成")
	}
	// 回归形状：无锁竞争时导出正常产出（载荷可解析且携带 waf 文件节）。
	if res.err != nil {
		t.Fatalf("导出失败: %v", res.err)
	}
	if !res.includesWafFiles || len(res.payload) == 0 {
		t.Fatalf("导出应携带 waf 文件节且载荷非空: includesWafFiles=%v len=%d", res.includesWafFiles, len(res.payload))
	}
}

// ── L6-66-04：CRS 分阶段流水「reloading/success」必须落在 commit 成功之后 ──

// Given lbbak 备份（含 CRS 文件）导入，Caddy stub 拒绝一切请求使 session.commit
// 失败（POST /load 被拒→Caddy 拒绝→400 回滚）。
// When 导入执行完毕。
// Then 普通 HTTP 导入不是 CRS 更新任务，不得写 tasks/crs.log。
func TestLbbakImport_commit_failure_does_not_write_crs_task_log(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	crsDir, _ := overrideTestWafPaths(t)
	// 分类导入不动 users：管理员守卫读本地——种一名本地启用管理员
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (6,'local-admin-l66','hash','admin',1)`); err != nil {
		t.Fatalf("seed local admin: %v", err)
	}
	// 种 CRS 活动树供导出端构建 bundle（内容与声明哈希天然配对）
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.29.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "REQUEST-901.conf"), []byte("SecRule a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// commit 失败注入：GET /config/ 回 200 {}（运行时快照阶段需要可解析体），
	// 其余（POST /load）回 400 {}——Caddy 拒绝渲染配置→ConfigRejectedError→400 回滚
	reject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/load") {
			w.WriteHeader(http.StatusBadRequest)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer reject.Close()
	h.caddyService = services.NewCaddyService(reject.URL)

	// 任务日志重定向到独立目录，避免测试间串扰
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules,waf_files", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}

	importRec := postLbbakImport(g, t, rec.Body.Bytes(), "?sections=rules,waf_files")
	if importRec.Code != http.StatusBadRequest {
		t.Fatalf("commit 失败应回 400（Caddy 拒绝），got %d body=%s", importRec.Code, importRec.Body.String())
	}
	if !strings.Contains(importRec.Body.String(), "未通过 Caddy 验证") {
		t.Fatalf("失败原因应为 Caddy 拒绝: %s", importRec.Body.String())
	}

	logBytes, err := os.ReadFile(taskengine.TaskLogPath("crs"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read tasks/crs.log: %v", err)
	}
	if len(logBytes) > 0 {
		t.Fatalf("普通 HTTP 导入不得写 CRS 任务日志: %s", logBytes)
	}
}

// 回归形状：commit 成功仍写安全数据审计，但普通 HTTP 导入不得写 CRS 任务日志。
func TestLbbakImport_commit_success_uses_audit_not_crs_task_log(t *testing.T) {
	h := newBackupTestHandlers(t) // 默认 caddy stub 接受 /load → commit 成功
	g := newBackupSectionRouter(h)
	crsDir, _ := overrideTestWafPaths(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (6,'local-admin-l66b','hash','admin',1)`); err != nil {
		t.Fatalf("seed local admin: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.29.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "REQUEST-901.conf"), []byte("SecRule a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules,waf_files", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	importRec := postLbbakImport(g, t, rec.Body.Bytes(), "?sections=rules,waf_files")
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", importRec.Code, importRec.Body.String())
	}
	logBytes, err := os.ReadFile(taskengine.TaskLogPath("crs"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read tasks/crs.log: %v", err)
	}
	if len(logBytes) > 0 {
		t.Fatalf("普通 HTTP 导入不得写 CRS 任务日志: %s", logBytes)
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='安全数据' AND detail LIKE '%规则库数据库%'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("安全数据审计行=%d, want 1（移除任务日志不得影响审计）", auditCount)
	}
}

// ── F-B1：manifest 未登记的 threat/*.iplist 条目必须告警（不拒绝） ──

// Given lbbak 包内含 manifest 未登记的 threat/ustc.iplist 条目。
// When 导入执行。
// Then 导入照常成功（老备份兼容），响应 warnings 含「未登记」告警文案。
func TestLbbakImport_unregistered_threat_entry_warns(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	dir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(dir)
	defer restore()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })

	body := buildLbbakWithExtraThreatEntry(t, completeBackupJSON(t, nil), []byte("1.2.3.4\n5.6.7.8\n"))
	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("未登记威胁条目不应拒绝导入（老备份兼容）, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "未登记") || !strings.Contains(rec.Body.String(), "threat/ustc.iplist") {
		t.Fatalf("响应应携带 manifest 未登记条目告警: %s", rec.Body.String())
	}
}

// Given 同形态 lbbak 包投递预览端点。
// When 预览执行。
// Then 预览 warnings 同样携带未登记告警（预览/导入口径一致）。
func TestLbbakValidate_unregistered_threat_entry_warns(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := buildLbbakWithExtraThreatEntry(t, completeBackupJSON(t, nil), []byte("1.2.3.4\n"))
	rec := postLbbakValidate(t, h, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "未登记") {
		t.Fatalf("预览应携带 manifest 未登记条目告警: %s", rec.Body.String())
	}
}
