package handlers

// 覆盖：lbbak 导入/导出的文件相位与 WAF/Caddy 锁序（生产链用例），旁路契约
// 包括 users 空表拒绝、预览单侧 WAF 文件缺失建模、CRS 日志时序、manifest
// 未登记威胁条目告警。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
// tar 内额外携带 manifest 未登记的 threat/ustc.iplist 条目（形态——
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

// 锁序不变量由生产链用例 TestLbbakImport_acquiresWafLockBeforeCaddyOpLock 承担
// （预持 CaddyOpLock + WafFileLock().TryLock() 探针 + 真实导出包导入）；此前这里
// 另定义了一个测试专属包装（自行加锁后调 InLock 变体）来「证明」阻塞，只能
// 证明测试包装加了锁，属自证，已删除。

// lbbak 导出侧 BuildWafFileBundle 读相位必须受 wafFileMu 互斥

// Given wafFileMu 被预持（模拟并发的三库更新器/lbbak 导入文件写相位）。
// When buildLbbakExport 勾选「安全防护」分类（触发 BuildWafFileBundle 读 CRS
// 树/xdb/威胁 .fast）执行导出。
// Then 必须阻塞至锁释放——读侧不入锁会在写者交换树/重写 .fast 中途打出残缺
// bundle（manifest sha256 按内存字节自洽仍通过，还原后 WAF 静默降级）。
// 回归形状：锁释放后导出完成且载荷完整（无锁竞争时导出正常产出）。
func TestBuildLbbakExport_blocks_while_waf_file_lock_held(t *testing.T) {
	withIsolatedGlobal(t)
	snapshotStarted := make(chan struct{}, 1)
	oldSnapshotHook := configBackupExportAfterDBSnapshot
	configBackupExportAfterDBSnapshot = func() { snapshotStarted <- struct{}{} }
	t.Cleanup(func() { configBackupExportAfterDBSnapshot = oldSnapshotHook })
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
	select {
	case <-snapshotStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后导出未进入 DB 快照完成点——正向屏障失效")
	}
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

func TestBuildLbbakExport_holdsWafLockAcrossDBSnapshot(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	crsDir, _ := overrideTestWafPaths(t)
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.29.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "REQUEST-901.conf"), []byte("SecRule a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldHook := configBackupExportAfterDBSnapshot
	configBackupExportAfterDBSnapshot = func() {
		locker, ok := services.WafFileLock().(interface {
			TryLock() bool
			Unlock()
		})
		if !ok {
			t.Error("WAF lock does not expose TryLock")
			return
		}
		if locker.TryLock() {
			locker.Unlock()
			t.Error("DB snapshot completed without holding WAF file lock")
		}
	}
	t.Cleanup(func() { configBackupExportAfterDBSnapshot = oldHook })

	payload, _, _, includesWafFiles, err := h.buildLbbakExport(context.Background(), []string{"security"})

	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !includesWafFiles || len(payload) == 0 {
		t.Fatalf("export missing WAF files: includes=%v len=%d", includesWafFiles, len(payload))
	}
}

func TestLbbakImport_waitsForWafLockBeforeDBTransaction(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	crsDir, _ := overrideTestWafPaths(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (6,'local-admin-lockorder','hash','admin',1)`); err != nil {
		t.Fatal(err)
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
	exportRec := httptest.NewRecorder()
	g.ServeHTTP(exportRec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules,waf_files", nil))
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportRec.Code, exportRec.Body.String())
	}
	payload := exportRec.Body.Bytes()

	prelockReached := make(chan struct{})
	oldPrelockHook := configImportBeforePrelockHook
	configImportBeforePrelockHook = func() { close(prelockReached) }
	t.Cleanup(func() { configImportBeforePrelockHook = oldPrelockHook })
	services.WafFileLock().Lock()
	importDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/config/import?sections=rules,waf_files", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/octet-stream")
		g.ServeHTTP(rec, req)
		importDone <- rec.Code
	}()
	// 已确证导入到达 WAF prelock、尚未开启 DB 事务；DB 探针不再依赖 300ms
	// 猜测 goroutine 已阻塞。
	select {
	case <-prelockReached:
	case <-time.After(5 * time.Second):
		services.WafFileLock().Unlock()
		t.Fatal("import did not reach WAF prelock")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, dbErr := db.DB.ExecContext(ctx, `UPDATE global_config SET log_level=log_level WHERE id=1`)
	cancel()
	services.WafFileLock().Unlock()

	var importCode int
	select {
	case importCode = <-importDone:
	case <-time.After(20 * time.Second):
		t.Fatal("import did not finish after releasing WAF lock")
	}
	if dbErr != nil {
		t.Fatalf("DB writer blocked while import waited for WAF lock (DB tx -> wafFileMu order): %v", dbErr)
	}
	if importCode != http.StatusOK {
		t.Fatalf("import status=%d, want 200", importCode)
	}
}

// 导入必须先暂停/排空任务再取 WAF 文件锁；若先取锁，
// 等待该锁的更新任务无法被取消，排空必然超时并可能在提交后旧写覆盖。
func TestLbbakImport_pausesSchedulingBeforeWafLock(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	if err := te.Register(taskengine.Descriptor{
		ID: "waf-lock-order-probe", Family: "test", Name: "WAF lock order probe",
		Kind: taskengine.KindOneshot,
		Run:  func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	body := buildTestLbbak(t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, EmptyConfigIfNil: true}), []byte("x"))
	services.WafFileLock().Lock()
	unlocked := false
	unlockWaf := func() {
		if !unlocked {
			services.WafFileLock().Unlock()
			unlocked = true
		}
	}
	defer unlockWaf()

	done := make(chan int, 1)
	go func() { done <- postLbbakImport(g, t, body, "").Code }()

	deadline := time.Now().Add(2 * time.Second)
	paused := false
	for time.Now().Before(deadline) {
		err := te.Trigger("waf-lock-order-probe", "manual", "test")
		if errors.Is(err, taskengine.ErrSchedulingPaused) {
			paused = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !paused {
		unlockWaf()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		t.Fatal("导入在等待 WAF 锁前未暂停调度（锁序仍为 WAF→排空）")
	}
	unlockWaf()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("import status=%d, want 200", code)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("releasing WAF lock did not let import finish")
	}
}

// CRS 分阶段流水「reloading/success」必须落在 commit 成功之后

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
	var securityDataAudits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='安全数据' AND detail LIKE '%规则库数据库%'`).Scan(&securityDataAudits); err != nil {
		t.Fatal(err)
	}
	if securityDataAudits != 0 {
		t.Fatalf("回滚导入留下安全数据成功审计 %d 条, want 0", securityDataAudits)
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

// manifest 未登记的 threat/*.iplist 条目必须告警（不拒绝）

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

	body := buildLbbakWithExtraThreatEntry(t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, EmptyConfigIfNil: true}), []byte("1.2.3.4\n5.6.7.8\n"))
	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("未登记威胁条目不应拒绝导入（老备份兼容）, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "未登记") || !strings.Contains(rec.Body.String(), "threat/ustc.iplist") {
		t.Fatalf("响应应携带 manifest 未登记条目告警: %s", rec.Body.String())
	}
}

// 未选择安全防护分类时条目并未落盘，警告不得宣称「已按原样落盘」。
func TestLbbakImport_unregisteredThreatSkippedBySectionsWarnsNotImported(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	dir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(dir)
	defer restore()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (6,'local-admin-unregistered','hash','admin',1)`); err != nil {
		t.Fatalf("seed local admin: %v", err)
	}

	body := buildLbbakWithExtraThreatEntry(t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, EmptyConfigIfNil: true}), []byte("1.2.3.4\n"))
	rec := postLbbakImport(g, t, body, "?sections=rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "未登记") || !strings.Contains(rec.Body.String(), "未导入") {
		t.Fatalf("响应应明确条目未导入: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "已按原样落盘") {
		t.Fatalf("未选安全防护分类仍宣称已落盘: %s", rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "threat-ustc.iplist")); !os.IsNotExist(err) {
		t.Fatalf("skipped threat file exists or stat failed unexpectedly: %v", err)
	}
}

// 预览端点对未登记威胁条目给出同一告警（预览/导入口径一致）。

// Given 同形态 lbbak 包投递预览端点。
// When 预览执行。
// Then 预览 warnings 同样携带未登记告警（预览/导入口径一致）。
func TestLbbakValidate_unregistered_threat_entry_warns(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := buildLbbakWithExtraThreatEntry(t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, EmptyConfigIfNil: true}), []byte("1.2.3.4\n"))
	rec := postLbbakValidate(t, h, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "未登记") {
		t.Fatalf("预览应携带 manifest 未登记条目告警: %s", rec.Body.String())
	}
}

// 导入路径的持锁序以实际实现为准：排空 → wafFileMu → CaddyOpLock。
// Given CaddyOpLock（=caddyOpMu 共享实例）被预持。
// When 含 WAF 文件相位的 lbbak 导入启动。
// Then 导入必须先取得 wafFileMu 才阻塞在 CaddyOpLock 上——这是可观测的锁序
// 判据（若实现先取 CaddyOpLock，此刻 wafFileMu 仍空闲）。反向嵌套
// （持 CaddyOpLock 再取 wafFileMu）即 AB-BA。
func TestLbbakImport_acquiresWafLockBeforeCaddyOpLock(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	crsDir, _ := overrideTestWafPaths(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (6,'local-admin-lockorder-b','hash','admin',1)`); err != nil {
		t.Fatal(err)
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
	exportRec := httptest.NewRecorder()
	g.ServeHTTP(exportRec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules,waf_files", nil))
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportRec.Code, exportRec.Body.String())
	}
	payload := exportRec.Body.Bytes()

	services.CaddyOpLock.Lock()
	released := false
	unlockCaddy := func() {
		if !released {
			services.CaddyOpLock.Unlock()
			released = true
		}
	}
	defer unlockCaddy()

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/config/import?sections=rules,waf_files", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/octet-stream")
		g.ServeHTTP(rec, req)
		done <- rec.Code
	}()

	locker, ok := services.WafFileLock().(interface {
		TryLock() bool
		Unlock()
	})
	if !ok {
		unlockCaddy()
		<-done
		t.Fatal("WAF lock does not expose TryLock")
	}
	wafHeld := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !locker.TryLock() {
			wafHeld = true
			break
		}
		locker.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	if !wafHeld {
		unlockCaddy()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
		}
		t.Fatal("CaddyOpLock 被预持期间导入未持有 wafFileMu——持锁序反了（CaddyOpLock→wafFileMu 即 AB-BA）")
	}

	unlockCaddy()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("import status=%d, want 200（锁序正确时导入应正常完成）", code)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("释放 CaddyOpLock 后导入 20s 内未完成")
	}
}
