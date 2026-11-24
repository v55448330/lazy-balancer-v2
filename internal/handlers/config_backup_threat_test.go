package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 威胁情报库备份接入（v2.3.x）：security_threat_sources 随「安全防护」节
// 导出；导入拒绝伪造源（name 不在三源种子集合内 → 400，防伪造 URL 源）；
// 开关值经导入往返保持。威胁名单原文自 v2.3.4 起恒随 lbbak 导出与还原
// （条目名见 config_backup_lbbak.go 的 lbbakEntryThreatPrefix，锁内快照后随包）；
// 仅纯 JSON 旧格式走「保留本地、由更新任务补齐」的告警通道。
func TestConfigBackup_threatSourcesExportAndRoundtrip(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	// 导入终态门要求至少一个启用管理员——新库无用户，补种子
	if _, err := db.DB.Exec(`INSERT INTO users (username, password_hash, role, is_enabled) VALUES ('admin','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0, apply_enabled=0 WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	// When：导出（安全防护节，lbbak tar.gz）
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=security", nil))

	// Then：含三源行
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	payload, err := parseLbbak(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse lbbak: %v", err)
	}
	var backup struct {
		Tables map[string][]map[string]any `json:"tables"`
	}
	if err := json.Unmarshal(payload.ConfigJSON, &backup); err != nil {
		t.Fatalf("decode export config: %v", err)
	}
	rows := backup.Tables["security_threat_sources"]
	if len(rows) != 3 {
		t.Fatalf("导出威胁库行数=%d, want 3", len(rows))
	}

	// 还原侧：清空开关后经导入恢复（lbbak 原文回喂）
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1, apply_enabled=1`); err != nil {
		t.Fatal(err)
	}
	importRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(rec.Body.String()))
	req.Header.Set("Content-Type", "application/octet-stream")
	router.ServeHTTP(importRec, req)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var updateEnabled, applyEnabled bool
	if err := db.DB.QueryRow(`SELECT update_enabled, apply_enabled FROM security_threat_sources WHERE name='ustc'`).Scan(&updateEnabled, &applyEnabled); err != nil {
		t.Fatal(err)
	}
	if updateEnabled || applyEnabled {
		t.Fatalf("导入后 ustc 开关=(%v,%v), want (false,false) 按备份恢复", updateEnabled, applyEnabled)
	}
}

func TestConfigBackup_threatSourcesRejectsForgedSource(t *testing.T) {
	// Given：伪造第四源（合法校验和的完整备份 + 伪造行）
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	body := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_threat_sources": {
			{"id": 1, "name": "ustc", "display_name": "中科大黑 IP", "url": "https://blackip.ustc.edu.cn/list.php?txt", "format": "plain", "update_enabled": 1, "apply_enabled": 1},
			{"id": 99, "name": "evil", "display_name": "伪造源", "url": "https://evil.example/list.txt", "format": "plain", "update_enabled": 1, "apply_enabled": 1},
		},
	}, EmptyConfigIfNil: true})

	// When
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	// Then：400 响亮拒绝
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（伪造源响亮拒绝）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "威胁库源不受支持") {
		t.Fatalf("body=%s, want 含「威胁库源不受支持」", rec.Body.String())
	}
}

// 威胁文件收敛文案必须区分两种「备份未携带源文件」成因——上次下载成功但
// 名单为空 vs 导出节点从未成功下载（后者在 update_enabled=0 时不会自动重取，
// 需要可执行提示）。删除行为的「记录与执行面恒一致」不变量保持不变。

func TestThreatReconcileDistinguishesAbsenceReasons(t *testing.T) {
	wafDir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(wafDir)
	t.Cleanup(restore)
	for _, name := range []string{"threat-ustc.iplist", "threat-gptbot.iplist"} {
		if err := os.WriteFile(filepath.Join(wafDir, name), []byte("1.2.3.4\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tables := map[string][]map[string]any{
		"security_threat_sources": {
			// 导出节点上次下载成功但名单为空 —— 备份内为空是真事实。
			{"name": "ustc", "update_status": "success", "version": "2026-10-01", "entry_count": 0},
			// 导出节点从未成功下载 —— 文件缺席不代表空名单。
			{"name": "gptbot", "update_status": "idle", "version": "", "entry_count": 0},
		},
	}
	warnings, _ := reconcileImportedThreatFiles(tables, &lbbakPayload{}, nil)
	joined := strings.Join(zhWarnings(warnings), " | ")
	if !strings.Contains(joined, "ustc") || !strings.Contains(joined, "上次下载成功但无条目") {
		t.Fatalf("warnings=%s, want 成功空名单语义（备份中该源为空）", joined)
	}
	if !strings.Contains(joined, "gptbot") || !strings.Contains(joined, "尚未成功下载") {
		t.Fatalf("warnings=%s, want 未下载语义（备份未携带该源文件）", joined)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist")); !os.IsNotExist(err) {
		t.Fatalf("空名单源的本地旧文件必须删除（记录与执行面一致）")
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-gptbot.iplist")); !os.IsNotExist(err) {
		t.Fatalf("未成功下载源的本地文件同样按记录清空（DB 与执行面一致）")
	}
}

// 生产导出路径的威胁名单证据（不经测试专用组包捷径）：真实 seed 三源
// .iplist(.fast) → GET /config/export → parseLbbak 必须携带 threat/*.iplist
// 条目、内容一致且无未登记条目。此前导出侧无任何此类断言——若
// BuildWafFileBundleInLockChecked 不再返回 ThreatFiles，恢复侧会按「备份未
// 携带该源」删除本地名单，运行态静默少拦。
func TestConfigBackup_exportShipsThreatIplistEntries(t *testing.T) {
	h := newBackupTestHandlers(t)
	wafDir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(wafDir)
	defer restore()

	sources := map[string]string{
		// 编译 .fast 时裸 IP 规范化为 /32（导出原文取自编译产物），期望值
		// 必须同口径。
		"ustc":           "192.0.2.0/24\n198.51.100.7/32\n",
		"firehol_l1":     "203.0.113.0/24\n",
		"et_compromised": "198.18.0.0/15\n",
	}
	for source, content := range sources {
		path := filepath.Join(wafDir, "threat-"+source+".iplist")
		if err := services.WriteThreatIplistCompiled(path, []byte(content)); err != nil {
			t.Fatalf("seed threat source %s: %v", source, err)
		}
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=security", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	payload, err := parseLbbak(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse lbbak: %v", err)
	}
	if len(payload.ThreatIplists) != len(sources) {
		t.Fatalf("导出威胁条目=%v, want 三源", payload.ThreatIplists)
	}
	for source, want := range sources {
		got, ok := payload.ThreatIplists[source]
		if !ok {
			t.Fatalf("导出包缺少 threat/%s.iplist（源=%s）", source, source)
		}
		if normalizeIplistText(string(got)) != normalizeIplistText(want) {
			t.Fatalf("threat/%s.iplist 内容=%q, want %q", source, got, want)
		}
	}
	if len(payload.UnregisteredThreatEntries) != 0 {
		t.Fatalf("导出不得产生未登记威胁条目: %v", payload.UnregisteredThreatEntries)
	}
}

func normalizeIplistText(s string) string {
	return strings.Join(strings.Fields(s), "\n")
}
