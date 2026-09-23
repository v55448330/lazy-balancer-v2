package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 威胁情报库备份接入（v2.3.x）：security_threat_sources 随「安全防护」节
// 导出；导入拒绝伪造源（name 不在三源种子集合内 → 400，防伪造 URL 源）；
// 开关值经导入往返保持。威胁文件本体不进备份（还原后由更新任务补齐）。
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

	body := completeBackupJSON(t, map[string][]map[string]any{
		"security_threat_sources": {
			{"id": 1, "name": "ustc", "display_name": "中科大黑 IP", "url": "https://blackip.ustc.edu.cn/list.php?txt", "format": "plain", "update_enabled": 1, "apply_enabled": 1},
			{"id": 99, "name": "evil", "display_name": "伪造源", "url": "https://evil.example/list.txt", "format": "plain", "update_enabled": 1, "apply_enabled": 1},
		},
	})

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
