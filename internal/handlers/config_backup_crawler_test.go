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

// 爬虫地址库独立源表随「安全防护」节导出/还原，不再借威胁源表通道。
func TestConfigBackup_crawlerSourcesExportAndRoundtrip(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (username, password_hash, role, is_enabled) VALUES ('admin','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	seedCrawlerSource(t, 1, "googlebot", 170)
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0 WHERE name='googlebot'`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	router.POST("/config/import", h.ImportConfigBackup)

	// When
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=security", nil))

	// Then：导出包含独立源表
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
	rows := backup.Tables["security_crawler_sources"]
	if len(rows) != 1 || rows[0]["name"] != "googlebot" {
		t.Fatalf("导出爬虫源行错误: %+v", rows)
	}

	// 还原侧：改回启用后导入，须按备份恢复为关闭
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1 WHERE name='googlebot'`); err != nil {
		t.Fatal(err)
	}
	importRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(rec.Body.String()))
	req.Header.Set("Content-Type", "application/octet-stream")
	router.ServeHTTP(importRec, req)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow(`SELECT update_enabled FROM security_crawler_sources WHERE name='googlebot'`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("导入后 googlebot 应按备份恢复 update_enabled=false")
	}
}

func TestConfigBackup_crawlerSourcesRejectsForgedSource(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	body := completeBackupJSON(t, map[string][]map[string]any{
		"security_crawler_sources": {
			{"id": 99, "name": "evil", "display_name": "伪造爬虫源", "url": "https://evil.example/list.json", "format": "json", "update_enabled": 1},
		},
	})

	// When
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	// Then
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（伪造爬虫源响亮拒绝）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "爬虫地址库源不受支持") {
		t.Fatalf("body=%s, want 含「爬虫地址库源不受支持」", rec.Body.String())
	}
}
