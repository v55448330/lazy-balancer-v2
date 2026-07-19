package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetAuditLogs_converts_utc_to_configured_timezone(t *testing.T) {
	// Given
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := mainDB.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, timezone VARCHAR(50)); INSERT INTO global_config VALUES (1, 'Asia/Shanghai')"); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR(50), action VARCHAR(50), resource VARCHAR(100), detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('admin', '登录成功', '用户认证', '', '127.0.0.1', '2026-07-19 12:00:00')"); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/audit-logs", h.GetAuditLogs)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/audit-logs?page=1&page_size=10", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			List []struct {
				CreatedAt string `json:"created_at"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Data.List) != 1 {
		t.Fatalf("expected 1 log, got %d", len(body.Data.List))
	}
	want := time.Date(2026, 7, 19, 20, 0, 0, 0, time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05")
	if body.Data.List[0].CreatedAt != want {
		t.Fatalf("created_at = %q, want %q (UTC converted to Asia/Shanghai)", body.Data.List[0].CreatedAt, want)
	}
}
