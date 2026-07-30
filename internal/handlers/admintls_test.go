package handlers

import (
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestUpdateAdminTLS_disables_upload_mode_without_new_files(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
		admin_tls_cert='existing cert',admin_tls_key='existing key' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	var body strings.Builder
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("enabled", "false"); err != nil {
		t.Fatalf("write enabled field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(body.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	var cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_enabled,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&enabled, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if enabled || cert != "existing cert" || key != "existing key" {
		t.Fatalf("saved config=(%v,%q,%q), want disabled with existing files", enabled, cert, key)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
}
