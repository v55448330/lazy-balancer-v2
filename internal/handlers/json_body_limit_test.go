package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// APIMCP41-2（第 41 轮审计，2026-09-19 用户裁定「统一遵循请求体大小配置项限制」）：
// 写/读探测端点的请求体上限统一取全局配置 request_body_max_size_mb
// （0=默认 128，写侧 0-4096），不再逐端点裸奔或各定各的常量。
func TestGuardConfiguredJSONBody(t *testing.T) {
	setupAuthTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, request_body_max_size_mb INTEGER); INSERT INTO global_config VALUES (1,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	gin.SetMode(gin.TestMode)
	mount := func() *gin.Engine {
		r := gin.New()
		r.POST("/probe", func(c *gin.Context) {
			if !guardConfiguredJSONBody(c) {
				return
			}
			var body map[string]any
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"code": 400})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0})
		})
		return r
	}
	serve := func(body string, contentLength int64) int {
		request := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = contentLength
		response := httptest.NewRecorder()
		mount().ServeHTTP(response, request)
		return response.Code
	}
	big := `{"k":"` + strings.Repeat("a", 2<<20) + `"}` // ≈2MB

	t.Run("配置 1MB 时 2MB body 预检 413", func(t *testing.T) {
		if code := serve(big, int64(len(big))); code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d, want 413", code)
		}
	})
	t.Run("配置 1MB 时小 body 放行", func(t *testing.T) {
		if code := serve(`{"k":"v"}`, int64(len(`{"k":"v"}`))); code != http.StatusOK {
			t.Fatalf("status=%d, want 200", code)
		}
	})
	t.Run("chunked 读中途超限走 binding 400", func(t *testing.T) {
		if code := serve(big, -1); code != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400（MaxBytesReader 掐断 → binding 错误）", code)
		}
	})
	t.Run("配置 0 回退默认 128MB", func(t *testing.T) {
		if _, err := db.DB.Exec(`UPDATE global_config SET request_body_max_size_mb=0 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		if code := serve(big, int64(len(big))); code != http.StatusOK {
			t.Fatalf("status=%d, want 200（128MB 默认下 2MB 放行）", code)
		}
	})
	t.Run("越界配置回退默认 128MB", func(t *testing.T) {
		if _, err := db.DB.Exec(`UPDATE global_config SET request_body_max_size_mb=99999 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		if code := serve(big, int64(len(big))); code != http.StatusOK {
			t.Fatalf("status=%d, want 200（越界配置回退 128MB）", code)
		}
	})
}

// nil DB 回退(集成事故钉):无 DB 脚手架的调用形态下 guard 不得 panic,
// 回退默认 128MB 放行正常 body。
func TestGuardConfiguredJSONBody_nilDBFallsBack(t *testing.T) {
	saved := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = saved })
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/probe", func(c *gin.Context) {
		if !guardConfiguredJSONBody(c) {
			return
		}
		c.JSON(http.StatusOK, gin.H{"code": 0})
	})
	body := `{"k":"v"}`
	request := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	r.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200（nil DB 回退默认上限放行）", response.Code)
	}
}
