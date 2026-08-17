package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// Round 25 LOW：Docker Compose 服务名允许下划线（内嵌 DNS 可解析 my_backend），
// isValidHost 需放行 '_'；同时标签首尾须为字母或数字，'-bad.com' 仍被拒绝。
func TestIsValidHost_dockerUnderscoreService(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "docker underscore service", host: "my_backend", want: true},
		{name: "docker underscore fqdn", host: "my_backend-2.default.svc", want: true},
		{name: "plain domain", host: "upstream.example.test", want: true},
		{name: "ip address", host: "127.0.0.1", want: true},
		{name: "leading hyphen label", host: "-bad.com", want: false},
		{name: "trailing hyphen label", host: "bad-.example.test", want: false},
		{name: "space in host", host: "bad host.example.test", want: false},
		{name: "empty label", host: "bad..example.test", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isValidHost(test.host); got != test.want {
				t.Fatalf("isValidHost(%q) = %v, want %v", test.host, got, test.want)
			}
		})
	}
}

// Round 25 LOW：拦截页面内容不能为空，创建与更新均须以 400 拒绝，且不落库。
func TestSecurityBlockPage_rejectsEmptyContent(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/block-pages", handler.CreateSecurityBlockPage)
	router.PUT("/security/block-pages/:id", handler.UpdateSecurityBlockPage)

	// When：创建空白内容
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/security/block-pages", strings.NewReader(`{"name":"blank","content":"   "}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "拦截页面内容不能为空") {
		t.Fatalf("create empty-content status=%d body=%s, want 400 with 拦截页面内容不能为空", response.Code, response.Body.String())
	}

	// When：更新已有页面为空内容
	result, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, created_by) VALUES ('keep', '', '<html></html>', 1)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, _ := result.LastInsertId()
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, "/security/block-pages/"+strconv.FormatInt(pageID, 10), strings.NewReader(`{"name":"keep","content":""}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "拦截页面内容不能为空") {
		t.Fatalf("update empty-content status=%d body=%s, want 400 with 拦截页面内容不能为空", response.Code, response.Body.String())
	}
	var content string
	if err := db.DB.QueryRow("SELECT content FROM security_block_pages WHERE id=?", pageID).Scan(&content); err != nil {
		t.Fatalf("read block page: %v", err)
	}
	if content != "<html></html>" {
		t.Fatalf("empty content overwrote page, got %q", content)
	}
}

// Round 25 LOW：日期面板仅按天禁用过去日期，当天早于现在的时刻仍可选；
// 后端须兜底拒绝创建时已过期的密钥（过期时间不能早于当前时间）。
func TestCreateAPIKey_rejectsPastExpiry(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api-keys", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("role", "admin")
		handler.CreateCurrentUserAPIKey(c)
	})

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api-keys", strings.NewReader(`{"name":"past-key","expires_at":"2000-01-01T00:00:00Z"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "过期时间不能早于当前时间") {
		t.Fatalf("past expiry status=%d body=%s, want 400 with 过期时间不能早于当前时间", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE name='past-key'").Scan(&count); err != nil {
		t.Fatalf("count keys: %v", err)
	}
	if count != 0 {
		t.Fatalf("past-expiry key created, want rejected before insert")
	}
}

// Round 25 LOW：未来过期时间不受影响，正常创建。
func TestCreateAPIKey_acceptsFutureExpiry(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api-keys", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("role", "admin")
		handler.CreateCurrentUserAPIKey(c)
	})

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api-keys", strings.NewReader(`{"name":"future-key","expires_at":"2999-01-01T00:00:00Z"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated {
		t.Fatalf("future expiry status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE name='future-key'").Scan(&count); err != nil {
		t.Fatalf("count keys: %v", err)
	}
	if count != 1 {
		t.Fatalf("future-expiry keys = %d, want 1", count)
	}
}
