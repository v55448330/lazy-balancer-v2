package middleware

// jwtAuth 的基建故障通道：会话状态查询失败必须 500 + 明确文案，不得折叠成
// 401（用户被诱导重登、日志无根因）也不得放行。apiKeyAuth 的同型分支已有专测
// （auth_error_classification_test），JWT 侧此前无任何用例覆盖——该分支退化为
// 401 或放行都不会变红。

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestJWTAuth_mapsAuthenticationStateQueryFailureTo500(t *testing.T) {
	// Given：查询注入返回真实 SQL 错误（缺表），模拟瞬时基础设施故障。
	newIsolatedTestDB(t)

	cfg := &config.Config{JWTSecret: "test-secret"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": float64(7), "username": "alice", "pwd_ver": float64(0),
		"jti": "jwt-failure", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	oldQuery := jwtAuthenticationQuery
	jwtAuthenticationQuery = func(database *sql.DB, query string, args ...any) *sql.Row {
		return database.QueryRow("SELECT 1 FROM table_that_does_not_exist")
	}
	t.Cleanup(func() { jwtAuthenticationQuery = oldQuery })

	entered := false
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/probe", func(c *gin.Context) {
		entered = true
		c.Status(http.StatusOK)
	})
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：500 + 基础设施故障文案，且请求不进入下游（不存在带半成品身份的放行）。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（会话状态查询失败不得折叠成 401）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "认证状态查询失败") {
		t.Fatalf("body=%s, want 含「认证状态查询失败」", response.Body.String())
	}
	if entered {
		t.Fatal("查询失败后仍进入下游 handler（认证状态未判定却放行）")
	}
	if strings.Contains(response.Body.String(), "alice") {
		t.Fatalf("body=%s 泄露/回显了未验证的身份", response.Body.String())
	}
}
