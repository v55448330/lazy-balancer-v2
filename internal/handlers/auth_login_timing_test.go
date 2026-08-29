package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
)

// D5-S5（N+11 轮）：Login 的 ErrNoRows 分支不跑 bcrypt 即返 401，与「用户存在
// 但密码错」路径存在 ~bcrypt 量级（数十毫秒）的时序差 → 用户名枚举侧信道。
// 修复：不存在用户也对包级固定 dummy 哈希（init 生成一次，DefaultCost 与真实
// 哈希同档）跑一次注定失败的比较后再返回同形 401。
// 本测试锚定行为不变量：两条 401 路径状态码与响应体逐字节一致。
// 时序断言豁免：毫秒级时序差断言受调度/负载抖动支配，跨机器必然 flaky，
// 不作为回归门——缓解措施为上述等时比较本身（见 auth.go）。
func TestLogin_unknownUserAndWrongPassword_returnIdentical401(t *testing.T) {
	// Given 存在用户 root（真实 bcrypt 哈希，DefaultCost 与生产一致）
	database := setupAuthTestDB(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)
	post := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, request)
		return rec
	}

	// When 用户名不存在 vs 用户名存在但密码错
	recUnknown := post(`{"username":"no-such-user","password":"whatever"}`)
	recWrong := post(`{"username":"root","password":"wrong-password"}`)

	// Then 两者 401 且响应体逐字节一致（不泄露用户名存在性）
	if recUnknown.Code != http.StatusUnauthorized || recWrong.Code != http.StatusUnauthorized {
		t.Fatalf("status unknown=%d wrong=%d, want both 401", recUnknown.Code, recWrong.Code)
	}
	if recUnknown.Body.String() != recWrong.Body.String() {
		t.Fatalf("401 响应体不一致（用户名枚举面）：unknown=%s wrong=%s", recUnknown.Body.String(), recWrong.Body.String())
	}
}
