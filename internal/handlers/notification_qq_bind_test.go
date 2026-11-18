package handlers

// QQ 绑定码闭环钉测：生成 → 模拟 QQ 侧「绑定 <code>」指令消费（与
// botlink.bindBotChannel 同落库：通道 target 写 openid+码消费）→ 轮询
// bound=true；同用户旧码作废。身份注入对齐中间件（c.Set user_id/role）。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func newQQBindRouter(t *testing.T, userID int64) *gin.Engine {
	t.Helper()
	h := newFakeCaddyHandlers(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", float64(userID))
		c.Set("role", "admin")
		c.Next()
	})
	router.POST("/notification/qq/bind-code", h.PostQQBindCode)
	router.GET("/notification/qq/bind-code", h.GetQQBindCode)
	return router
}

func doGet(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder { return rec }

func TestQQBindCode_generateConsumePoll(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	const uid = int64(7)
	router := newQQBindRouter(t, uid)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/qq/bind-code", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("generate status=%d body=%s", w.Code, w.Body.String())
	}
	var code string
	if err := db.DB.QueryRow(`SELECT code FROM qq_bind_codes WHERE user_id=?`, uid).Scan(&code); err != nil || len(code) != 6 {
		t.Fatalf("bind code=%q (err=%v), want 6 位数字", code, err)
	}

	// 模拟 QQ 侧「绑定 <code>」指令消费（与 botlink.bindBotChannel 同落库）
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled, created_at, updated_at)
		VALUES (?, 'qq', 'QQ 机器人', ?, 1, datetime('now'), datetime('now'))`,
		uid, `{"openid":"OPENID_A"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`DELETE FROM qq_bind_codes WHERE code=?`, code); err != nil {
		t.Fatal(err)
	}

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/notification/qq/bind-code", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("poll status=%d", w2.Code)
	}
	if !contains2(w2.Body.String(), `"bound":true`) || !contains2(w2.Body.String(), `"openid":"OPENID_A"`) {
		t.Fatalf("poll body=%s, want bound=true+openid", w2.Body.String())
	}
}

func contains2(hay, needle string) bool {
	return len(hay) >= len(needle) && (needle == "" || indexOf2(hay, needle) >= 0)
}

func indexOf2(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestQQBindCode_oldCodeInvalidated(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	const uid = int64(9)
	router := newQQBindRouter(t, uid)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/qq/bind-code", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("first generate status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/qq/bind-code", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("second generate status=%d", w.Code)
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM qq_bind_codes WHERE user_id=?`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("bind codes=%d, want 1（旧码作废）", n)
	}
}
