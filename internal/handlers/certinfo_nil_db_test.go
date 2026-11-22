package handlers

// DB 未装配/关停窗防护（db.Close 会把包级句柄置 nil）：批量证书信息端点
// 此前裸解引用 db.DB，nil 时 panic；必须改为 500 固定文案。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetRulesCertInfo_returns500WhenDatabaseUnavailable(t *testing.T) {
	oldDB := db.DB
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldDB)
	})

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)
	req := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["lb_a"]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（DB 未装配不得 panic/静默）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "批量读取规则证书配置失败") {
		t.Fatalf("body=%s, want 固定失败文案", rec.Body.String())
	}
}
