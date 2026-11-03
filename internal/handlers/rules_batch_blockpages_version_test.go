package handlers

// 批量设置阶段拦截页停用后的写侧钉测（2026-11 用户裁定：写侧停写、渲染链
// 零消费、DB 4 列保留）。原钉「批量端点推进规则版本列」的语义已不可达——
// 停用端点零写入：不触碰四列、不推进 updated_at/updated_by、不触发行级
// 同步触发器；响应形状保持兼容（bound=0，unchanged=存在的 http 规则数）。

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// withBatchOperator 注入操作者身份（contextUserID 的读取面）。中间件必须在
// 路由注册之前 Use——gin 的 Use 只影响其后注册的路由。
func withBatchOperator(router *gin.Engine, userID float64) *gin.Engine {
	router.Use(func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Next()
	})
	return router
}

// operatorRouter 组装「操作者中间件 + 指定路由」的测试路由器。
func operatorRouter(userID float64, register func(*gin.Engine)) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := withBatchOperator(gin.New(), userID)
	register(router)
	return router
}

func readRuleVersionRow(t *testing.T, caddyID string) (string, int64) {
	t.Helper()
	var updatedAt string
	var updatedBy int64
	if err := db.DB.QueryRow(`SELECT COALESCE(updated_at,''), COALESCE(updated_by,0) FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&updatedAt, &updatedBy); err != nil {
		t.Fatalf("read version columns for %s: %v", caddyID, err)
	}
	return updatedAt, updatedBy
}

func TestBatchRuleBlockPages_deprecatedNoWrite(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := operatorRouter(42, func(router *gin.Engine) {
		router.POST("/rules/batch-block-pages", handler.BatchRuleBlockPages)
	})

	const baseline = "2020-01-01 00:00:00"
	if _, err := db.DB.Exec(`UPDATE lb_rules SET updated_at=?, updated_by=7 WHERE caddy_id IN ('lb_b1','lb_b2','lb_b3')`, baseline); err != nil {
		t.Fatalf("seed baseline version: %v", err)
	}

	// When：即使携带异值四字段，停用端点也必须零写入。
	response := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if response.Code != http.StatusOK {
		t.Fatalf("batch status=%d body=%s, want 200（兼容回执）", response.Code, response.Body.String())
	}
	bound, _ := batchResult(t, response)
	if bound != 0 {
		t.Fatalf("deprecated batch bound=%d, want 0（零写入）", bound)
	}

	// Then：版本列保持基线、操作者不覆盖；四列保持 0。
	for _, id := range []string{"lb_b1", "lb_b2", "lb_b3"} {
		updatedAt, updatedBy := readRuleVersionRow(t, id)
		if updatedAt != baseline {
			t.Fatalf("%s updated_at=%q, want unchanged %q（停用端点零写入）", id, updatedAt, baseline)
		}
		if updatedBy != 7 {
			t.Fatalf("%s updated_by=%d, want 7（不得改写操作者）", id, updatedBy)
		}
		var s1, s1s, s3, s3s int
		if err := db.DB.QueryRow(`SELECT COALESCE(block_page_stage1_id,0),COALESCE(block_page_stage1_status,0),COALESCE(block_page_stage3_id,0),COALESCE(block_page_stage3_status,0) FROM lb_rules WHERE caddy_id=?`, id).Scan(&s1, &s1s, &s3, &s3s); err != nil {
			t.Fatal(err)
		}
		if s1 != 0 || s1s != 0 || s3 != 0 || s3s != 0 {
			t.Fatalf("%s stage columns=(%d,%d,%d,%d), want all zero", id, s1, s1s, s3, s3s)
		}
	}
}
