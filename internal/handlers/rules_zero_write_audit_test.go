package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 已停用的批量拦截页端点是零写入端点：预读规则失败时没有任何「更新」发生，
// 不得把它记成「更新失败」审计（运维按审计排障会把读故障误判为写失败）；
// 响应仍是 500 + 固定文案。
func TestBatchRuleBlockPages_readFailureNotAuditedAsUpdateFailure(t *testing.T) {
	newBackupTestHandlers(t)
	before := countAuditRows(t, "更新失败", "负载规则")
	// 制造预读失败：规则表不可读（等价于查询期 DB 故障）。
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/batch-block-pages", (&Handlers{}).BatchRuleBlockPages)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/batch-block-pages",
		strings.NewReader(`{"rule_ids":["lb-a","lb-b"],"block_page_stage1_id":1,"block_page_stage1_status":1}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("预读失败 status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	if got := countAuditRows(t, "更新失败", "负载规则") - before; got != 0 {
		t.Fatalf("零写入端点的读失败不得记为「更新失败」审计: 新增 %d 行", got)
	}
}
