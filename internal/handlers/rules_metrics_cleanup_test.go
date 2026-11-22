package handlers

// （用户裁定）：删除规则后的 metrics_history 清理失败
// 此前仅 Logf，无审计、无重试。裁定：改为操作审计 + taskengine 周期任务
// （maintenance-retention 孤儿指标步）有界收敛重试，不阻断删除。

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// Given metrics 库不可写（规则删除时 DELETE metrics_history 失败）。
// When 删除规则。
// Then 删除照常 200（不阻断），且「清理失败/规则指标」操作审计留痕并点名规则。
func TestDeleteRule_metricsCleanupFailureAudited(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_a86metrics", "a86-metrics", "a86-metrics.example.test", 18081, true, "manual", false)
	seedAuditUpstream(t, "lb_a86metrics")
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)

	// 破坏 metrics 库：关闭后的 *sql.DB 使 Exec 恒返回 sql.ErrConnDone。
	broken, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open scratch metrics db: %v", err)
	}
	if err := broken.Close(); err != nil {
		t.Fatalf("close scratch metrics db: %v", err)
	}
	previousMetricsDB := db.MetricsDB
	db.MetricsDB = broken
	t.Cleanup(func() { db.MetricsDB = previousMetricsDB })

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_a86metrics", nil))

	// Then：删除不阻断
	if response.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200（清理失败不得阻断删除）", response.Code, response.Body.String())
	}
	var remaining int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_a86metrics'`).Scan(&remaining); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("规则仍存在（count=%d），删除未完成", remaining)
	}

	// Then：失败必须落操作审计（此前仅 Logf，无审计）
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='清理失败' AND resource='规则指标' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("metrics 清理失败未落操作审计: %v", err)
	}
	if !strings.Contains(detail, "lb_a86metrics") {
		t.Fatalf("审计详情未点名规则: %q", detail)
	}
}
