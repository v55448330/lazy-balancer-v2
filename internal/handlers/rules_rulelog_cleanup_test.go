package handlers

// 删除规则的访问日志清理失败必须留痕：与规则指标 / 证书任务日志同口径——
// 清理失败不阻断删除（规则已提交），但残留文件此前完全静默（函数无返回值，
// os.Remove 错误被丢弃），运维无从发现磁盘残留。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given 规则日志目录不可写（权限故障）且该规则存在访问日志。
// When 删除规则。
// Then 删除照常 200（不阻断），且「清理失败/规则日志」操作审计留痕并点名路径。
func TestDeleteRule_ruleLogCleanupFailureAudited(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 忽略目录权限位，无法构造规则日志清理失败")
	}
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_rulelog", "rulelog", "rulelog.example.test", 18091, true, "manual", false)
	seedAuditUpstream(t, "lb_rulelog")
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)

	logDir := t.TempDir()
	restore := services.SetRuleLogDirForTest(logDir)
	t.Cleanup(restore)
	if err := os.WriteFile(filepath.Join(logDir, "lb_rulelog.log"), []byte("line\n"), 0o644); err != nil {
		t.Fatalf("seed rule log: %v", err)
	}
	if err := os.Chmod(logDir, 0o500); err != nil {
		t.Fatalf("chmod rule log dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(logDir, 0o755) })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/rules/lb_rulelog", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200（日志清理失败不得阻断删除）", response.Code, response.Body.String())
	}
	var remaining int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_rulelog'`).Scan(&remaining); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("规则仍存在（count=%d），删除未完成", remaining)
	}

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='清理失败' AND resource='规则日志' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("规则日志清理失败未落操作审计: %v", err)
	}
	if !strings.Contains(detail, "lb_rulelog") || !strings.Contains(detail, "lb_rulelog.log") {
		t.Fatalf("审计明细=%q，want 点名规则与残留路径", detail)
	}

	// 恢复可写后重删（同规则已不存在，仍走日志清理）应为零失败——对照形状：
	// 只读目录是唯一失败源，权限恢复后不得再报清理失败。
	if err := os.Chmod(logDir, 0o755); err != nil {
		t.Fatalf("restore dir mode: %v", err)
	}
	if err := services.RemoveRuleLogFiles("lb_rulelog"); err != nil {
		t.Fatalf("权限恢复后清理仍失败: %v", err)
	}
}
