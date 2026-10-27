package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestSetupRouter_writeRoutesHaveExplicitAuditClassification(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	intentionalSkip := map[string]struct{}{
		"POST /api/v1/admin-tls/inspect":         {},
		"POST /api/v1/certificates/parse":        {},
		"POST /api/v1/certificates/jobs/current": {},
		"POST /api/v1/cluster/nodes/report":      {},
		// 服务控制机器接口：handler 全路径（含失败）显式记录「服务控制」审计。
		// registration/confirm 已升 Explicit（handler 记录确认/确认失败），
		// 不再属有意跳过。
		"POST /api/v1/cluster/service-control": {},
		"POST /api/v1/config/import/validate":  {},
		"POST /api/v1/config/preview":          {},
		// c：/config/validate 已升为 Explicit（handler 记录校验三态）。
		"POST /api/v1/mcp":             {},
		"POST /api/v1/rules/cert-info": {},
		// v2.1.8 MFA：verify-step 为内部动作（不产生审计；handler 对失败已按
		// 认证拒绝/错误路径细分记录）。setup 已升 Explicit（重绑成功的 pending
		// 密钥轮换由 handler 记「重新绑定/用户认证」，首绑由 activate 记
		// 「启用」）；recovery-codes 已升为 Explicit（handler 显式记录「生成/
		// 恢复码」），两者均不再属有意跳过。
		"POST /api/v1/auth/mfa/verify-step": {},
		// 三库手动更新：审计由任务体 defer 单记（2026-09-29 用户裁定 + 历史
		// 收敛——handler 补记已撤、operator 经 RunContext 归人）。
		"POST /api/v1/security/crs/update":         {},
		"POST /api/v1/security/ip2region/update":   {},
		"POST /api/v1/security/threat-lib/update":  {},
		"POST /api/v1/security/crawler-lib/update": {},
		// 大屏流量采集租约：UI 生命周期内部动作，显式 skip。
		"POST /api/v1/security/overview/threat-screen/collector":   {},
		"DELETE /api/v1/security/overview/threat-screen/collector": {},
		// 任务触发：已升 Explicit——12 个可触发族中 7 族
		// 任务体零审计，handler 对非自记族显式补记「触发/任务监控」（自记族
		// 跳过，保 单记裁定），不再属有意跳过。
	}
	// 直接消费包级单一事实源（middleware.go 的 writeMethods）：此前本测试
	// 自建局部副本（且类型不同）遮蔽它，包级集合扩方法时本测试会静默按旧四
	// 方法枚举，新增方法的写路由跳过「必须有显式审计分类」断言。
	// When
	// 反向对账：intentionalSkip 的每个键必须是真实注册的写路由——路由删除/
	// 改名后旧键恒不命中，跳过声明就成了永不生效的孤儿（后续新增写路由的
	// 分类缺陷被掩盖）。
	registered := map[string]struct{}{}
	for _, route := range router.Routes() {
		registered[route.Method+" "+route.Path] = struct{}{}
	}
	for key := range intentionalSkip {
		if _, ok := registered[key]; !ok {
			t.Fatalf("intentional audit skip 指向未注册路由: %s", key)
		}
	}
	for _, route := range router.Routes() {
		if !writeMethods[route.Method] {
			continue
		}
		key := route.Method + " " + route.Path
		policy := services.ClassifyAuditRoute(route.Method, route.Path)

		// Then
		if _, skipped := intentionalSkip[key]; skipped {
			if policy != services.AuditPolicySkip || !services.IsAuditedWriteRoute(route.Method, route.Path) {
				t.Errorf("intentional audit skip is not explicitly classified: %s", key)
			}
			continue
		}
		if policy == services.AuditPolicySkip {
			t.Errorf("write route has default audit classification: %s", key)
		}
	}
}

// auditMiddleware 本体行为：成功写 → 落一条审计；4xx 跳过；5xx 追加
// 「结果：失败」。此前全包无直接断言（分类表/拒绝留痕/MCP 集成都不覆盖
// 本体），删掉任一分支测试仍绿。
func TestAuditMiddleware_recordsGenericWriteRoute(t *testing.T) {
	newRouter := newMiddlewareTestRouter // 复用其 DB 初始化/清理
	cases := []struct {
		name       string
		status     int
		wantRows   int
		wantFailed bool
	}{
		{"成功写", http.StatusOK, 1, false},
		{"4xx 跳过", http.StatusBadRequest, 0, false},
		{"5xx 追加失败标记", http.StatusInternalServerError, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = newRouter(t)
			before := auditLogRows(t)
			engine := gin.New()
			engine.Use(func(c *gin.Context) {
				c.Set("username", "auditor")
				c.Set("auth_type", "jwt")
				c.Next()
			})
			engine.Use(auditMiddleware())
			engine.POST("/api/v1/caddy/restart", func(c *gin.Context) { c.Status(tc.status) })

			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/caddy/restart", nil))

			if got := auditLogRows(t) - before; got != tc.wantRows {
				t.Fatalf("审计行增量=%d, want %d", got, tc.wantRows)
			}
			if tc.wantRows == 0 {
				return
			}
			var detail string
			if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
				t.Fatal(err)
			}
			hasFailed := strings.Contains(detail, "结果：失败")
			if hasFailed != tc.wantFailed {
				t.Fatalf("detail=%q 含失败标记=%v, want %v", detail, hasFailed, tc.wantFailed)
			}
		})
	}
}

func auditLogRows(t *testing.T) int {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count); err != nil {
		t.Fatalf("count audit_log: %v", err)
	}
	return count
}
