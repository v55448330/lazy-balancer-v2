package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 导入窗口写门：security 族写端点（策略/自定义规则/拦截页/IP 名单）写入的表
// 全部在导入的「安全防护」分类全量替换清单内。它们只取 caddyOpMu（排队、不
// fast-fail）：窗口内的保存会悬挂到导入提交之后再按陈旧 id 落库，静默改写刚
// 恢复的安全配置（策略被弱化 / 名单条目被改回）。与 settings/users/cert/规则×5
// 同口径 409 fast-fail，且门必须早于参数解析与取锁。
func TestSecurityWrites409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
	router.DELETE("/security/custom-rules/:id", h.DeleteSecurityCustomRule)
	router.POST("/security/block-pages", h.CreateSecurityBlockPage)
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	router.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
	router.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	router.PUT("/security/rules/:caddy_id/policies", h.SetRuleSecurityPolicies)
	router.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)
	router.POST("/security/policies/batch-bind", h.BatchBindSecurityPolicies)
	router.POST("/security/policies/:id/split", h.SplitSecurityPolicy)
	router.DELETE("/security/policies/:id/bind/:caddy_id", h.UnbindRuleFromPolicy)
	router.POST("/security/ip-lists", h.CreateIPList)
	router.PUT("/security/ip-lists/:id", h.UpdateIPList)
	router.DELETE("/security/ip-lists/:id", h.DeleteIPList)
	router.POST("/security/ip-lists/:id/ips", h.AddIPToList)
	router.DELETE("/security/ip-lists/:id/ips", h.RemoveIPFromList)

	// 落库侧快照：409 必须是「未落库」而不是「落库后报错」。
	tables := []string{"security_policies", "security_custom_rules", "security_block_pages", "security_ip_lists", "security_policy_bindings"}
	countsBefore := make(map[string]int64, len(tables))
	for _, table := range tables {
		countsBefore[table] = rowCountOf(t, table)
	}

	// 模拟导入会话进行中（configImportBusy 的事实源：窗口计数）。
	beginImportWindowForTest(t)

	calls := []struct{ method, path, body string }{
		{"POST", "/security/custom-rules", `{"name":"waf","rule":"SecRule"}`},
		{"PUT", "/security/custom-rules/1", `{"name":"waf2"}`},
		{"DELETE", "/security/custom-rules/1", ""},
		{"POST", "/security/block-pages", `{"name":"p","content":"x"}`},
		{"PUT", "/security/block-pages/1", `{"name":"p2"}`},
		{"DELETE", "/security/block-pages/1", ""},
		{"POST", "/security/policies", `{"name":"policy"}`},
		{"PUT", "/security/policies/1", `{"name":"policy2"}`},
		{"DELETE", "/security/policies/1", ""},
		{"POST", "/security/policies/1/bind", `{"rule_caddy_id":"lb_x"}`},
		{"PUT", "/security/rules/lb_x/policies", `{"policy_ids":[1]}`},
		{"POST", "/security/policies/1/bindings/bulk", `{"bind":["lb_x"]}`},
		{"POST", "/security/policies/batch-bind", `{"rule_ids":["lb_x"],"policy_ids":[1],"mode":"append"}`},
		{"POST", "/security/policies/1/split", `{"rule_caddy_ids":["lb_x"]}`},
		{"DELETE", "/security/policies/1/bind/lb_x", ""},
		{"POST", "/security/ip-lists", `{"name":"l","category":"whitelist","entries":"[]"}`},
		{"PUT", "/security/ip-lists/1", `{"name":"l2"}`},
		{"DELETE", "/security/ip-lists/1", ""},
		{"POST", "/security/ip-lists/1/ips", `{"ip":"10.0.0.1"}`},
		{"DELETE", "/security/ip-lists/1/ips", `{"ip":"10.0.0.1"}`},
	}
	if len(calls) != 20 {
		t.Fatalf("写端点清单=%d，want 20（增删端点时须同步本清单与门）", len(calls))
	}
	for _, call := range calls {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口内安全域写必须 fast-fail）",
				call.method, call.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "配置导入进行中") {
			t.Fatalf("%s %s body=%s, want 配置导入进行中 文案", call.method, call.path, rec.Body.String())
		}
	}

	for _, table := range tables {
		if got := rowCountOf(t, table); got != countsBefore[table] {
			t.Fatalf("%s 行数 %d → %d：窗口内必须零落库", table, countsBefore[table], got)
		}
	}
}

// 对照：导入窗口外照常处理（409 门不得做成恒拒）。
func TestSecurityWritesAllowedOutsideImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/ip-lists", h.CreateIPList)
	router.POST("/security/block-pages", h.CreateSecurityBlockPage)
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.POST("/security/policies", h.CreateSecurityPolicy)

	calls := []struct{ path, body string }{
		{"/security/ip-lists", `{"name":"l-outside","category":"whitelist","entries":"[]"}`},
		{"/security/block-pages", `{"name":"p-outside","content":"x"}`},
		{"/security/custom-rules", `{"name":"waf-outside","rule":"SecRule"}`},
		{"/security/policies", `{"name":"policy-outside"}`},
	}
	for _, call := range calls {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code == http.StatusConflict {
			t.Fatalf("%s status=409, want 非冲突（导入窗口外必须放行）: %s", call.path, rec.Body.String())
		}
	}
}

// 结构性覆盖判据：本族每个写端点都以 caddyOpMu.Lock() 串行化（15+5 处，与
// 上表 20 个端点一一对应）——凡持该锁的 handler 必须在入口先过导入门。
// 「单源门函数 + 逐端点手工接」正是漏接的根源：新增写端点时若只加锁不加门，
// 本测试失败并点名函数。
func TestSecurityWriteHandlersDeclareImportGate(t *testing.T) {
	for _, file := range []string{"security.go", "securityiplists.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		funcs := splitHandlerFuncs(string(source))
		gated := 0
		for name, body := range funcs {
			if !strings.Contains(body, "caddyOpMu.Lock()") {
				continue
			}
			gated++
			if !strings.Contains(body, "rejectWriteDuringImport(") {
				t.Errorf("%s: %s 持 caddyOpMu 写库但未接导入窗口门（rejectWriteDuringImport）", file, name)
			}
		}
		if gated == 0 {
			t.Fatalf("%s: 未识别到任何持锁 handler（扫描器失效）", file)
		}
	}
}

// splitHandlerFuncs 把源码切成「handler 名 → 函数体」映射（仅
// `func (h *Handlers) Name(c *gin.Context) {` 形态）。按大括号配对切分足够
// 定位本族 handler——函数体内无裸字符串包含未配对大括号的形态。
func splitHandlerFuncs(source string) map[string]string {
	const prefix = "func (h *Handlers) "
	out := make(map[string]string)
	for offset := 0; ; {
		idx := strings.Index(source[offset:], prefix)
		if idx < 0 {
			return out
		}
		start := offset + idx
		headerEnd := strings.Index(source[start:], "(c *gin.Context) {")
		if headerEnd < 0 {
			offset = start + len(prefix)
			continue
		}
		nameEnd := start + len(prefix)
		name := source[nameEnd : start+headerEnd]
		bodyStart := start + headerEnd + len("(c *gin.Context) {") - 1
		depth := 0
		end := -1
		for i := bodyStart; i < len(source); i++ {
			switch source[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i + 1
				}
			}
			if end > 0 {
				break
			}
		}
		if end < 0 {
			return out
		}
		out[name] = source[bodyStart:end]
		offset = end
	}
}

func rowCountOf(t *testing.T, table string) int64 {
	t.Helper()
	var count int64
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}
