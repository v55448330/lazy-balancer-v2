package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 第 43 轮审计修复(用户 2026-09-19 裁定按建议修):
// LB43-3 CreateRule/UpdateRule 对 chunked/未知长度超限 body 不映射 413(落 400),
// 与 PutCaddyConfig(caddy.go:843)/导入路径(config_backup.go:1990)口径不一。
// LB43-4 UpdateRule 显式空 upstreams 数组被 len==0 归并进「保留存量」,校验输入
// (0 上游,updateRuleFeatures 按 nil 判空)与落库值(旧上游)分叉;改为 nil 判定后
// 显式 []=清空(零上游为合法形态:渲染整跳过,Round 31 C-2 特判)。
// LB43-5 DuplicateRule 的 TCP 死形态归一漏清 CAProviderID,与 CreateRule(:890)
// /UpdateRule(:1296)两入口不对称——源行遗留 tcp+ca_provider_id≠0 死形态会放大到副本。

// LB43-3①:CreateRule 对 chunked(无 ContentLength)超限 body 期望 413。
func TestCreateRule_chunkedOversizeBodyReturns413(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"x","protocol":"http","listen_port":18080,"upstreams":[{"host":"` + strings.Repeat("a", 1<<20) + `","port":9000}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.ContentLength = -1 // chunked/未知长度:绕过 ContentLength 快路径
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then:MaxBytesReader 截断应映射 413(修复前 CreateRule 预读吞错后 bind 400)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%.200s, want 413", response.Code, response.Body.String())
	}
}

// LB43-3②:UpdateRule 对 chunked 超限 body 期望 413。
func TestUpdateRule_chunkedOversizeBodyReturns413(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_chunked", "chunked", 19092, false, "weighted_round_robin", false)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	body := `{"description":"` + strings.Repeat("b", 1<<20) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_chunked", strings.NewReader(body))
	request.ContentLength = -1
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%.200s, want 413", response.Code, response.Body.String())
	}
}

// LB43-4:UpdateRule 显式 "upstreams":[] 期望显式拒绝(400 点名上游),
// 且存量上游保持不变——修复前 len==0 归并「保留存量」在校验前发生,
// 显式清空被静默吞掉(200+旧上游),校验/落库分叉。
func TestUpdateRule_explicitEmptyUpstreamsRejected(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_clearups", "clear-ups", 19093, false, "weighted_round_robin", false)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/rules/lb_clearups", strings.NewReader(`{"upstreams":[]}`)))

	// Then:400 显式拒绝,存量上游不变(修复前 200 静默保留)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "上游") {
		t.Fatalf("status=%d body=%.200s, want 400 点名上游", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM upstreams WHERE rule_id='lb_clearups'").Scan(&count); err != nil {
		t.Fatalf("count upstreams: %v", err)
	}
	if count != 1 {
		t.Fatalf("upstreams=%d, want 1(拒绝后存量不变)", count)
	}
}

// LB43-5:DuplicateRule 对遗留 tcp+ca_provider_id≠0 死形态源行,副本应归一
// ca_provider_id=0(与 CreateRule/UpdateRule 的 TCP 归一同口径)。
func TestDuplicateRule_clearsCAProviderIDForTCP(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_tcpcap", "tcp-ca", 19094, false, "weighted_round_robin", false)
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=7 WHERE caddy_id='lb_tcpcap'"); err != nil {
		t.Fatalf("seed dead-form ca_provider_id: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_tcpcap/duplicate", nil))

	// Then:副本 ca_provider_id=0(修复前原样携带 7)
	if response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%.200s, want 200/201", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name LIKE 'tcp-ca%' AND ca_provider_id<>0 AND caddy_id<>'lb_tcpcap'").Scan(&count); err != nil {
		t.Fatalf("query duplicate: %v", err)
	}
	if count != 0 {
		t.Fatalf("duplicate carried dead-form ca_provider_id≠0")
	}
}

// 2026-09-20 用户裁定（样式批第 4 项）：复制规则必须携带安全策略绑定——
// 副本不携带会在「启用副本」时形成零防护静默缺口。副本创建即插绑定行，
// 成功消息明示携带数量（审计同批：补偿删除清单本就含绑定表，方向相反）。
func TestDuplicateRule_copiesSecurityPolicyBindings(t *testing.T) {
	// Given：源规则绑定两条策略
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_dupbind", "dup-bind", "dupbind.example.test", 8080, false, "manual", false)
	for i, name := range []string{"bind-a", "bind-b"} {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES (?, 'off', 'stage3', 1)`, name)
		if err != nil {
			t.Fatal(err)
		}
		pid, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_dupbind',?)`, pid); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dupbind/duplicate", nil))

	// Then：201 + 副本（name LIKE 'dup-bind（副本）%'）携带同样两条绑定
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("duplicate status=%d body=%.200s, want 2xx", response.Code, response.Body.String())
	}
	var newID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name LIKE 'dup-bind（副本）%' AND caddy_id<>'lb_dupbind'`).Scan(&newID); err != nil {
		t.Fatalf("find duplicate: %v", err)
	}
	var bindCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=?`, newID).Scan(&bindCount); err != nil {
		t.Fatal(err)
	}
	if bindCount != 2 {
		t.Fatalf("duplicate bindings=%d, want 2 (copied from source)", bindCount)
	}
	// 成功消息明示携带数量
	if !strings.Contains(response.Body.String(), "2 条策略绑定") {
		t.Fatalf("success message must state carried bindings, body=%.300s", response.Body.String())
	}
}
