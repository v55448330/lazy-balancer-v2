package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// (用户 2026-09-19 裁定按建议修)
// CreateRule/UpdateRule 对 chunked/未知长度超限 body 不映射 413(落 400),
// 与 PutCaddyConfig/导入路径(config_backup.go)口径不一。
// UpdateRule 显式空 upstreams 数组曾被 len==0 归并进「保留存量」;改为
// nil 判定区分「省略」与「显式 []」——显式 [] 经 validateRulePayloadBeforeSave
// 「至少需要一个上游服务器」400 拒绝（纠正：零上游非合法形态，
// 本文件早期头注释「显式 []=清空（零上游为合法形态）」与现行语义相反，已更正；
// 引用一律用函数名，不写行号——行号漂移曾致三处误导）。
// DuplicateRule 的 TCP 死形态归一漏清 CAProviderID,与 CreateRule/UpdateRule
// 两入口不对称——源行遗留 tcp+ca_provider_id≠0 死形态会放大到副本。

// CreateRule 对 chunked(无 ContentLength)超限 body 期望 413。
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

// UpdateRule 对 chunked 超限 body 期望 413。
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

// UpdateRule 显式 "upstreams":[] 期望显式拒绝(400 点名上游),
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

// DuplicateRule 对遗留 tcp+ca_provider_id≠0 死形态源行,副本应归一
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
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%.200s, want 201", response.Code, response.Body.String())
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
	for _, name := range []string{"bind-a", "bind-b"} {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES (?, 'off', 'stage3', 1)`, name)
		if err != nil {
			t.Fatal(err)
		}
		pid, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_dupbind',?)`, pid); err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dupbind/duplicate", nil))

	// Then：201 + 副本（name LIKE 'dup-bind（副本）%'）携带同样两条绑定
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%.200s, want 201", response.Code, response.Body.String())
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

// 复制必须携带绑定的执行序（rank），不只携带数量：读路径按 (rank ASC,
// policy_id ASC) 排序（GetSecurityPoliciesForRule），复制丢 rank 落 DDL
// 默认 0 会让副本执行序退化为 policy_id 序——策略按序评估，源的非平凡序
// 与副本逐位不一致即防护语义漂移。源序刻意与 policy_id 序相反以区分两种
// 排序来源。
func TestDuplicateRule_preservesSecurityPolicyBindingRankOrder(t *testing.T) {
	// Given：源规则三条绑定，rank 序与 policy_id 序相反（非平凡序）
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_duprank", "dup-rank", "duprank.example.test", 8080, false, "manual", false)
	var pids []int
	for _, name := range []string{"rank-a", "rank-b", "rank-c"} {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES (?, 'off', 'stage3', 1)`, name)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := res.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		pids = append(pids, int(pid))
	}
	rankOf := map[int]int{pids[0]: 3, pids[1]: 1, pids[2]: 2}
	for _, pid := range pids {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES ('lb_duprank',?,?)`, pid, rankOf[pid]); err != nil {
			t.Fatal(err)
		}
	}
	wantOrder := []int{pids[1], pids[2], pids[0]}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_duprank/duplicate", nil))

	// Then：201 + 副本的读路径顺序与源逐位一致
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%.200s, want 201", response.Code, response.Body.String())
	}
	var newID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name LIKE 'dup-rank（副本）%' AND caddy_id<>'lb_duprank'`).Scan(&newID); err != nil {
		t.Fatalf("find duplicate: %v", err)
	}
	gotIDs := func(ruleID string) []int {
		t.Helper()
		policies := services.GetSecurityPoliciesForRule(ruleID)
		ids := make([]int, 0, len(policies))
		for _, p := range policies {
			ids = append(ids, p.ID)
		}
		return ids
	}
	sourceOrder := gotIDs("lb_duprank")
	if len(sourceOrder) != 3 {
		t.Fatalf("source policies=%v, want 3 seeded bindings", sourceOrder)
	}
	for i, pid := range wantOrder {
		if sourceOrder[i] != pid {
			t.Fatalf("source order=%v, want %v（rank 非平凡序前提）", sourceOrder, wantOrder)
		}
	}
	copyOrder := gotIDs(newID)
	if len(copyOrder) != len(sourceOrder) {
		t.Fatalf("copy policies=%v, want same length as source %v", copyOrder, sourceOrder)
	}
	for i := range sourceOrder {
		if copyOrder[i] != sourceOrder[i] {
			t.Fatalf("copy order=%v, want %v（逐位与源一致；丢 rank 会退化为 policy_id 序）", copyOrder, sourceOrder)
		}
	}
}

// 跨模式残留清理——生效来源非 manual 不保留证书材料；
// 非 acme_dns 的 ca_provider_id 归零（manual→manual 编辑同样自愈）。
func TestUpdateRule_clearsCrossSourceTLSResidue(t *testing.T) {
	t.Run("manual-to-acme-drops-certificate-material", func(t *testing.T) {
		handler := newRuleFeatureTestHandlers(t)
		seedAuditRule(t, "lb_a87_cross", "cross", "cross-a87.example.test", 8088, false, "manual", true)
		seedAuditUpstream(t, "lb_a87_cross")
		certPEM, keyPEM, err := generateTestCert("cross-a87.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		if _, err := db.DB.Exec("UPDATE lb_rules SET tls_cert=?,tls_key=? WHERE caddy_id='lb_a87_cross'", certPEM, keyPEM); err != nil {
			t.Fatalf("seed material: %v", err)
		}
		configID := seedR52CertificateConfig(t)
		router := gin.New()
		router.PUT("/rules/:caddy_id", handler.UpdateRule)
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_a87_cross",
			strings.NewReader(fmt.Sprintf(`{"tls_source":"acme_dns","acme_config_id":%d}`, configID)))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var storedCert, storedKey, source string
		if err := db.DB.QueryRow("SELECT COALESCE(tls_cert,''),COALESCE(tls_key,''),COALESCE(tls_source,'') FROM lb_rules WHERE caddy_id='lb_a87_cross'").Scan(&storedCert, &storedKey, &source); err != nil {
			t.Fatalf("read rule: %v", err)
		}
		if source != "acme_dns" {
			t.Fatalf("tls_source=%q, want acme_dns", source)
		}
		if storedCert != "" || storedKey != "" {
			t.Fatal("acme 源规则仍保留手动证书材料——私钥正文会随导出/备份/快照放大")
		}
	})

	t.Run("manual-edit-zeroes-stale-ca-provider", func(t *testing.T) {
		handler := newRuleFeatureTestHandlers(t)
		seedAuditRule(t, "lb_a87_ca", "ca", "ca-a87.example.test", 8089, false, "manual", false)
		seedAuditUpstream(t, "lb_a87_ca")
		var providerID int
		if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
			t.Fatalf("read CA provider: %v", err)
		}
		if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id='lb_a87_ca'", providerID); err != nil {
			t.Fatalf("seed stale provider: %v", err)
		}
		router := gin.New()
		router.PUT("/rules/:caddy_id", handler.UpdateRule)
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_a87_ca", strings.NewReader(`{"description":"touch"}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var storedProvider int
		if err := db.DB.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id='lb_a87_ca'").Scan(&storedProvider); err != nil {
			t.Fatalf("read rule: %v", err)
		}
		if storedProvider != 0 {
			t.Fatalf("ca_provider_id=%d, want 0（manual 行不得继承陈旧 CA 提供商）", storedProvider)
		}
	})
}

// 空 tls_source（API/MCP 创建时省略来源且 TLS 关闭，或旧版本/导入行）
// 同样不消费 acme_config_id——Create 与 Update 都必须清零该跨模式死引用，
// 否则引用会随导出/备份/集群快照长期携带（渲染/签发零消费，全部消费方都以
// enable_tls=1 && tls_source='acme_dns' 门控）。
func TestRuleWrites_emptyTLSSourceClearsACMEReference(t *testing.T) {
	t.Run("create-omitted-source", func(t *testing.T) {
		handler := newRuleFeatureTestHandlers(t)
		router := gin.New()
		router.POST("/rules", handler.CreateRule)
		body := `{"name":"empty-src-create","protocol":"http","domain":"empty-src-create.example.test","listen_port":8090,"enable_tls":false,"acme_config_id":7,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s, want 201", recorder.Code, recorder.Body.String())
		}
		var source string
		var acmeID int
		if err := db.DB.QueryRow("SELECT COALESCE(tls_source,''), COALESCE(acme_config_id,0) FROM lb_rules WHERE name='empty-src-create'").Scan(&source, &acmeID); err != nil {
			t.Fatalf("read created rule: %v", err)
		}
		if source != "" {
			t.Fatalf("tls_source=%q, want 空来源（省略即空）", source)
		}
		if acmeID != 0 {
			t.Fatalf("acme_config_id=%d, want 0（非 acme_dns 不保留 ACME 引用）", acmeID)
		}
	})

	t.Run("update-stored-empty-source", func(t *testing.T) {
		handler := newRuleFeatureTestHandlers(t)
		seedAuditRule(t, "lb_empty_acme", "empty-acme", "empty-acme.example.test", 8091, true, "", false)
		seedAuditUpstream(t, "lb_empty_acme")
		if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=7 WHERE caddy_id='lb_empty_acme'"); err != nil {
			t.Fatalf("seed stale acme reference: %v", err)
		}
		router := gin.New()
		router.PUT("/rules/:caddy_id", handler.UpdateRule)
		request := httptest.NewRequest(http.MethodPut, "/rules/lb_empty_acme", strings.NewReader(`{"description":"touch"}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var acmeID int
		if err := db.DB.QueryRow("SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id='lb_empty_acme'").Scan(&acmeID); err != nil {
			t.Fatalf("read rule: %v", err)
		}
		if acmeID != 0 {
			t.Fatalf("acme_config_id=%d, want 0（空来源不保留 ACME 引用）", acmeID)
		}
	})
}
