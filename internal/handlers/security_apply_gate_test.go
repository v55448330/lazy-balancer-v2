package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 2026-09-06 裁定 ①② 的契约测试（只有可渲染配置可落库，杜绝坏配置持久化后
// 重启全停）：安全域写入口从家族 1（先提交后重放）转家族 3（事务内应用门控
// 提交）后——
//
//	渲染拒绝（Caddy 4xx）→ 400 + DB 未落库 + 「<动作>失败」审计；
//	传输失败（Caddy 不可达）→ 退化家族 1 语义：200 + 落库 + 重载失败审计
//	（与转换前行为等价，守护不回归）。
func newSecurityGateRouter(t *testing.T, rejectLoads bool) *gin.Engine {
	t.Helper()
	var loads atomic.Int32
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			loads.Add(1)
			if rejectLoads {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"coraza directive invalid: bad rule"}`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.POST("/security/block-pages", h.CreateSecurityBlockPage)
	return router
}

func TestSecurityWrites_caddyRejectionBlocksCommit(t *testing.T) {
	// Given：Caddy 拒绝全部 /load（4xx = 配置本身不可用）
	setupSecurityPolicyTestDB(t)
	router := newSecurityGateRouter(t, true)

	// When：创建一条安全自定义规则
	rec := httptest.NewRecorder()
	body := `{"name":"会被拒绝的规则","conditions":[{"target":"uri","operator":"contains","pattern":"/admin"}],"action":"block","score":5,"enabled":true}`
	request := httptest.NewRequest(http.MethodPost, "/security/custom-rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：400 + 未落库 + 失败审计——坏配置不得进 DB（否则重启即全停）
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create status=%d body=%s, want 400（配置被拒不得落库）", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE name='会被拒绝的规则'").Scan(&count); err != nil {
		t.Fatalf("count custom rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected rule committed rows=%d, want 0", count)
	}
	var failures int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='创建失败' AND resource='自定义规则'").Scan(&failures); err != nil {
		t.Fatalf("count failure audit: %v", err)
	}
	if failures != 1 {
		t.Fatalf("failure audit rows=%d, want 1", failures)
	}
}

func TestSecurityWrites_transportFailureDegradesToCommit(t *testing.T) {
	// Given：Caddy 管理接口不可达（传输失败≠配置非法）
	setupSecurityPolicyTestDB(t)
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := closed.URL
	closed.Close()
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(url)}
	router := gin.New()
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)

	// When：创建安全自定义规则
	rec := httptest.NewRecorder()
	body := `{"name":"传输失败仍可保存","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5,"enabled":true}`
	request := httptest.NewRequest(http.MethodPost, "/security/custom-rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：退化家族 1——200 + 落库 + 重载失败审计（Caddy down 不阻断保存）
	if rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s, want 200（传输失败退化为保存+标记）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "但 Caddy 配置应用失败") {
		t.Fatalf("body=%s, want degrade suffix", rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE name='传输失败仍可保存'").Scan(&count); err != nil {
		t.Fatalf("count custom rules: %v", err)
	}
	if count != 1 {
		t.Fatalf("degraded rule rows=%d, want 1", count)
	}
	var reloadFailures int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='重载失败' AND resource='Caddy服务'").Scan(&reloadFailures); err != nil {
		t.Fatalf("count reload failure audit: %v", err)
	}
	if reloadFailures != 1 {
		t.Fatalf("reload failure audit rows=%d, want 1", reloadFailures)
	}
}
