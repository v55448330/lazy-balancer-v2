package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 2026-09-06 裁定 ①② 的契约测试（只有可渲染配置可落库，杜绝坏配置持久化后
// 重启全停）：安全域写入口从「先提交后重放」转到事务内应用门控提交后——
//
//	渲染拒绝（Caddy 4xx）→ 400 + DB 未落库 + 「<动作>失败」审计；
//	传输失败（Caddy 不可达）→ 退化语义（与直应用通道同口径）：200 + 落库 +
//	重载失败审计
//	（与转换前行为等价，守护不回归）。
func newSecurityGateRouter(t *testing.T, rejectLoads bool) (*gin.Engine, *atomic.Int32) {
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
	return router, &loads
}

func TestSecurityWrites_caddyRejectionBlocksCommit(t *testing.T) {
	// Given：Caddy 拒绝全部 /load（4xx = 配置本身不可用）
	setupSecurityPolicyTestDB(t)
	router, loads := newSecurityGateRouter(t, true)

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
	// 应用门控必须真的尝试过应用且不重试：拒绝=一次 /load 即回滚，
	// 计数器恒 0 说明校验阶段早退、本用例未覆盖应用门。
	if got := loads.Load(); got != 1 {
		t.Fatalf("/load 次数=%d, want 1（拒绝不重试；0 表示未进入应用门）", got)
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
	// 审计项：未装配校验器现在返回显式「未校验」信号（与生产 EnableCLIValidation
	// 装配态对齐）——本用例验证的是「CLI 已通过 + 应用传输失败仍可退化提交」，
	// 因此显式注入通过型校验器。
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return nil })
	router := gin.New()
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)

	// When：创建安全自定义规则
	rec := httptest.NewRecorder()
	body := `{"name":"传输失败仍可保存","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5,"enabled":true}`
	request := httptest.NewRequest(http.MethodPost, "/security/custom-rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, request)

	// Then：退化语义——200 + 落库 + 重载失败审计（Caddy down 不阻断保存）
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

// 裁定 2026-09-07（残余项处置）：安全域写路径与规则域共享 caddyOpMu——
// 跨域并发写（规则+安全）不再有渲染/应用交错窗口。
func TestSecurityWrites_serializeWithRuleWrites(t *testing.T) {
	withIsolatedGlobal(t)
	// Given
	setupSecurityPolicyTestDB(t)
	handler, _, _ := newAuditRuleHandlers(t, 0)
	router := gin.New()
	router.POST("/security/custom-rules", handler.CreateSecurityCustomRule)
	body := `{"name":"串行化","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5,"enabled":true}`

	// When：规则域视角持锁（模拟并发的规则写/手动重载），安全写必须阻塞
	handler.caddyOpMu.Lock()
	prelockReached := make(chan struct{})
	oldPrelockHook := createSecurityCustomRulePreLockHook
	createSecurityCustomRulePreLockHook = func() { close(prelockReached) }
	t.Cleanup(func() { createSecurityCustomRulePreLockHook = oldPrelockHook })
	done := make(chan struct{})
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/security/custom-rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(httptest.NewRecorder(), request)
		close(done)
	}()
	// 已确证请求到达 caddyOpMu 入口且主协程仍持锁，因此它不可能已经完成；
	// 不再用 200ms 作为「尚未被调度」的假绿窗口。
	select {
	case <-prelockReached:
	case <-time.After(5 * time.Second):
		handler.caddyOpMu.Unlock()
		t.Fatal("security write did not reach caddyOpMu")
	}
	select {
	case <-done:
		handler.caddyOpMu.Unlock()
		t.Fatal("安全写未与规则写共享 caddyOpMu（持锁期间应阻塞）")
	default:
	}

	// Then：释放后安全写完成且成功
	handler.caddyOpMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("释放锁后安全写未完成（疑似死锁）")
	}
}

// （源码文本断言退役）：绑定必须先于 caddyOpMu——可观察契约是
// 「请求体尚未到齐时不得持共享锁」。以阻塞 body 证明：处理器读完 body 之后才
// 触碰 caddyOpMu，慢客户端不会把规则域/安全域的全部写操作串行化在锁上。
func TestSecurityWrite_parsesBodyBeforeCaddyOpLock(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.POST("/security/ip-lists", h.CreateIPList)

	cases := []struct {
		name string
		path string
		body string
	}{
		{"custom rule", "/security/custom-rules", `{"name":"慢体规则","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}],"action":"block","score":5,"enabled":true}`},
		{"ip list", "/security/ip-lists", `{"name":"慢体名单","category":"测试","entries":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := newGatedRequestBody(tc.body)
			req := httptest.NewRequest(http.MethodPost, tc.path, body)
			req.Header.Set("Content-Type", "application/json")
			done := make(chan struct{})
			go func() {
				router.ServeHTTP(httptest.NewRecorder(), req)
				close(done)
			}()

			// body 已被读取（处理器已进入绑定阶段，仍阻塞在 body 上）
			select {
			case <-body.started:
			case <-time.After(5 * time.Second):
				close(body.release)
				t.Fatal("处理器未开始读取请求体")
			}
			// 此刻共享锁必须空闲：绑定先于加锁
			if !h.caddyOpMu.TryLock() {
				close(body.release)
				t.Fatalf("%s: 请求体未到齐即持有 caddyOpMu（绑定被锁串行化）", tc.name)
			}
			h.caddyOpMu.Unlock()

			close(body.release)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: body 放行后请求未完成", tc.name)
			}
		})
	}
}

// gatedRequestBody 在首次 Read 时通知 started，随后阻塞到 release 关闭才交付
// 完整 JSON（模拟慢客户端）。
type gatedRequestBody struct {
	payload []byte
	offset  int
	started chan struct{}
	release chan struct{}
}

func newGatedRequestBody(payload string) *gatedRequestBody {
	return &gatedRequestBody{payload: []byte(payload), started: make(chan struct{}, 1), release: make(chan struct{})}
}

func (b *gatedRequestBody) Read(p []byte) (int, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	if b.offset >= len(b.payload) {
		return 0, io.EOF
	}
	n := copy(p, b.payload[b.offset:])
	b.offset += n
	return n, nil
}
