package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"
)

// newMiddlewareTestRouter 用随机空闲端口而非固定 8000：SetupRouter 用它拼
// MCP 内部转发 base URL（http://127.0.0.1:<port>/api/v1），固定 8000 在开发机
// 面板容器常驻监听时会让 tools/call 用例跨进程转发到宿主机真实面板。需要
// 真实转发的用例改走 newMiddlewareTestRouterAtPort 注入自己的 listener 端口。
func newMiddlewareTestRouter(t *testing.T) *gin.Engine {
	return newMiddlewareTestRouterAtPort(t, freeTestPort(t))
}

// freeTestPort 取一个当前空闲的 127.0.0.1 端口（监听后立即释放）。
func freeTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release free port: %v", err)
	}
	return port
}

func newMiddlewareTestRouterAtPort(t *testing.T, port int) *gin.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	cfg := &config.Config{
		Port: port, StaticDir: t.TempDir(), CaddyAdminURL: "http://127.0.0.1:1",
		CaddyMetricsURL: "http://127.0.0.1:1/metrics", MetricsInterval: 60,
		NodeName: "node-test", JWTSecret: "test-secret",
	}
	caddy := services.NewCaddyService(cfg.CaddyAdminURL)
	handler := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddy, MetricsService: services.NewMetricsService(cfg.CaddyMetricsURL, 60),
		SyncService: services.NewSyncService(db.DB, cfg, caddy), ClusterService: services.NewClusterService(db.DB, ""),
		CAProviderService: services.NewCAProviderService(),
	})
	return SetupRouter(handler, cfg)
}

func addClusterRouteTestAPIKey(t *testing.T, userID int, username, role, plain string) {
	t.Helper()
	addRouteTestAPIKeyWithReadOnly(t, userID, username, role, plain, false)
}

// addRouteTestAPIKeyWithReadOnly 建一个可显式指定 read_only 的 Key：生产写侧对
// 非管理员恒写 1，管理员可经改授流程决定；只有 read_only=1 的 Key 会经过
// apiKeyReadOnlyGuard 的拦截面。
func addRouteTestAPIKeyWithReadOnly(t *testing.T, userID int, username, role, plain string, readOnly bool) {
	t.Helper()
	readOnlyFlag := 0
	if readOnly {
		readOnlyFlag = 1
	}
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, is_enabled) VALUES (?, ?, '', ?, 1)", userID, username, role); err != nil {
		t.Fatalf("insert %s user: %v", role, err)
	}
	hash := sha256.Sum256([]byte(plain))
	if _, err := db.DB.Exec("INSERT INTO api_keys (name, key_hash, key_prefix, created_by, is_enabled, read_only) VALUES (?, ?, ?, ?, 1, ?)", username+"-key", hex.EncodeToString(hash[:]), plain[:12], userID, readOnlyFlag); err != nil {
		t.Fatalf("insert %s API key: %v", role, err)
	}
}

func requestWithAPIKey(router *gin.Engine, method, path, key string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("X-API-Key", key)
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestSetupRouter_registers_cluster_contract_and_removes_legacy_routes(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)

	// When
	routes := make(map[string]bool)
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	// Then
	expected := []string{
		"GET /api/v1/cluster/status",
		"GET /api/v1/cluster/nodes",
		"POST /api/v1/cluster/register-tokens",
		"POST /api/v1/cluster/register",
		"GET /api/v1/cluster/register/:id/status",
		"POST /api/v1/cluster/nodes/:id/approve",
		"POST /api/v1/cluster/nodes/:id/reject",
		"POST /api/v1/cluster/nodes/:id/login-ticket",
		"PUT /api/v1/cluster/nodes/:id/access-url",
		"POST /api/v1/cluster/nodes/:id/forget-pin",
		"DELETE /api/v1/cluster/nodes/:id",
		"POST /api/v1/cluster/mode",
		"POST /api/v1/cluster/promote",
		"GET /api/v1/cluster/sync/snapshot",
		"POST /api/v1/cluster/registration/confirm",
		"POST /api/v1/cluster/sync/pull",
		"POST /api/v1/cluster/nodes/report",
		"POST /api/v1/auth/ticket-login",
		"PUT /api/v1/cluster/settings",
		"POST /api/v1/cluster/forget-pins",
	}
	for _, route := range expected {
		if !routes[route] {
			t.Errorf("missing route %s", route)
		}
	}
	for route := range routes {
		if route == "POST /api/v1/nodes/register" || route == "GET /api/v1/sync/status" || route == "GET /api/v1/sync/config" || route == "POST /api/v1/sync/pull" || route == "POST /api/v1/nodes/:id/heartbeat" {
			t.Errorf("legacy route remains registered: %s", route)
		}
	}
}

func TestClusterMachineEndpoints_rateLimitBeforeAuthentication(t *testing.T) {
	// Given：五个 token/registration 机器端点，均携带无效但非空凭证以覆盖 DB 查询路径。
	tests := []struct {
		name   string
		method string
		path   string
		header string
		ip     string
	}{
		{name: "registration status", method: http.MethodGet, path: "/api/v1/cluster/register/1/status", header: "X-Registration-Secret", ip: "198.51.100.11:1234"},
		{name: "snapshot", method: http.MethodGet, path: "/api/v1/cluster/sync/snapshot", header: "X-Cluster-Token", ip: "198.51.100.12:1234"},
		{name: "waf files", method: http.MethodGet, path: "/api/v1/cluster/sync/waf-files", header: "X-Cluster-Token", ip: "198.51.100.13:1234"},
		{name: "registration confirm", method: http.MethodPost, path: "/api/v1/cluster/registration/confirm", header: "X-Cluster-Token", ip: "198.51.100.14:1234"},
		{name: "node report", method: http.MethodPost, path: "/api/v1/cluster/nodes/report", header: "X-Cluster-Token", ip: "198.51.100.15:1234"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withIsolatedRateLimitBuckets(t)
			router := newMiddlewareTestRouter(t)
			// When：同一 IP 连续 30 次无效认证仍按原契约返回 401。
			for attempt := 1; attempt <= 30; attempt++ {
				request := httptest.NewRequest(test.method, test.path, nil)
				request.RemoteAddr = test.ip
				request.Header.Set(test.header, "invalid-cluster-credential")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("attempt %d status=%d body=%s, want 401 before limit", attempt, response.Code, response.Body.String())
				}
			}
			// Then：第 31 次必须在认证/DB 查询之前被 429 截断。
			request := httptest.NewRequest(test.method, test.path, nil)
			request.RemoteAddr = test.ip
			request.Header.Set(test.header, "invalid-cluster-credential")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusTooManyRequests || !bytes.Contains(response.Body.Bytes(), []byte("集群机器接口请求过于频繁")) {
				t.Fatalf("31st status=%d body=%s, want machine-endpoint 429", response.Code, response.Body.String())
			}
			if retryAfter := response.Header().Get("Retry-After"); retryAfter == "" {
				t.Fatal("machine-endpoint 429 must include Retry-After")
			}
		})
	}
}

func TestClusterMachineRateLimit_validResponsesDoNotConsumeFailureBudget(t *testing.T) {
	// Given：单个合法凭证经同一出口连续 31 次成功——必须跨越凭证桶上限
	// （credentialLimit=30），否则「成功不耗预算」的回滚分支永远打不到；
	// 同出口第二个凭证在同窗口内仍可同步（IP 宽桶未被成功流量消耗）。
	withIsolatedRateLimitBuckets(t)
	database, firstToken := newClusterAuthContractDatabase(t)
	secondToken := "cluster-contract-token-valid-second"
	hash := sha256.Sum256([]byte(secondToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,cluster_token_hash,is_approved) VALUES (?,?,1)`, 99, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(clusterMachineRateLimit("valid-nat-traffic", clusterCredentialFromToken))
	router.Use(clusterTokenAuth(database))
	router.GET("/cluster", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	// When / Then：成功请求不得消耗配额，第 31 次同一凭证仍 204。
	for attempt := range 31 {
		request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
		request.RemoteAddr = "198.51.100.60:1234"
		request.Header.Set("X-Cluster-Token", firstToken)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("attempt %d status=%d body=%s, want 204（成功轮必须回滚凭证预算）", attempt+1, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.RemoteAddr = "198.51.100.60:1234"
	request.Header.Set("X-Cluster-Token", secondToken)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("同出口第二凭证 status=%d body=%s, want 204（IP 宽桶不得被成功流量打满）", response.Code, response.Body.String())
	}
}

func TestClusterMachineRateLimit_concurrentFailuresReserveAtomically(t *testing.T) {
	// Given：同一凭证/IP 同时发起 100 个必然 401 的请求，计数进入认证桩的次数。
	const scope = "concurrent-failure-reservation"
	withIsolatedRateLimitBuckets(t)
	var entered, rejected, throttled atomic.Int32
	router := gin.New()
	router.Use(clusterMachineRateLimit(scope, clusterCredentialFromToken))
	router.GET("/cluster", func(c *gin.Context) {
		entered.Add(1)
		rejected.Add(1)
		c.Status(http.StatusUnauthorized)
	})
	var waitGroup sync.WaitGroup
	for range 100 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
			request.RemoteAddr = "198.51.100.61:1234"
			request.Header.Set("X-Cluster-Token", "same-invalid-credential")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code == http.StatusTooManyRequests {
				throttled.Add(1)
			}
		}()
	}
	waitGroup.Wait()

	// Then：预算必须在认证前原子预占——恰好30次进入认证并401，其余70次429。
	if got := entered.Load(); got != 30 || rejected.Load() != 30 || throttled.Load() != 70 {
		t.Fatalf("authentication attempts=%d rejected=%d throttled=%d, want 30/30/70", entered.Load(), rejected.Load(), throttled.Load())
	}
}

func TestClusterMachineRateLimit_failureDoesNotBlockValidCredentialFromSameIP(t *testing.T) {
	// Given：同一出口先出现 30 次同凭证失败，随后合法节点使用自己的凭证同步。
	withIsolatedRateLimitBuckets(t)
	database, validToken := newClusterAuthContractDatabase(t)
	router := gin.New()
	router.Use(clusterMachineRateLimit("mixed-credential-traffic", clusterCredentialFromToken))
	router.Use(clusterTokenAuth(database))
	router.GET("/cluster", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	const ip = "198.51.100.62:1234"
	for attempt := range 30 {
		request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
		request.RemoteAddr = ip
		request.Header.Set("X-Cluster-Token", "repeated-invalid-credential")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid attempt %d status=%d body=%s, want 401", attempt+1, response.Code, response.Body.String())
		}
	}

	// When
	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.RemoteAddr = ip
	request.Header.Set("X-Cluster-Token", validToken)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：失败预算按凭证隔离，IP 宽桶未被 30 次失败打满。
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid credential status=%d body=%s after other failures, want 204", response.Code, response.Body.String())
	}
}

func TestClusterMachineRateLimit_ignoresHeadersNotUsedByRouteAuth(t *testing.T) {
	// Given：认证中间件只认其路由凭证来源；攻击者用另一个路由的头做变体。
	tests := []struct {
		name      string
		method    string
		path      string
		decoyHead string
		ip        string
	}{
		{name: "cluster token ignores registration header", method: http.MethodGet, path: "/api/v1/cluster/sync/snapshot", decoyHead: "X-Registration-Secret", ip: "198.51.100.71:1234"},
		{name: "registration ignores cluster token header", method: http.MethodGet, path: "/api/v1/cluster/register/1/status", decoyHead: "X-Cluster-Token", ip: "198.51.100.72:1234"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withIsolatedRateLimitBuckets(t)
			router := newMiddlewareTestRouter(t)
			stableAuthorization := "Bearer " + "invalid-stable-credential"
			for attempt := 1; attempt <= 30; attempt++ {
				request := httptest.NewRequest(test.method, test.path, nil)
				request.RemoteAddr = test.ip
				// 实际认证固定读取 Bearer；另一头每轮变化，仅是无关噪声。
				request.Header.Set("Authorization", stableAuthorization)
				request.Header.Set(test.decoyHead, fmt.Sprintf("noise-%d", attempt))
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("attempt %d status=%d body=%s, want 401", attempt, response.Code, response.Body.String())
				}
			}
			request := httptest.NewRequest(test.method, test.path, nil)
			request.RemoteAddr = test.ip
			request.Header.Set("Authorization", stableAuthorization)
			request.Header.Set(test.decoyHead, "noise-31")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("31st status=%d body=%s, want 429 based on the credential auth actually reads", response.Code, response.Body.String())
			}
		})
	}
}

func TestClusterMachineRateLimit_capacityFullEvictsLRUAndKeepsLimiting(t *testing.T) {
	// Given：共享桶容量已满；合法节点的机器认证不得被误报为限流。
	// 容量满不得 fail-open（不建桶=本分钟对该来源零限流）——
	// 改为 LRU 淘汰最久未命中桶后照常预占。
	withIsolatedRateLimitBuckets(t)
	database, token := newClusterAuthContractDatabase(t)
	now := time.Now()
	loginRateBuckets.Lock()
	for index := range rateLimitBucketCapacity {
		bucket := &loginRateBucket{until: now.Add(time.Minute), count: 1}
		bucket.lastUsed.Store(now.Add(time.Duration(index) * time.Millisecond).UnixNano())
		loginRateBuckets.entries[fmt.Sprintf("machine-cap-%d", index)] = bucket
	}
	loginRateBuckets.Unlock()
	router := gin.New()
	router.Use(clusterMachineRateLimit("capacity-full", clusterCredentialFromToken))
	router.Use(clusterTokenAuth(database))
	router.GET("/cluster", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.RemoteAddr = "198.51.100.73:1234"
	request.Header.Set("X-Cluster-Token", token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：配额内放行，且新来源真实获得桶（未 fail-open 跳过限流）。
	if response.Code != http.StatusNoContent {
		t.Fatalf("capacity-full valid request status=%d body=%s, want 204", response.Code, response.Body.String())
	}
	loginRateBuckets.Lock()
	_, newKeyBucketed := loginRateBuckets.entries["198.51.100.73|capacity-full|ip"]
	_, oldestEvicted := loginRateBuckets.entries["machine-cap-0"]
	buckets := len(loginRateBuckets.entries)
	loginRateBuckets.Unlock()
	if !newKeyBucketed {
		t.Fatal("容量满时新来源必须获得计数桶（LRU 淘汰腾位），否则限流 fail-open")
	}
	if oldestEvicted {
		t.Fatal("LRU 淘汰应移除最久未命中的桶（machine-cap-0）")
	}
	if buckets > rateLimitBucketCapacity {
		t.Fatalf("桶表越界：%d > %d", buckets, rateLimitBucketCapacity)
	}
}

func TestUpdateClusterNodeAccessURL(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_access-url-admin-test"
	addClusterRouteTestAPIKey(t, 104, "access-admin", "admin", key)
	if _, err := db.DB.Exec("INSERT INTO nodes (id,name,ip_address,port) VALUES (12,'slave','172.18.0.2',8000)"); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"access_url":"http://127.0.0.1:8001"}`)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/cluster/nodes/12/access-url", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", key)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var accessURL string
	if err := db.DB.QueryRow("SELECT access_url FROM nodes WHERE id=12").Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "http://127.0.0.1:8001" {
		t.Fatalf("access_url=%q", accessURL)
	}
}

func TestClusterLoginTicketSignsAndLogsIntoSlave(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	// 预算敏感：本用例已用掉 login 族 10/min/IP 中的 1 次（ticket-login 与
	// login/mfa-verify 同桶，httptest RemoteAddr 恒 192.0.2.1）；不隔离时
	// -count=2 或同包其它用例的登录族调用会把窗口占满 → 与实现无关的 429 假红。
	withIsolatedRateLimitBuckets(t)
	key := "lb_sk_ticket-admin-secret"
	clusterToken := "lb_cluster_ticket-secret"
	addClusterRouteTestAPIKey(t, 103, "ticket-admin", "admin", key)
	// v2.1.8 决策4：签发从节点登录票据要求 admin 已启用 MFA——为该测试账号置位
	//（写验证开关默认关，无需 mfa_ts 窗口）。
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1 WHERE username='ticket-admin'"); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(clusterToken))
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,status,is_approved,cluster_token_hash,last_seen) VALUES (9,'slave', '10.0.0.9',8443,'https','online',1,?,datetime('now'))`, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}

	issued := requestWithAPIKey(router, http.MethodPost, "/api/v1/cluster/nodes/9/login-ticket", key)
	if issued.Code != http.StatusOK {
		t.Fatalf("issue status=%d body=%s", issued.Code, issued.Body.String())
	}
	var ticketResponse struct {
		Ticket string `json:"ticket"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(issued.Body.Bytes(), &ticketResponse); err != nil {
		t.Fatal(err)
	}
	if ticketResponse.URL != "https://10.0.0.9:8443" {
		t.Fatalf("url=%q", ticketResponse.URL)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=9 WHERE id=1", clusterToken); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"ticket": ticketResponse.Ticket})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/ticket-login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"node_mode":"slave"`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"token":`)) {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestClusterRoutesAcceptAdminAPIKey(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_admin-cluster-route-test"
	addClusterRouteTestAPIKey(t, 101, "cluster-admin", "admin", key)

	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/cluster/nodes"},
		{http.MethodPost, "/api/v1/cluster/sync/pull"},
	} {
		recorder := requestWithAPIKey(router, test.method, test.path, key)
		// 断言「管理员身份被接受」：401（未认证）与 403（角色门误判/次序错置）
		// 都属失败——此前只挡 401，adminOnly/readOnlyGuard 次序错置时本用例仍绿。
		if recorder.Code == http.StatusUnauthorized || recorder.Code == http.StatusForbidden {
			t.Errorf("%s %s rejected admin API key: status=%d body=%s", test.method, test.path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestClusterWriteRouteRejectsUserAPIKey(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	key := "lb_sk_user-cluster-route-test"
	addClusterRouteTestAPIKey(t, 102, "cluster-user", "user", key)

	recorder := requestWithAPIKey(router, http.MethodPost, "/api/v1/cluster/sync/pull", key)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestConfirmClusterRegistrationClearsSecretAfterExplicitPost(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	token := "lb_cluster_confirm-secret"
	secret := "registration-secret-hash"
	hash := sha256.Sum256([]byte(token))
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,is_approved,cluster_token_hash,registration_secret) VALUES (31,'confirm-node','10.0.0.31',1,?,?)`, hex.EncodeToString(hash[:]), secret); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/registration/confirm", nil)
	request.Header.Set("X-Cluster-Token", token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var cleared int
	if err := db.DB.QueryRow("SELECT registration_secret IS NULL FROM nodes WHERE id=31").Scan(&cleared); err != nil {
		t.Fatal(err)
	}
	if cleared != 1 {
		t.Fatal("registration_secret was not cleared")
	}
}

func TestClusterNodeServiceControlRoute_requires_admin_and_relays(t *testing.T) {
	// Given 完整路由 + 管理员/普通用户 API Key + 桩从节点
	router := newMiddlewareTestRouter(t)
	adminKey := "lb_sk_service-admin-relay"
	addClusterRouteTestAPIKey(t, 105, "service-admin", "admin", adminKey)
	userKey := "lb_sk_service-user-relay"
	addClusterRouteTestAPIKey(t, 106, "service-user", "user", userKey)
	slave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"Caddy 已停止"}`))
	}))
	t.Cleanup(slave.Close)
	hash := sha256.Sum256([]byte("lb_cluster_service-e2e"))
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,status,is_approved,cluster_token_hash) VALUES (22,'slave-e2e','10.0.0.22',8000,'http',?,'online',1,?)`, slave.URL, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"action":"stop_caddy"}`)

	// When 普通用户 API Key 调用主节点端点
	request := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/22/service", bytes.NewReader(body.Bytes()))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", userKey)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	// Then 非管理员 403
	if response.Code != http.StatusForbidden {
		t.Fatalf("user key status=%d body=%s, want 403", response.Code, response.Body.String())
	}

	// When 管理员 API Key 调用
	request = httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/22/service", bytes.NewReader(body.Bytes()))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", adminKey)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	// Then 中继从节点结果
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte("Caddy 已停止")) {
		t.Fatalf("admin key status=%d body=%s, want relayed 200", response.Code, response.Body.String())
	}

	// When 无认证调用从节点机器接口
	request = httptest.NewRequest(http.MethodPost, "/api/v1/cluster/service-control", bytes.NewBufferString(`{"action":"stop_caddy","ticket":"forged"}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	// Then 伪造票据 401
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("forged ticket status=%d body=%s, want 401", response.Code, response.Body.String())
	}
}

func TestClusterMachineRateLimit_panicReleasesReservedBudget(t *testing.T) {
	// Given：机器端点 handler 必然 panic（经 gin.Recovery 返回 500）。
	// 额度预占发生在认证之前，panic 时控制流不经过中间件的收尾语句，
	// 归还必须写在 defer 里，否则凭证桶与 IP 宽桶各泄漏 1 次额度。
	const scope = "panic-released-budget"
	withIsolatedRateLimitBuckets(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(clusterMachineRateLimit(scope, clusterCredentialFromToken))
	router.GET("/cluster", func(*gin.Context) { panic("boom") })

	// When
	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.RemoteAddr = "198.51.100.64:1234"
	request.Header.Set("X-Cluster-Token", "panic-credential")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：500 且两个桶计数都回到 0（panic 轮不消耗失败预算）。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("panicking handler status=%d, want 500", response.Code)
	}
	assertReservedBucketCount(t, "198.51.100.64|"+scope+"|credential:", 0)
	assertReservedBucketCount(t, "198.51.100.64|"+scope+"|ip", 0)
}

func assertReservedBucketCount(t *testing.T, keyPrefix string, want int) {
	t.Helper()
	loginRateBuckets.Lock()
	var found *loginRateBucket
	for key, bucket := range loginRateBuckets.entries {
		if strings.HasPrefix(key, keyPrefix) {
			found = bucket
			break
		}
	}
	loginRateBuckets.Unlock()
	if found == nil {
		t.Fatalf("限流桶 %s* 不存在，无法断言额度归还", keyPrefix)
	}
	found.mu.Lock()
	got := found.count
	found.mu.Unlock()
	if got != want {
		t.Fatalf("限流桶 %s* 计数=%d, want %d（panic 轮必须归还预占额度）", keyPrefix, got, want)
	}
}
