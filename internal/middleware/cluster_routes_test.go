package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"
)

func newMiddlewareTestRouter(t *testing.T) *gin.Engine {
	return newMiddlewareTestRouterAtPort(t, 8000)
}

func newMiddlewareTestRouterAtPort(t *testing.T, port int) *gin.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		services.StopAuditCleanup()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	cfg := &config.Config{
		Port: port, StaticDir: t.TempDir(), CaddyAdminURL: "http://127.0.0.1:1",
		CaddyMetricsURL: "http://127.0.0.1:1/metrics", MetricsInterval: 60,
		NodeName: "node-test", JWTSecret: "test-secret",
	}
	caddy := services.NewCaddyService(cfg.CaddyAdminURL)
	handler := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddy, MetricsService: services.NewMetricsService(cfg.CaddyMetricsURL, 60),
		SyncService: services.NewSyncService(db.DB, cfg, caddy), ClusterService: services.NewClusterService(db.DB, nil),
		CAProviderService: services.NewCAProviderService(),
	})
	return SetupRouter(handler, cfg)
}

func addClusterRouteTestAPIKey(t *testing.T, userID int, username, role, plain string) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, is_enabled) VALUES (?, ?, '', ?, 1)", userID, username, role); err != nil {
		t.Fatalf("insert %s user: %v", role, err)
	}
	hash := sha256.Sum256([]byte(plain))
	if _, err := db.DB.Exec("INSERT INTO api_keys (name, key_hash, key_prefix, created_by, is_enabled) VALUES (?, ?, ?, ?, 1)", username+"-key", hex.EncodeToString(hash[:]), plain[:12], userID); err != nil {
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
		"DELETE /api/v1/cluster/nodes/:id",
		"POST /api/v1/cluster/mode",
		"POST /api/v1/cluster/promote",
		"GET /api/v1/cluster/sync/snapshot",
		"POST /api/v1/cluster/registration/confirm",
		"POST /api/v1/cluster/sync/pull",
		"POST /api/v1/cluster/nodes/report",
		"POST /api/v1/auth/ticket-login",
		"PUT /api/v1/cluster/settings",
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
	key := "lb_sk_ticket-admin-secret"
	clusterToken := "lb_cluster_ticket-secret"
	addClusterRouteTestAPIKey(t, 103, "ticket-admin", "admin", key)
	// v2.1.8 决策4：签发从节点登录票据要求 admin 已启用 MFA——为该测试账号置位
	//（写验证开关默认关，无需 mfa_ts 窗口）。
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1 WHERE username='ticket-admin'"); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(clusterToken))
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,status,is_approved,cluster_token_hash) VALUES (9,'slave', '10.0.0.9',8443,'https','online',1,?)`, hex.EncodeToString(hash[:])); err != nil {
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
		if recorder.Code == http.StatusUnauthorized {
			t.Errorf("%s %s returned 401 for admin API key: %s", test.method, test.path, recorder.Body.String())
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
