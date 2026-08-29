package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// setupClusterServiceControlDB 初始化测试库并挂载恢复钩子（与 cluster_ticket_test.go 同模式）。
func setupClusterServiceControlDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	gin.SetMode(gin.TestMode)
}

// seedControlNode 写入一个已审批从节点行并返回其 id。
func seedControlNode(t *testing.T, clusterToken string, extra map[string]any) int {
	t.Helper()
	hash := sha256.Sum256([]byte(clusterToken))
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,status,is_approved,cluster_token_hash,access_url) VALUES (21,'slave-x','10.0.0.21',8000,'http','online',1,?,?)`,
		hex.EncodeToString(hash[:]), extra["access_url"]); err != nil {
		t.Fatal(err)
	}
	return 21
}

// issueControlTicketOnTestDB 在测试库上以主节点身份签发票据，随后切换为从节点身份。
func issueControlTicketOnTestDB(t *testing.T, nodeID int, clusterToken, action string) string {
	t.Helper()
	service := services.NewClusterService(db.DB, nil)
	issued, err := service.IssueServiceControlTicket(context.Background(), nodeID, action, time.Now())
	if err != nil {
		t.Fatalf("issue control ticket: %v", err)
	}
	return issued.Ticket
}

func becomeSlave(t *testing.T, nodeID int, clusterToken string) {
	t.Helper()
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=? WHERE id=1", clusterToken, nodeID); err != nil {
		t.Fatal(err)
	}
}

func postServiceControl(router *gin.Engine, action, ticket string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(models.ClusterServiceControlRequest{Action: action, Ticket: ticket})
	request := httptest.NewRequest(http.MethodPost, "/service-control", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func newSlaveTestHandler(cfg *config.Config) (*Handlers, *gin.Engine) {
	handler := &Handlers{cfg: cfg, clusterService: services.NewClusterService(db.DB, nil), caddyService: services.NewCaddyService(cfg.CaddyAdminURL)}
	router := gin.New()
	router.POST("/service-control", handler.ClusterServiceControl)
	return handler, router
}

func auditDetailsServiceControlRows(t *testing.T) []string {
	t.Helper()
	rows, err := db.AuditDB.Query("SELECT detail FROM audit_log WHERE action='服务控制' AND resource='节点服务' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return details
}

func TestClusterServiceControl_start_caddy_executes_and_audits(t *testing.T) {
	setupClusterServiceControlDB(t)
	fakeAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeAdmin.Close)
	original := caddyRunCommand
	caddyRunCommand = func() *exec.Cmd { return exec.Command("sh", "-c", "sleep 2") }
	t.Cleanup(func() { caddyRunCommand = original })

	const clusterToken = "lb_cluster_ctl-start"
	seedControlNode(t, clusterToken, nil)
	ticket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionStartCaddy)
	becomeSlave(t, 21, clusterToken)
	_, router := newSlaveTestHandler(&config.Config{CaddyAdminURL: fakeAdmin.URL})

	response := postServiceControl(router, models.ClusterServiceActionStartCaddy, ticket)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Caddy 已启动") {
		t.Fatalf("body=%s, want start message", response.Body.String())
	}
	details := auditDetailsServiceControlRows(t)
	if len(details) == 0 || !strings.Contains(details[0], "操作：start_caddy") || !strings.Contains(details[0], "来源：主节点") {
		t.Fatalf("audit details=%v, want sourced master action row", details)
	}
}

func TestClusterServiceControl_stop_caddy_executes(t *testing.T) {
	setupClusterServiceControlDB(t)
	originalCmd, originalProcRoot := caddyStopCommand, caddyProcRoot
	caddyStopCommand = func(string) *exec.Cmd { return exec.Command("sh", "-c", "exit 0") }
	caddyProcRoot = t.TempDir() // 空 /proc：无存活 caddy，停止判定立即收敛
	t.Cleanup(func() { caddyStopCommand, caddyProcRoot = originalCmd, originalProcRoot })

	const clusterToken = "lb_cluster_ctl-stop"
	seedControlNode(t, clusterToken, nil)
	ticket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionStopCaddy)
	becomeSlave(t, 21, clusterToken)
	_, router := newSlaveTestHandler(&config.Config{CaddyAdminURL: "http://127.0.0.1:1"})

	response := postServiceControl(router, models.ClusterServiceActionStopCaddy, ticket)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Caddy 已停止") {
		t.Fatalf("status=%d body=%s, want 200 stopped", response.Code, response.Body.String())
	}
}

func TestClusterServiceControl_caddy_failure_returns_500(t *testing.T) {
	setupClusterServiceControlDB(t)
	originalRun, originalStop := caddyRunCommand, caddyStopCommand
	caddyRunCommand = func() *exec.Cmd { return exec.Command("sh", "-c", "exit 7") }
	caddyStopCommand = func(string) *exec.Cmd { return exec.Command("sh", "-c", "exit 8") }
	t.Cleanup(func() { caddyRunCommand, caddyStopCommand = originalRun, originalStop })

	const clusterToken = "lb_cluster_ctl-fail"
	seedControlNode(t, clusterToken, nil)
	startTicket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionStartCaddy)
	stopTicket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionStopCaddy)
	restartTicket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionRestartCaddy)
	becomeSlave(t, 21, clusterToken)
	_, router := newSlaveTestHandler(&config.Config{CaddyAdminURL: "http://127.0.0.1:1"})

	for _, ticket := range []string{startTicket, stopTicket, restartTicket} {
		response := postServiceControl(router, mustActionForTicket(t, ticket), ticket)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
		}
	}
	details := auditDetailsServiceControlRows(t)
	if len(details) != 3 {
		t.Fatalf("failure audit rows=%d, want 3", len(details))
	}
}

// mustActionForTicket 反解票据声明的动作（签发与动作绑定校验的回归面）。
func mustActionForTicket(t *testing.T, ticket string) string {
	t.Helper()
	parts := strings.Split(ticket, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var claims models.ClusterServiceControlClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Action
}

func TestClusterServiceControl_restart_app_delays_exit(t *testing.T) {
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-restart-app"
	seedControlNode(t, clusterToken, nil)
	ticket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionRestartApp)
	becomeSlave(t, 21, clusterToken)
	_, router := newSlaveTestHandler(&config.Config{})

	originalExit, originalDelay := clusterServiceExit, clusterServiceExitDelay
	exited := make(chan struct{})
	clusterServiceExit = func() { close(exited) }
	clusterServiceExitDelay = 50 * time.Millisecond
	defer func() { clusterServiceExit, clusterServiceExitDelay = originalExit, originalDelay }()

	response := postServiceControl(router, models.ClusterServiceActionRestartApp, ticket)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "服务正在重启") {
		t.Fatalf("status=%d body=%s, want 200 restarting", response.Code, response.Body.String())
	}
	// 必须先等延迟退出发生，再恢复注入（否则 goroutine 可能调用真实 os.Exit）
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("delayed exit was not invoked")
	}
	details := auditDetailsServiceControlRows(t)
	if len(details) == 0 || !strings.Contains(details[0], "操作：restart_app") {
		t.Fatalf("audit details=%v, want restart_app row", details)
	}
}

func TestClusterServiceControl_rejects_invalid_action(t *testing.T) {
	setupClusterServiceControlDB(t)
	_, router := newSlaveTestHandler(&config.Config{})
	response := postServiceControl(router, "shutdown_everything", "any-ticket")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}

func TestClusterServiceControl_rejects_bad_ticket_without_leaking_it(t *testing.T) {
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-bad"
	seedControlNode(t, clusterToken, nil)
	becomeSlave(t, 21, clusterToken)
	_, router := newSlaveTestHandler(&config.Config{})

	response := postServiceControl(router, models.ClusterServiceActionStopCaddy, "forged.ticket")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "forged.ticket") {
		t.Fatalf("response leaked ticket: %s", response.Body.String())
	}
	details := auditDetailsServiceControlRows(t)
	if len(details) != 1 || !strings.Contains(details[0], "失败") {
		t.Fatalf("audit details=%v, want one failure row", details)
	}
	for _, detail := range details {
		if strings.Contains(detail, "forged.ticket") {
			t.Fatalf("audit leaked ticket: %q", detail)
		}
	}
}

func TestClusterServiceControl_rejects_replay(t *testing.T) {
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-replay"
	seedControlNode(t, clusterToken, nil)
	ticket := issueControlTicketOnTestDB(t, 21, clusterToken, models.ClusterServiceActionStopCaddy)
	becomeSlave(t, 21, clusterToken)
	originalCmd, originalProcRoot := caddyStopCommand, caddyProcRoot
	caddyStopCommand = func(string) *exec.Cmd { return exec.Command("sh", "-c", "exit 0") }
	caddyProcRoot = t.TempDir()
	t.Cleanup(func() { caddyStopCommand, caddyProcRoot = originalCmd, originalProcRoot })
	_, router := newSlaveTestHandler(&config.Config{CaddyAdminURL: "http://127.0.0.1:1"})

	first := postServiceControl(router, models.ClusterServiceActionStopCaddy, ticket)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s, want 200", first.Code, first.Body.String())
	}
	second := postServiceControl(router, models.ClusterServiceActionStopCaddy, ticket)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("replay status=%d body=%s, want 401", second.Code, second.Body.String())
	}
}

// --- 主节点端点 ---

func newMasterTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}, clusterService: services.NewClusterService(db.DB, nil)}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", "admin")
		c.Set("auth_type", "jwt")
		c.Next()
	})
	router.POST("/nodes/:id/service", handler.ControlClusterNodeService)
	return router
}

func postNodeService(router *gin.Engine, id, action string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(models.ClusterNodeServiceRequest{Action: action})
	request := httptest.NewRequest(http.MethodPost, "/nodes/"+id+"/service", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestControlClusterNodeService_relays_slave_response_and_audits(t *testing.T) {
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-relay"
	type slaveCall struct {
		Action string `json:"action"`
		Ticket string `json:"ticket"`
	}
	calls := make(chan slaveCall, 1)
	slave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/service-control" {
			t.Errorf("slave path=%q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var call slaveCall
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			t.Errorf("decode slave call: %v", err)
		}
		calls <- call
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"Caddy 已停止"}`))
	}))
	t.Cleanup(slave.Close)

	seedControlNode(t, clusterToken, map[string]any{"access_url": slave.URL})
	router := newMasterTestRouter(t)
	response := postNodeService(router, "21", models.ClusterServiceActionStopCaddy)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Caddy 已停止") {
		t.Fatalf("status=%d body=%s, want relayed 200", response.Code, response.Body.String())
	}
	select {
	case call := <-calls:
		if call.Action != models.ClusterServiceActionStopCaddy {
			t.Fatalf("relayed action=%q", call.Action)
		}
		if len(call.Ticket) < 32 {
			t.Fatalf("relayed ticket missing or too short: %q", call.Ticket)
		}
	default:
		t.Fatal("master did not call slave")
	}
	rows, err := db.AuditDB.Query("SELECT username, detail FROM audit_log WHERE action='服务控制' AND resource='节点服务' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var username, detail string
		if err := rows.Scan(&username, &detail); err != nil {
			t.Fatal(err)
		}
		if username == "admin" && strings.Contains(detail, "节点 slave-x") && strings.Contains(detail, "操作：stop_caddy") && strings.Contains(detail, "结果：成功") {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("master audit row missing")
	}
}

func TestControlClusterNodeService_relays_slave_failure(t *testing.T) {
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-relay-fail"
	slave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":500,"message":"Caddy 启动失败：进程退出"}`))
	}))
	t.Cleanup(slave.Close)
	seedControlNode(t, clusterToken, map[string]any{"access_url": slave.URL})
	router := newMasterTestRouter(t)
	response := postNodeService(router, "21", models.ClusterServiceActionStartCaddy)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Caddy 启动失败：进程退出") {
		t.Fatalf("body=%s, want slave message relayed", response.Body.String())
	}
	details := auditDetailsServiceControlRows(t)
	if len(details) != 1 || !strings.Contains(details[0], "结果：失败") {
		t.Fatalf("audit details=%v, want failure row", details)
	}
}

func TestControlClusterNodeService_unreachable_slave_returns_502(t *testing.T) {
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-unreachable"
	seedControlNode(t, clusterToken, map[string]any{"access_url": "http://127.0.0.1:1"})
	router := newMasterTestRouter(t)
	response := postNodeService(router, "21", models.ClusterServiceActionRestartApp)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
}

func TestControlClusterNodeService_rejects_bad_requests(t *testing.T) {
	setupClusterServiceControlDB(t)
	router := newMasterTestRouter(t)

	if response := postNodeService(router, "21", "explode"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid action status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if response := postNodeService(router, "999", models.ClusterServiceActionStopCaddy); response.Code != http.StatusNotFound {
		t.Fatalf("missing node status=%d body=%s, want 404", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/nodes/abc/service", strings.NewReader(`{"action":"stop_caddy"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad node id status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

func TestControlClusterNodeService_requires_master(t *testing.T) {
	setupClusterServiceControlDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	router := newMasterTestRouter(t)
	response := postNodeService(router, "21", models.ClusterServiceActionStopCaddy)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403 on slave", response.Code, response.Body.String())
	}
}

func TestControlClusterNodeService_ignores_APIKey_readonly_annotation(t *testing.T) {
	// recordAudit 的 API Key 附加信息在 auth_type=api_key 时生效——确认主节点
	// 中转路径在 JWT 语义下不误附加（回归保护，非功能断言主体）。
	setupClusterServiceControlDB(t)
	const clusterToken = "lb_cluster_ctl-jwt-audit"
	slave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"message":"Caddy 已停止"}`))
	}))
	t.Cleanup(slave.Close)
	seedControlNode(t, clusterToken, map[string]any{"access_url": slave.URL})
	router := newMasterTestRouter(t)
	if response := postNodeService(router, "21", models.ClusterServiceActionStopCaddy); response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	for _, detail := range auditDetailsServiceControlRows(t) {
		if strings.Contains(detail, "API Key") {
			t.Fatalf("JWT path annotated API key detail: %q", detail)
		}
	}
}
