package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

type metricsCursorErrorDriver struct{}

var metricsCursorErrorDriverOnce sync.Once

func (metricsCursorErrorDriver) Open(string) (driver.Conn, error) {
	return metricsCursorErrorConn{}, nil
}

type metricsCursorErrorConn struct{}

func (metricsCursorErrorConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not supported")
}
func (metricsCursorErrorConn) Close() error              { return nil }
func (metricsCursorErrorConn) Begin() (driver.Tx, error) { return nil, errors.New("not supported") }
func (metricsCursorErrorConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &metricsCursorErrorRows{}, nil
}

type metricsCursorErrorRows struct {
	read bool
}

func (*metricsCursorErrorRows) Columns() []string {
	return []string{"timestamp", "requests_total", "requests_2xx", "requests_3xx", "requests_4xx", "requests_5xx", "bytes_in", "bytes_out"}
}
func (*metricsCursorErrorRows) Close() error { return nil }
func (r *metricsCursorErrorRows) Next(dest []driver.Value) error {
	if r.read {
		return errors.New("cursor interrupted")
	}
	r.read = true
	dest[0] = time.Now()
	for i := 1; i < len(dest); i++ {
		dest[i] = int64(i)
	}
	return nil
}

func newMetricsTestDatabase(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
}

func TestGetCaddyMetrics_propagates_request_cancellation(t *testing.T) {
	// Given
	requestStarted := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: server.URL}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics", h.GetCaddyMetrics)
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx)
	done := make(chan struct{})

	// When
	go func() {
		router.ServeHTTP(httptest.NewRecorder(), request)
		close(done)
	}()
	<-requestStarted
	cancel()

	// Then
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("metrics request did not stop after client cancellation")
	}
}

func TestGetCaddyMetrics_returns_bad_gateway_on_caddy_error_status(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	defer server.Close()
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: server.URL}}
	router := gin.New()
	router.GET("/metrics", h.GetCaddyMetrics)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "采集 Caddy 指标失败") {
		t.Fatalf("status=%d body=%s, want 502 with collection error", response.Code, response.Body.String())
	}
}

func TestGetRuleMetricsHistory_returns_error_when_cursor_fails(t *testing.T) {
	// Given
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_history', 'history', 'http', 8080, 1)"); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	const driverName = "metrics-cursor-error"
	metricsCursorErrorDriverOnce.Do(func() { sql.Register(driverName, metricsCursorErrorDriver{}) })
	metricsDB, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatalf("open cursor error database: %v", err)
	}
	oldMetricsDB := db.MetricsDB
	db.MetricsDB = metricsDB
	t.Cleanup(func() {
		_ = metricsDB.Close()
		db.MetricsDB = oldMetricsDB
	})
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics-history", h.GetRuleMetricsHistory)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/lb_history/metrics-history", nil))

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLoadRuleUpstreams_returns_scan_error(t *testing.T) {
	// Given
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_scan', 'scan', 'tcp', 9001, 1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, enabled) VALUES ('lb_scan', '127.0.0.1', 'bad-port', 1)`); err != nil {
		t.Fatalf("seed malformed upstream: %v", err)
	}

	// When
	_, err := loadRuleUpstreams("lb_scan")

	// Then
	if err == nil {
		t.Fatal("loadRuleUpstreams returned nil error for malformed row")
	}
}

func TestLoadRuleUpstreams_coalesces_nullable_columns(t *testing.T) {
	// Given
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES ('lb_nullable', 'nullable', 'tcp', 9002, 1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, enabled, weight, domain, dynamic_dns, protocol, dns_server, max_connections) VALUES ('lb_nullable', '127.0.0.1', 9000, 1, NULL, NULL, NULL, NULL, NULL, NULL)`); err != nil {
		t.Fatalf("seed nullable upstream: %v", err)
	}

	// When
	upstreams, err := loadRuleUpstreams("lb_nullable")

	// Then
	if err != nil {
		t.Fatalf("loadRuleUpstreams: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0].Host != "127.0.0.1" || upstreams[0].Port != 9000 {
		t.Fatalf("upstreams=%#v", upstreams)
	}
}

var _ driver.QueryerContext = metricsCursorErrorConn{}
