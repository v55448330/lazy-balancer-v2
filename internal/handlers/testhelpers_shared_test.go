package handlers

import (
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// newFakeCaddyHandlers 装配恒 200 假 Caddy admin 的 Handlers（测试模式）：
// 安全域路由夹具的共用样板——假服务随用例 Cleanup 关闭，调用方只挂路由。
func newFakeCaddyHandlers(t *testing.T) *Handlers {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	return &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
}

func newSecurityR26Router(t *testing.T) *gin.Engine {
	t.Helper()
	h := newFakeCaddyHandlers(t)
	router := gin.New()
	router.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)
	router.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)
	router.GET("/security/events", h.ListSecurityEvents)
	return router
}

func deleteRequest(t *testing.T, router *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, path, nil))
	return recorder
}

func postImportShared(t *testing.T, handler gin.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(path, handler)
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func seedCurrentAdminShared(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
}

func checksumBackupPayload(t *testing.T, tables map[string][]map[string]any, config map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}{tables, config})
	if err != nil {
		t.Fatalf("marshal checksum payload: %v", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func postValidateString(t *testing.T, h *Handlers, body string) importValidateResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode validate response: %v (body=%s)", err, response.Body.String())
	}
	return envelope.Data
}

func validateRouterShared(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.POST("/config/validate", h.ValidateConfigImport)
	return g
}

func postValidateBytes(t *testing.T, h *Handlers, body []byte) importValidateResponse {
	t.Helper()
	g := validateRouterShared(h)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/octet-stream")
	g.ServeHTTP(rec, req)
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode validate response: %v body=%s", err, rec.Body.String())
	}
	return envelope.Data
}

func validateResponseShared(t *testing.T, h *Handlers, body string) importValidateResponse {
	t.Helper()
	return postValidateBytes(t, h, []byte(body))
}

func marshalJSONForTest(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

func postJSONImport(t *testing.T, g *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)
	return rec
}

type fakeQueryRows struct {
	values    [][]driver.Value
	failAfter int
	err       error
	i         int
}

func (r *fakeQueryRows) Columns() []string {
	if len(r.values) > 0 {
		return make([]string, len(r.values[0]))
	}
	return []string{"c"}
}

func (fakeQueryRows) Close() error { return nil }

func (r *fakeQueryRows) Next(dest []driver.Value) error {
	if r.i < len(r.values) {
		copy(dest, r.values[r.i])
		r.i++
		return nil
	}
	if r.i-len(r.values) < r.failAfter {
		r.i++
		return nil
	}
	if r.err != nil {
		return r.err
	}
	return io.EOF
}

func newAuditLogRouter(t *testing.T) (*gin.Engine, *Handlers) {
	t.Helper()
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/audit-logs", h.GetAuditLogs)
	router.GET("/audit-logs/options", h.GetAuditLogOptions)
	return router, h
}

func seedR52CertificateConfig(t *testing.T) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns-cert','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config ID: %v", err)
	}
	return id
}

func seedTCPStoredRule(t *testing.T, id, name string, port int, enabled bool, strategy string, dynamicDNS bool) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,tls_source,enable_tls,dynamic_dns)
		VALUES (?,?,?,'tcp','',?,?,'',?,1,'manual',0,?)`, id, name, "", port, strategy, enabled, dynamicDNS); err != nil {
		t.Fatalf("seed tcp rule %s: %v", id, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 1, 'tcp')`, id); err != nil {
		t.Fatalf("seed tcp upstream %s: %v", id, err)
	}
}

type threatScreenR79Payload struct {
	Code int `json:"code"`
	Data struct {
		Hours        int    `json:"hours"`
		TotalEvents  int    `json:"total_events"`
		RollupStale  bool   `json:"rollup_stale"`
		RollupLastOK string `json:"rollup_last_success"`
		TopTargets   []struct {
			Name   string `json:"name"`
			Domain string `json:"domain"`
			Value  int    `json:"value"`
		} `json:"top_targets"`
	} `json:"data"`
}

func getThreatScreenR79(t *testing.T, router *gin.Engine, path string) threatScreenR79Payload {
	t.Helper()
	recorder := getRequest(t, router, path)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenR79Payload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v (%s)", err, recorder.Body.String())
	}
	return payload
}

func importBackupShared(h *Handlers, t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.POST("/config/import", h.ImportConfigBackup)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)
	return rec
}

func validXdbBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "caddygeoip", "testdata", "ip2region_v4.xdb"))
	if err != nil {
		t.Fatalf("read xdb fixture: %v", err)
	}
	return data
}
