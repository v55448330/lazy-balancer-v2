package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

type humanLiveProxySession struct {
	ID         string `json:"id"`
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	PolicyName string `json:"policy_name"`
	Status     string `json:"status"`
	ClientIP   string `json:"client_ip"`
	URI        string `json:"uri"`
}

type humanLiveProxyResponse struct {
	NowMS       int64                   `json:"now_ms"`
	ActiveCount int                     `json:"active_count"`
	Sessions    []humanLiveProxySession `json:"sessions"`
}

// /security/human/live 是运行态代理：scope 原样转交 Caddy admin，并就地补全
// 规则名/阶段 2 策略名，前端不需要再用事件日志反查归属。
func TestGetHumanLiveChallenges_proxiesScopeAndEnrichesAttribution(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-live-proxy','实时规则','http','live.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,policy_type,human_verify_mode,human_verify_type,enabled) VALUES ('实时CC策略','stage2','force','slider',1)`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES ('lb-live-proxy',?,1)`, policyID); err != nil {
		t.Fatal(err)
	}

	var gotScope string
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lb/human/live" {
			t.Errorf("admin path=%s", r.URL.Path)
		}
		gotScope = r.URL.Query().Get("scope")
		_, _ = w.Write([]byte(`{"now_ms":1786447300123,"active_count":1,"sessions":[{"id":"puzzle1","kind":"slider","status":"waiting","rule_id":"lb-live-proxy","client_ip":"203.0.113.30","method":"GET","uri":"/live","user_agent":"ProxyLive/1.0","issued_at_ms":1786447300000,"expires_at_ms":1786447420000,"remaining_ms":120000,"attempts":0,"max_attempts":3}]}`))
	}))
	defer admin.Close()

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	router := gin.New()
	router.GET("/security/human/live", h.GetHumanLiveChallenges)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/human/live?scope=active", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotScope != "active" {
		t.Fatalf("scope forwarded=%q, want active", gotScope)
	}
	var payload struct {
		Code int                    `json:"code"`
		Data humanLiveProxyResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.ActiveCount != 1 || len(payload.Data.Sessions) != 1 {
		t.Fatalf("live rows=(%d,%d), want (1,1)", payload.Data.ActiveCount, len(payload.Data.Sessions))
	}
	row := payload.Data.Sessions[0]
	if row.RuleName != "实时规则" || row.PolicyName != "实时CC策略" || row.Status != "waiting" || row.ClientIP != "203.0.113.30" || row.URI != "/live" {
		t.Fatalf("enriched live row mismatch: %+v", row)
	}
}

// 插件端点缺失（旧二进制）时保持 /human/stats 同容错口径：空运行态而非 5xx。
func TestGetHumanLiveChallenges_degradesToEmptyWhenAdminUnavailable(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: "http://127.0.0.1:1"}}
	router := gin.New()
	router.GET("/security/human/live", h.GetHumanLiveChallenges)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/human/live", strings.NewReader("")))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"active_count":0`) || !strings.Contains(rec.Body.String(), `"sessions":[]`) {
		t.Fatalf("live degrade payload=%s", rec.Body.String())
	}
}
