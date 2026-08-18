package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// R28 后续优化：同协议端口迁移放行（原「仅协议切换时允许迁移监听端口」守卫删除），
// 冲突拦截由 validateRuleListenPort / validatePortFromDB / validateRuleFeatures 兜底。
func TestUpdateRule_allows_same_protocol_port_migration(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	seed := func(caddyID, protocol, domain string, port int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress) VALUES (?,?,?,?,?,?,'weighted_round_robin',1,1)`,
			caddyID, caddyID, "", protocol, domain, port); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		upstreamProtocol := "http"
		if protocol == "tcp" {
			upstreamProtocol = "tcp"
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,?)`, caddyID, upstreamProtocol); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	put := func(caddyID, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	assertPort := func(caddyID string, want int) {
		t.Helper()
		var got int
		if err := db.DB.QueryRow("SELECT listen_port FROM lb_rules WHERE caddy_id=?", caddyID).Scan(&got); err != nil {
			t.Fatalf("read rule %s: %v", caddyID, err)
		}
		if got != want {
			t.Fatalf("rule %s listen_port=%d, want %d", caddyID, got, want)
		}
	}

	t.Run("http 8080 to 8081 allowed", func(t *testing.T) {
		seed("lb_mig_http", "http", "mig-http.example.test", 8080)
		response := put("lb_mig_http", `{"name":"lb_mig_http","protocol":"http","domain":"mig-http.example.test","listen_port":8081}`)
		if response.Code != http.StatusOK {
			t.Fatalf("http port migration status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		assertPort("lb_mig_http", 8081)
	})

	t.Run("disable TLS with 443 to 80 allowed", func(t *testing.T) {
		certPEM, keyPEM, err := generateTestCert("mig-tls.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		if err != nil {
			t.Fatalf("generate certificate: %v", err)
		}
		seed("lb_mig_tls", "http", "mig-tls.example.test", 443)
		if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_tls=1, tls_source='manual', tls_cert=?, tls_key=? WHERE caddy_id='lb_mig_tls'`, certPEM, keyPEM); err != nil {
			t.Fatalf("seed tls fields: %v", err)
		}
		// 前端 enable_tls watch 的联动路径：关 TLS 时自动把 443 改回 80。
		body := fmt.Sprintf(`{"name":"lb_mig_tls","protocol":"http","domain":"mig-tls.example.test","listen_port":80,"enable_tls":false,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM)
		response := put("lb_mig_tls", body)
		if response.Code != http.StatusOK {
			t.Fatalf("disable-TLS 443->80 migration status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		assertPort("lb_mig_tls", 80)
		var enableTLS int
		if err := db.DB.QueryRow("SELECT enable_tls FROM lb_rules WHERE caddy_id='lb_mig_tls'").Scan(&enableTLS); err != nil {
			t.Fatalf("read enable_tls: %v", err)
		}
		if enableTLS != 0 {
			t.Fatalf("enable_tls=%d, want 0", enableTLS)
		}
	})

	t.Run("tcp 9000 to 9001 allowed", func(t *testing.T) {
		seed("lb_mig_tcp", "tcp", "", 9000)
		response := put("lb_mig_tcp", `{"name":"lb_mig_tcp","protocol":"tcp","listen_port":9001}`)
		if response.Code != http.StatusOK {
			t.Fatalf("tcp port migration status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		assertPort("lb_mig_tcp", 9001)
	})

	t.Run("http onto tcp-occupied port still rejected", func(t *testing.T) {
		seed("lb_mig_tcphold", "tcp", "", 9500)
		seed("lb_mig_httpblk", "http", "mig-blocked.example.test", 8180)
		response := put("lb_mig_httpblk", `{"name":"lb_mig_httpblk","protocol":"http","domain":"mig-blocked.example.test","listen_port":9500}`)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "已被其他规则占用") {
			t.Fatalf("http onto tcp-occupied port status=%d body=%s, want 400 port conflict", response.Code, response.Body.String())
		}
		assertPort("lb_mig_httpblk", 8180)
	})
}
