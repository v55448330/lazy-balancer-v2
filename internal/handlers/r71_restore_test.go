package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// fakeCaddyRecorder 记录 /load POST 的配置体，供恢复断言。
type fakeCaddyRecorder struct {
	loads []string
}

func newFakeCaddyServer(t *testing.T, rec *fakeCaddyRecorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/load":
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			rec.loads = append(rec.loads, string(body))
			w.WriteHeader(http.StatusOK)
		case "/config/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"apps":{}}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// R71 N-4/N-1（2026-09-06 裁定 ④' 后重述）：UpdateRule 409（证书在途）早退
// 时运行配置必须零扰动——保存路径已无预校验探针（merged /load 副作用与
// R70-C-1 恢复机器一并撤除），409 守卫先于任何 Caddy 交互触发，候选上游
// 不得出现在任何 /load 载荷中。
func TestUpdateRule_409_restoresRuntimeForTCP(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	rec := &fakeCaddyRecorder{}
	fake := newFakeCaddyServer(t, rec)
	h.caddyService = services.NewCaddyService(fake.URL)

	// Given：一条启用中的 TCP 规则 + 一个非终态证书任务（触发 409 守卫）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_409tcp','orig','tcp','',9471,1,0,'manual');
		UPDATE lb_rules SET description='' WHERE caddy_id='lb_409tcp';
		INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_409tcp','10.0.0.1',9471,1,1,'tcp');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_409tcp','','queued')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	router := gin.New()
	router.PUT("/rules/:caddy_id", h.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_409tcp", strings.NewReader(
		`{"name":"edited","protocol":"tcp","listen_port":9471,"strategy":"weighted_round_robin","upstreams":[{"host":"10.9.9.9","port":9999,"weight":1,"enabled":true,"protocol":"tcp"}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	// Then：409 早退发生在任何 Caddy 交互之前——零 /load、零候选泄漏。
	if len(rec.loads) != 0 {
		t.Fatalf("/load calls=%d, want 0（无探针后 409 早退零运行时扰动）", len(rec.loads))
	}
}
