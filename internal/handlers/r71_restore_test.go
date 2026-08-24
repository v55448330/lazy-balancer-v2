package handlers

import (
	"fmt"
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

// R71 N-4/N-1：UpdateRule 409（证书在途）早退在 TCP 协议下必须恢复运行配置——
// validate 经 /load 已把候选 TCP server 真实加载，无恢复则跨规则流量顶替/孤儿
// server 残留至重启。
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
	// Then：validate 加载（≥1 次）后必须有恢复 POST——最终一次 /load 的配置
	// 不含候选上游 10.9.9.9（恢复的是 validate 前快照或不含该上游的权威配置）。
	if len(rec.loads) < 2 {
		t.Fatalf("/load calls=%d, want ≥2（validate 加载 + 409 恢复）", len(rec.loads))
	}
	for i, load := range rec.loads {
		if strings.Contains(load, "10.9.9.9") && i == len(rec.loads)-1 {
			t.Fatalf("最终 /load 载荷仍含候选上游 10.9.9.9——409 后未恢复运行配置")
		}
	}
	_ = fmt.Sprint()
}
