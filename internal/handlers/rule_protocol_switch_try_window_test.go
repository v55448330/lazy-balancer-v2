package handlers

// TCP→HTTP 协议切换的重试窗口契约（与 HTTP→TCP 方向对称）：重试窗口是
// http/tcp 共用字段，显式提交的合法值必须原样落库（指针合并契约：显式值=
// 尊重输入）；只有未提交的存量 TCP 残留才随切换清零。此前切换分支无条件
// 清零，把用户在切换请求里显式给出的窗口静默归零。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateRule_switchToHTTPKeepsExplicitTryWindow(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	seedTCP := func(id, name string, port int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
			VALUES (?,?,?,'tcp','',?,'weighted_round_robin',1,4000,300)`, id, name, "", port); err != nil {
			t.Fatalf("seed rule %s: %v", id, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,?,9000,1,1,'tcp')`, id, "127.0.0.1"); err != nil {
			t.Fatalf("seed upstream %s: %v", id, err)
		}
	}
	put := func(id, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/rules/"+id, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	readWindow := func(id string) (int, int) {
		t.Helper()
		var duration, interval int
		if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id=?`, id).
			Scan(&duration, &interval); err != nil {
			t.Fatal(err)
		}
		return duration, interval
	}

	// 目标形状：切换请求显式携带合法窗口 → 原样落库（不得静默归零）。
	seedTCP("lb_swhttp_explicit", "swhttp-explicit", 18701)
	if response := put("lb_swhttp_explicit", `{"protocol":"http","domain":"swhttp-explicit.test","tcp_try_duration":5000,"tcp_try_interval":250}`); response.Code != http.StatusOK {
		t.Fatalf("switch with explicit window: status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if duration, interval := readWindow("lb_swhttp_explicit"); duration != 5000 || interval != 250 {
		t.Fatalf("显式窗口被切换清零: duration=%d interval=%d, want 5000/250", duration, interval)
	}

	// 回归形状：未提交窗口的切换 → 存量 TCP 残留清零（既有契约不变）。
	seedTCP("lb_swhttp_stored", "swhttp-stored", 18702)
	if response := put("lb_swhttp_stored", `{"protocol":"http","domain":"swhttp-stored.test"}`); response.Code != http.StatusOK {
		t.Fatalf("switch without window: status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if duration, interval := readWindow("lb_swhttp_stored"); duration != 0 || interval != 0 {
		t.Fatalf("未提交窗口的存量残留未清零: duration=%d interval=%d, want 0/0", duration, interval)
	}

	// 畸形形状：显式越界值不得被切换吞掉——仍交值域门 400（与同协议编辑同契约）。
	seedTCP("lb_swhttp_bad", "swhttp-bad", 18703)
	if response := put("lb_swhttp_bad", `{"protocol":"http","domain":"swhttp-bad.test","tcp_try_duration":70000}`); response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "重试窗口") {
		t.Fatalf("explicit out-of-range on switch: status=%d body=%s, want 400 重试窗口", response.Code, response.Body.String())
	}

	// 部分显式：只提交 duration 时 interval 的存量残留仍清零（未提交=沿用
	// 存量→切换清零），显式 duration 保留；duration>0 要求 interval>0 的
	// 渲染必填门仍生效——此处 duration=0（默认窗口）不触发该门。
	seedTCP("lb_swhttp_partial", "swhttp-partial", 18704)
	if response := put("lb_swhttp_partial", `{"protocol":"http","domain":"swhttp-partial.test","tcp_try_duration":0}`); response.Code != http.StatusOK {
		t.Fatalf("partial explicit switch: status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if duration, interval := readWindow("lb_swhttp_partial"); duration != 0 || interval != 0 {
		t.Fatalf("部分显式切换: duration=%d interval=%d, want 0/0（显式 0 保留、存量 interval 清零）", duration, interval)
	}
}
