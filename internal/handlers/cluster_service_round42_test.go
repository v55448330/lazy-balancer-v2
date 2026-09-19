package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// CL42-2（第 42 轮审计）②：主节点→从节点服务控制调用与集群同步
// doWithTLSUpgradeRedirect 同契约——从节点启用管理 HTTPS 后明文端口整体 301，
// 服务控制调用必须对「同主机名 + 升级为 https」的 Location 按原方法重放一次，
// 否则票据调用在 301 上空 body 解析失败、服务控制全线不可用。
func TestCallClusterServiceControl_followsSameHostTLSUpgradeRedirect(t *testing.T) {
	setupClusterServiceControlDB(t)
	// Given a slave whose plaintext port 301s to its HTTPS port (same hostname)
	type slaveCall struct{ Action, Ticket string }
	received := make(chan slaveCall, 1)
	tlsSlave := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%q, want POST preserved across redirect", r.Method)
		}
		var req models.ClusterServiceControlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode slave call: %v", err)
		}
		received <- slaveCall{req.Action, req.Ticket}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"Caddy 已停止"}`))
	}))
	t.Cleanup(tlsSlave.Close)
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, tlsSlave.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	t.Cleanup(plaintext.Close)
	oldFactory := clusterServiceControlClientFactory
	clusterServiceControlClientFactory = func(string) *http.Client {
		client := tlsSlave.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return client
	}
	t.Cleanup(func() { clusterServiceControlClientFactory = oldFactory })
	handler := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}

	// When the master calls the slave via the plaintext address
	message, err := handler.callClusterServiceControl(context.Background(), plaintext.URL, models.ClusterServiceActionStopCaddy, "ticket-x")

	// Then the request is replayed over https and the slave response relayed
	if err != nil {
		t.Fatalf("callClusterServiceControl: %v", err)
	}
	if message != "Caddy 已停止" {
		t.Fatalf("message=%q, want relayed slave message", message)
	}
	select {
	case call := <-received:
		if call.Action != models.ClusterServiceActionStopCaddy || call.Ticket != "ticket-x" {
			t.Fatalf("relayed call=%+v, want action+ticket preserved", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("redirect target never received the service control call")
	}
}

// CL42-2 回归形状：跨主机重定向一律不跟随（票据不出原主机）。
func TestCallClusterServiceControl_doesNotFollowCrossHostRedirect(t *testing.T) {
	setupClusterServiceControlDB(t)
	// Given a redirect to the same listener but under a different hostname
	received := make(chan struct{}, 1)
	tlsSlave := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		_, _ = w.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	t.Cleanup(tlsSlave.Close)
	crossHost := strings.Replace(tlsSlave.URL, "127.0.0.1", "localhost", 1)
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossHost+r.URL.Path, http.StatusMovedPermanently)
	}))
	t.Cleanup(plaintext.Close)
	oldFactory := clusterServiceControlClientFactory
	clusterServiceControlClientFactory = func(string) *http.Client {
		client := tlsSlave.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return client
	}
	t.Cleanup(func() { clusterServiceControlClientFactory = oldFactory })
	handler := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}

	// When the master calls the slave via the plaintext address
	_, err := handler.callClusterServiceControl(context.Background(), plaintext.URL, models.ClusterServiceActionStopCaddy, "ticket-x")

	// Then the redirect is not followed（301 空 body 解析失败即返回错误，票据不外泄）
	if err == nil {
		t.Fatal("want error for unanswered 301, got nil")
	}
	select {
	case <-received:
		t.Fatal("cross-host redirect must not be followed（凭证外泄防护）")
	case <-time.After(300 * time.Millisecond):
	}
}
