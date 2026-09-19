package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// CL42-2（第 42 轮审计）①：notifyMasterDetach 与集群同步 doWithTLSUpgradeRedirect
// 同契约——旧主节点启用管理 HTTPS 后明文端口整体 301，脱离通知必须对
// 「同主机名 + 升级为 https」的 Location 按原方法重放一次，否则主节点永远
// 收不到 detached 上报、节点行与令牌不撤销。
func TestNotifyMasterDetach_followsSameHostTLSUpgradeRedirect(t *testing.T) {
	// Given an old master whose plaintext port 301s to its HTTPS port (same hostname)
	received := make(chan string, 1)
	tlsMaster := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%q, want POST preserved across redirect", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"detached":true`) {
			t.Errorf("body=%s, want detached report", body)
		}
		received <- r.Header.Get("X-Cluster-Token")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tlsMaster.Close)
	pin := sha256.Sum256(tlsMaster.Certificate().Raw)
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, tlsMaster.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	t.Cleanup(plaintext.Close)

	// When the detach notification is sent to the plaintext address
	notifyMasterDetach(context.Background(), plaintext.URL, "cluster-secret", hex.EncodeToString(pin[:]))

	// Then the report is replayed over https with the cluster token header preserved
	select {
	case token := <-received:
		if token != "cluster-secret" {
			t.Fatalf("token=%q, want cluster-secret", token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("redirect target never received the detach report")
	}
}

// CL42-2 回归形状：跨主机重定向一律不跟随（凭证不出原主机，与
// TestSyncService_do_doesNotFollowHTTPRedirectOrForwardCredentials 同契约）。
func TestNotifyMasterDetach_doesNotFollowCrossHostRedirect(t *testing.T) {
	// Given a redirect to the same listener but under a different hostname
	received := make(chan struct{}, 1)
	tlsMaster := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tlsMaster.Close)
	pin := sha256.Sum256(tlsMaster.Certificate().Raw)
	crossHost := strings.Replace(tlsMaster.URL, "127.0.0.1", "localhost", 1)
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossHost+r.URL.Path, http.StatusMovedPermanently)
	}))
	t.Cleanup(plaintext.Close)

	// When the detach notification is sent
	notifyMasterDetach(context.Background(), plaintext.URL, "cluster-secret", hex.EncodeToString(pin[:]))

	// Then the redirect is not followed (no request reaches the target)
	select {
	case <-received:
		t.Fatal("cross-host redirect must not be followed（凭证外泄防护）")
	case <-time.After(300 * time.Millisecond):
	}
}
