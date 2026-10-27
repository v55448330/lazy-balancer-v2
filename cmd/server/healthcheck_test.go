package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func withHealthcheckURLs(t *testing.T, httpsURL, httpURL string) {
	t.Helper()
	oldHTTPS, oldHTTP, oldTimeout := healthcheckHTTPSURL, healthcheckHTTPURL, healthcheckTimeout
	healthcheckHTTPSURL, healthcheckHTTPURL = httpsURL, httpURL
	t.Cleanup(func() {
		healthcheckHTTPSURL, healthcheckHTTPURL, healthcheckTimeout = oldHTTPS, oldHTTP, oldTimeout
	})
}

func TestRunHealthcheck_httpsOK(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withHealthcheckURLs(t, srv.URL, "http://127.0.0.1:1")

	if code := runHealthcheck(); code != 0 {
		t.Fatalf("exit=%d, want 0（自签 HTTPS 回环应视为健康）", code)
	}
}

func TestRunHealthcheck_fallsBackToPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// HTTPS 端点不可达（面板关闭管理 TLS 的形态）→ 明文回落成功。
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL)

	if code := runHealthcheck(); code != 0 {
		t.Fatalf("exit=%d, want 0（HTTPS 失败后必须回落明文）", code)
	}
}

func TestRunHealthcheck_non200IsUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL)

	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1（非 200 不得判健康）", code)
	}
}

func TestRunHealthcheck_timeoutIsUnhealthy(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { close(release); srv.Close() }()
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL)
	healthcheckTimeout = 50 * time.Millisecond

	start := time.Now()
	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1（超时必须判不健康）", code)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("耗时 %v，探针未按超时收敛", elapsed)
	}
}

func TestHealthcheckRequested_onlyFirstArgument(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"lazy-balancer"}, false},
		{[]string{"lazy-balancer", "--healthcheck"}, true},
		{[]string{"lazy-balancer", "-config", "/app/config.yaml"}, false},
		// 只有首个参数触发模式切换，避免误吞服务参数。
		{[]string{"lazy-balancer", "-config", "--healthcheck"}, false},
	}
	for _, tc := range cases {
		if got := healthcheckRequested(tc.args); got != tc.want {
			t.Fatalf("args=%v got=%v want=%v", tc.args, got, tc.want)
		}
	}
}

// 明文入口若 302 到登录页，跟随跳转会拿到登录页 200 —— 必须判不健康。
func TestRunHealthcheck_doesNotFollowRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL+"/health")

	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1（302 不得跟随成登录页 200）", code)
	}
}

func TestRunHealthcheck_twoFailedAttemptsStayWithinConfiguredBudget(t *testing.T) {
	release := make(chan struct{})
	newBlockingServer := func(tlsEnabled bool) *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			<-release
			w.WriteHeader(http.StatusOK)
		})
		if tlsEnabled {
			return httptest.NewTLSServer(handler)
		}
		return httptest.NewServer(handler)
	}
	httpsServer := newBlockingServer(true)
	httpServer := newBlockingServer(false)
	defer func() {
		close(release)
		httpsServer.Close()
		httpServer.Close()
	}()
	withHealthcheckURLs(t, httpsServer.URL, httpServer.URL)
	healthcheckTimeout = 40 * time.Millisecond

	start := time.Now()
	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("two attempts took %v, want two bounded waits", elapsed)
	}
}
