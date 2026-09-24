package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// validationPollServer 假 CA：/chal/1 与 /auth/1 的状态由 handler 控制，
// 用于 waitForValidation 轮询行为测试。
type validationPollServer struct {
	mu           sync.Mutex
	server       *httptest.Server
	chalStatus   int // challenge 端点恒返的 HTTP 状态码（200 时返回 pending challenge）
	authStatus   string
	chalHits     int // 到达 challenge 端点的请求数（含失败）
	chalSuccess  int // challenge 端点返回 200 的次数
	chalAttempts int // transport 层 challenge 请求尝试数（含被注入失败的）
	failChal     int // 剩余 transport 级失败注入次数（challenge 端点）
}

func newValidationPollServer(t *testing.T) *validationPollServer {
	t.Helper()
	fake := &validationPollServer{chalStatus: http.StatusOK, authStatus: "pending"}
	fake.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		fake.mu.Lock()
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newOrder":%q,"newAccount":%q}`, fake.server.URL+"/nonce", fake.server.URL+"/order", fake.server.URL+"/account")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/chal/1":
			fake.chalHits++
			if fake.chalStatus != http.StatusOK {
				status := fake.chalStatus
				fake.mu.Unlock()
				response.WriteHeader(status)
				_, _ = fmt.Fprintf(response, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many requests"}`)
				return
			}
			fake.chalSuccess++
			_, _ = fmt.Fprintf(response, `{"type":"dns-01","status":"pending","url":%q,"token":"tok"}`, fake.server.URL+"/chal/1")
		case "/auth/1":
			_, _ = fmt.Fprintf(response, `{"status":%q,"identifier":{"type":"dns","value":"example.com"}}`, fake.authStatus)
		default:
			fake.mu.Unlock()
			http.NotFound(response, request)
			return
		}
		fake.mu.Unlock()
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// failNextChalRequests 注入 n 次 challenge 端点的 transport 级失败
// （模拟网络瞬时错误，非 HTTP 状态码）。
func (fake *validationPollServer) failNextChalRequests(n int) {
	fake.mu.Lock()
	fake.failChal = n
	fake.mu.Unlock()
}

func (fake *validationPollServer) setAuthStatus(status string) {
	fake.mu.Lock()
	fake.authStatus = status
	fake.mu.Unlock()
}

func (fake *validationPollServer) counts() (hits, success int) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.chalHits, fake.chalSuccess
}

// flakyTransport 前 failChal 次 /chal/1 请求返回注入的 transport 错误。
type flakyTransport struct {
	fake  *validationPollServer
	inner http.RoundTripper
}

func (transport *flakyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.fake.mu.Lock()
	if strings.HasSuffix(request.URL.Path, "/chal/1") {
		transport.fake.chalAttempts++
		if transport.fake.failChal > 0 {
			transport.fake.failChal--
			transport.fake.mu.Unlock()
			return nil, fmt.Errorf("injected transient transport failure")
		}
	}
	transport.fake.mu.Unlock()
	return transport.inner.RoundTrip(request)
}

func newValidationTestClient(t *testing.T, server *httptest.Server, transport http.RoundTripper) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	httpClient := server.Client()
	if transport != nil {
		httpClient = &http.Client{Transport: transport}
	}
	return &Client{
		DirectoryURL: server.URL + "/directory",
		Email:        "admin@example.com",
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: server.URL + "/directory",
			HTTPClient:   httpClient,
			RetryBackoff: func(_ int, _ *http.Request, resp *http.Response) time.Duration {
				// 与生产 newClient 同口径：429 库内立即放弃，错误上抛。
				if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
					return 0
				}
				return min(time.Duration(1<<4)*time.Second, 10*time.Second)
			},
		},
	}
}

// F49-9（第 49 轮审计）：验证轮询中 CA 返回 429 时，waitForValidation 只是
// 记录日志继续轮询——限流错误被吞成 10 分钟超时，丢失限流语义（外层
// detectRateLimit 接不到 *acme.Error，任务无法进入 waiting_ca 按
// Retry-After 退避），且轮询持续给已被限流的 CA 加压。429 必须立即上抛。
func TestIssuer_waitForValidation_returnsRateLimitErrorImmediately(t *testing.T) {
	// Given: CA 对 challenge 轮询恒返 429
	fake := newValidationPollServer(t)
	fake.chalStatus = http.StatusTooManyRequests
	issuer := &Issuer{Client: newValidationTestClient(t, fake.server, nil)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// When
	start := time.Now()
	err := issuer.waitForValidation(ctx, fake.server.URL+"/auth/1", fake.server.URL+"/chal/1")
	elapsed := time.Since(start)

	// Then: 立即返回可归因的 429 错误，而非吞掉后等超时
	var acmeErr *acme.Error
	if !errors.As(err, &acmeErr) || acmeErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("error=%v, want *acme.Error with StatusCode=429", err)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("429 未快速返回（耗时 %v，跨过了 5s 轮询 tick）", elapsed)
	}
}

// F49-9 回归形状：非 429 的瞬时错误（transport 级网络失败）维持「日志+重试」
// 口径——轮询恢复后照常完成验证。
func TestIssuer_waitForValidation_retriesTransientErrors(t *testing.T) {
	// Given: 前两次 challenge 轮询 transport 级失败，授权在 challenge
	// 首次成功后才转 valid（保证断言的是「challenge 重试后恢复」）
	fake := newValidationPollServer(t)
	fake.failNextChalRequests(2)
	issuer := &Issuer{Client: newValidationTestClient(t, fake.server, &flakyTransport{fake: fake, inner: http.DefaultTransport})}
	go func() {
		for {
			_, success := fake.counts()
			if success > 0 {
				fake.setAuthStatus("valid")
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// When
	err := issuer.waitForValidation(ctx, fake.server.URL+"/auth/1", fake.server.URL+"/chal/1")

	// Then: 瞬时错误被重试吸收，验证最终完成
	if err != nil {
		t.Fatalf("waitForValidation()=%v, want nil（瞬时错误应重试而非上抛）", err)
	}
	fake.mu.Lock()
	attempts, success := fake.chalAttempts, fake.chalSuccess
	fake.mu.Unlock()
	if success < 1 || attempts <= success {
		t.Fatalf("challenge attempts=%d success=%d, want 失败后重试至少一次成功", attempts, success)
	}
}
