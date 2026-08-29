package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
)

type cleanupTrackingProvider struct {
	mu       sync.Mutex
	presents int
	cleaned  []string
}

func (p *cleanupTrackingProvider) Present(context.Context, string, string, string, int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.presents++
	if p.presents == 2 {
		return errors.New("second present failed")
	}
	return nil
}

func (p *cleanupTrackingProvider) CleanUp(_ context.Context, _ string, tokenFQDN string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleaned = append(p.cleaned, tokenFQDN)
	return nil
}

func TestIssuer_Issue_cleans_presented_records_when_later_present_fails(t *testing.T) {
	// Given
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/order")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/account":
			response.Header().Set("Location", serverURL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"status":"valid"}`))
		case "/order":
			response.Header().Set("Location", serverURL+"/order/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(response, `{"status":"pending","authorizations":[%q,%q],"finalize":%q}`, serverURL+"/auth/1", serverURL+"/auth/2", serverURL+"/finalize/1")
		case "/auth/1":
			_, _ = fmt.Fprintf(response, `{"status":"pending","identifier":{"type":"dns","value":"example.com"},"challenges":[{"type":"dns-01","url":%q,"status":"pending","token":"token-one"}]}`, serverURL+"/challenge/1")
		case "/auth/2":
			_, _ = fmt.Fprintf(response, `{"status":"pending","identifier":{"type":"dns","value":"www.example.com"},"challenges":[{"type":"dns-01","url":%q,"status":"pending","token":"token-two"}]}`, serverURL+"/challenge/2")
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &Client{
		DirectoryURL: serverURL + "/directory",
		Email:        "admin@example.com",
		accountKey:   key,
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	provider := &cleanupTrackingProvider{}
	issuer := &Issuer{Client: client, Provider: provider}

	// When
	_, _, _, issueErr := issuer.Issue(context.Background(), []string{"example.com", "www.example.com"})

	// Then
	if issueErr == nil {
		t.Fatal("issuance succeeded despite second DNS presentation failure")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	firstRecordCleanups := 0
	for _, record := range provider.cleaned {
		if record == "_acme-challenge.example.com." {
			firstRecordCleanups++
		}
	}
	if len(provider.cleaned) != 3 || firstRecordCleanups != 2 {
		t.Fatalf("cleaned records=%v, want stale cleanup for both records and deferred cleanup for the first", provider.cleaned)
	}
}

func TestTerminalAuthorizationError_prefers_authorization_error(t *testing.T) {
	authError := &acme.Error{ProblemType: "urn:auth", Detail: "authorization detail"}
	challengeError := &acme.Error{ProblemType: "urn:challenge", Detail: "challenge detail"}
	err := terminalAuthorizationError(
		"invalid",
		&acme.AuthorizationError{Errors: []error{authError}},
		&acme.Challenge{Error: challengeError},
	)
	if !strings.Contains(err.Error(), "authorization detail") || strings.Contains(err.Error(), "challenge detail") {
		t.Fatalf("terminal error=%q, want authorization detail only", err)
	}
}

// valueAwareProvider tracks TXT records by challenge value: CleanUpValue
// removes only the matching value, CleanUp removes everything.
type valueAwareProvider struct {
	mu            sync.Mutex
	presents      int
	failPresents  bool
	records       map[string]string
	cleanedValues []string
	cleanedAll    bool
}

func (p *valueAwareProvider) Present(_ context.Context, _, _, value string, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.presents++
	if p.failPresents {
		return errors.New("present failed")
	}
	p.records[value] = "record-" + value
	return nil
}

func (p *valueAwareProvider) CleanUp(_ context.Context, _ string, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanedAll = true
	p.records = map[string]string{}
	return nil
}

func (p *valueAwareProvider) CleanUpValue(_ context.Context, _, _, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanedValues = append(p.cleanedValues, value)
	delete(p.records, value)
	return nil
}

func TestIssuer_preCleanup_spares_concurrent_challenge_values(t *testing.T) {
	// Given: a stub ACME server with one authorization
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/order")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/account":
			response.Header().Set("Location", serverURL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"status":"valid"}`))
		case "/order":
			response.Header().Set("Location", serverURL+"/order/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(response, `{"status":"pending","authorizations":[%q],"finalize":%q}`, serverURL+"/auth/1", serverURL+"/finalize/1")
		case "/auth/1":
			_, _ = fmt.Fprintf(response, `{"status":"pending","identifier":{"type":"dns","value":"example.com"},"challenges":[{"type":"dns-01","url":%q,"status":"pending","token":"token-one"}]}`, serverURL+"/challenge/1")
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &Client{
		DirectoryURL: serverURL + "/directory",
		Email:        "admin@example.com",
		accountKey:   key,
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	keyAuth, err := client.DNS01ChallengeRecord("token-one")
	if err != nil {
		t.Fatalf("derive key auth: %v", err)
	}
	provider := &valueAwareProvider{
		records: map[string]string{
			keyAuth:           "own-leftover", // stale record from a previous attempt of the same order
			"concurrent-live": "another-job",  // young record of a live concurrent issuance
		},
		failPresents: true,
	}
	issuer := &Issuer{Client: client, Provider: provider}

	// When: issuance starts (pre-cleanup runs before Present fails)
	_, _, _, issueErr := issuer.Issue(context.Background(), []string{"example.com"})

	// Then
	if issueErr == nil {
		t.Fatal("issuance succeeded despite present failure")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.cleanedValues) != 1 || provider.cleanedValues[0] != keyAuth {
		t.Fatalf("cleaned values=%v, want exactly the current key auth", provider.cleanedValues)
	}
	if _, exists := provider.records["concurrent-live"]; !exists {
		t.Fatal("pre-cleanup deleted a live concurrent challenge's record")
	}
	if _, exists := provider.records[keyAuth]; exists {
		t.Fatal("pre-cleanup did not remove the same-value leftover")
	}
}

// startFakeDNSServer 在随机端口同时监听 UDP/TCP（probeTXT 会先 UDP 后 TCP 回退，
// 仅监听 UDP 时 TCP 回退会以 connection refused 覆盖真实的 RCODE 错误）。
func startFakeDNSServer(t *testing.T, respond func(query *dns.Msg) *dns.Msg) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		_ = w.WriteMsg(respond(query))
	})
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	addr := packetConn.LocalAddr().String()
	udpServer := &dns.Server{PacketConn: packetConn, Handler: handler}
	t.Cleanup(func() { _ = udpServer.Shutdown() })
	go func() { _ = udpServer.ActivateAndServe() }()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen tcp on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tcpServer := &dns.Server{Listener: listener, Handler: handler}
	t.Cleanup(func() { _ = tcpServer.Shutdown() })
	go func() { _ = tcpServer.ActivateAndServe() }()
	return addr
}

// F-C1：SERVFAIL/REFUSED 等 DNS 错误应答不是「无记录」——必须作为错误上报，
// 否则权威服务器循环中该服务器永远留在存活列表，authReady 无法为真，
// 快速路径卡死直至递归回退超时，造成假阴性杀签发。
func TestProbeTXT_returns_error_on_dns_error_rcode(t *testing.T) {
	cases := []struct {
		name  string
		rcode int
	}{
		{"SERVFAIL", dns.RcodeServerFailure},
		{"REFUSED", dns.RcodeRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			addr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
				m := new(dns.Msg)
				m.SetRcode(query, tc.rcode)
				return m
			})

			// When
			hit, found, err := probeTXT(context.Background(), addr, "_acme-challenge.example.com.", "expected", false)

			// Then
			if err == nil {
				t.Fatalf("dns error rcode %s was treated as a successful empty answer", tc.name)
			}
			if hit {
				t.Fatal("probe reported a hit on a failing server")
			}
			if found != nil {
				t.Fatalf("found=%v, want nil on error rcode", found)
			}
			if !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("error=%q, want rcode name %s", err, tc.name)
			}
		})
	}
}

// F-C1 伴随契约：NOERROR 无应答（NODATA）仍是「未命中」而非错误，权威服务器
// 保留在存活列表等待下一轮轮询。
func TestProbeTXT_nodata_is_miss_not_error(t *testing.T) {
	// Given
	addr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(query)
		return m
	})

	// When
	hit, found, err := probeTXT(context.Background(), addr, "_acme-challenge.example.com.", "expected", false)

	// Then
	if err != nil {
		t.Fatalf("nodata must remain a miss, got error: %v", err)
	}
	if hit || found != nil {
		t.Fatalf("hit=%v found=%v, want empty miss", hit, found)
	}
}

// F-C1：waitForDNS 权威循环必须把返回错误 RCODE 的服务器从存活列表移除
// （与传输失败同口径），仅命中的服务器留在列表；任一服务器失败/未命中则
// authReady 为假。
func TestIssuer_probeAuthServers_drops_dns_error_rcode_servers(t *testing.T) {
	// Given
	expected := "expected-value"
	fqdn := "_acme-challenge.example.com."
	servfailAddr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(query, dns.RcodeServerFailure)
		return m
	})
	missAddr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(query)
		return m
	})
	hitAddr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(query)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{expected},
		}
		m.Answer = append(m.Answer, rr)
		return m
	})
	issuer := &Issuer{}

	// When
	alive, ready, _, _ := issuer.probeAuthServers(context.Background(), []string{servfailAddr, missAddr, hitAddr}, fqdn, expected)

	// Then
	if len(alive) != 2 {
		t.Fatalf("alive=%v, want miss and hit servers only", alive)
	}
	for _, server := range alive {
		if server == servfailAddr {
			t.Fatalf("alive=%v, servfail server must be dropped", alive)
		}
	}
	if ready {
		t.Fatal("ready must be false while a server fails and another misses")
	}

	// 全部命中 → ready
	alive, ready, _, _ = issuer.probeAuthServers(context.Background(), []string{hitAddr}, fqdn, expected)
	if !ready || len(alive) != 1 {
		t.Fatalf("alive=%v ready=%v, want sole hit server ready", alive, ready)
	}
}

// F-D1：finalize 提交必须有独立于任务总预算的超时——卡死的 CA 应以
// finalize 阶段错误呈现，而不是吃光整个任务预算后报泛化超时。
func TestIssuer_finalizeOrder_enforces_independent_deadline(t *testing.T) {
	// Given
	var serverURL string
	finalizeStarted := make(chan struct{}, 4)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/order")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/finalize/1":
			finalizeStarted <- struct{}{}
			time.Sleep(2 * time.Second)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &Client{
		DirectoryURL: serverURL + "/directory",
		Email:        "admin@example.com",
		accountKey:   key,
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	issuer := &Issuer{Client: client}
	csrDER, _, err := CreateCSR([]string{"example.com"})
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	originalTimeout := finalizeTimeout
	finalizeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { finalizeTimeout = originalTimeout })

	// When
	start := time.Now()
	order, finalizeErr := issuer.finalizeOrder(context.Background(), serverURL+"/finalize/1", csrDER)
	elapsed := time.Since(start)

	// Then
	if finalizeErr == nil {
		t.Fatalf("finalize succeeded despite stalled CA (order=%+v)", order)
	}
	if !strings.Contains(finalizeErr.Error(), "finalize") {
		t.Fatalf("error=%q, want finalize stage named", finalizeErr)
	}
	if !errors.Is(finalizeErr, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want context deadline exceeded in chain", finalizeErr)
	}
	if elapsed >= time.Second {
		t.Fatalf("finalize deadline did not bound the stalled CA: %v", elapsed)
	}
	select {
	case <-finalizeStarted:
	default:
		t.Fatal("finalize endpoint was never reached")
	}
}
