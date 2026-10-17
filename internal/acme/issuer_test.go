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
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	provider := &cleanupTrackingProvider{}
	issuer := &Issuer{Client: client, Provider: provider}

	// When
	_, _, issueErr := issuer.Issue(context.Background(), []string{"example.com", "www.example.com"})

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
	// U06-F01（第 78 轮）：挑战在 Present 前登记——第二个域名的 Present 失败也
	// 会进 deferred 清理集合（按 value 幂等；provider 不实现 CleanUpValue 时按名
	// 兜底）。计数=2 次 stale 预清理 + 2 次 deferred 清理。
	if len(provider.cleaned) != 4 || firstRecordCleanups != 2 {
		t.Fatalf("cleaned records=%v, want stale cleanup for both records and deferred cleanup for both", provider.cleaned)
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
	// 按 value 幂等：仅在确有该值记录时记一次删除。挑战会在 Present 前登记进
	// deferred 清理（U06-F01），已由 stale 预清理删掉的值不得重复计数。
	if _, ok := p.records[value]; ok {
		p.cleanedValues = append(p.cleanedValues, value)
	}
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
	_, _, issueErr := issuer.Issue(context.Background(), []string{"example.com"})

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

// probeAuthServers 是单发形态的测试夹具（U06-F08：原生产 helper 零调用，已
// 移入测试文件）。probes every authoritative name server once; a miss keeps the
// server alive for the next round. ready reports whether every server already
// holds the expected record. 多轮轮询走 probeAuthServersLogged 共享状态表，
// 仅状态变化时打印（C-3 第 73 轮）。
func (i *Issuer) probeAuthServers(ctx context.Context, servers []string, fqdn, expected string) (alive []string, ready bool, lastFound []string, lastResolver string) {
	return i.probeAuthServersLogged(ctx, servers, fqdn, expected, &dnsLogState{})
}

// startFakeDNSServer 在随机端口同时监听 UDP/TCP（probeTXT 会先 UDP 后 TCP 回退，
// 仅监听 UDP 时 TCP 回退会以 connection refused 覆盖真实的 RCODE 错误）。
func startFakeDNSServer(t *testing.T, respond func(query *dns.Msg) *dns.Msg) string {
	return startFakeDNSServerW(t, func(_ dns.ResponseWriter, query *dns.Msg) *dns.Msg {
		return respond(query)
	})
}

// startFakeDNSServerW 同 startFakeDNSServer，但回调可见 dns.ResponseWriter
// （按传输层 udp/tcp 区分应答形态时使用，如 AD-3 的 TC 截断应答）。
func startFakeDNSServerW(t *testing.T, respond func(w dns.ResponseWriter, query *dns.Msg) *dns.Msg) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		_ = w.WriteMsg(respond(w, query))
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

// N+8：NXDOMAIN（Rcode 3）是权威否定应答——「名称不存在」是首发/彻底清理后
// _acme-challenge.<domain> 写入前的正常传播状态，必须与 NODATA 同为「未命中」
// 而非错误；否则传播窗口内健康权威服务器被移出存活列表，叠加递归负缓存
// （SOA TTL 300~600s）可致假阴性杀签发。
func TestProbeTXT_nxdomain_is_miss_not_error(t *testing.T) {
	// Given
	addr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(query, dns.RcodeNameError)
		return m
	})

	// When
	hit, found, err := probeTXT(context.Background(), addr, "_acme-challenge.example.com.", "expected", false)

	// Then
	if err != nil {
		t.Fatalf("nxdomain is an authoritative negative answer and must remain a miss, got error: %v", err)
	}
	if hit || found != nil {
		t.Fatalf("hit=%v found=%v, want empty miss", hit, found)
	}
}

// AD-3（第 70 轮审计）：UDP 应答 TC=1（截断）时 Answer 段不可信（UDP
// 512B 载荷上限内常被截空）——同域并存 TXT 较多（并发签发+残留）时权威
// UDP 应答恒截断，若按 miss 处理则 authReady 永假 → 假阴性烧一次签发
// （LE 5 次/时配额）。必须 continue 承接到 TCP 重查。
func TestProbeTXT_truncated_udp_falls_back_to_tcp(t *testing.T) {
	// Given：UDP 恒回 TC=1 空 Answer，TCP 回完整命中应答
	addr := startFakeDNSServerW(t, func(w dns.ResponseWriter, query *dns.Msg) *dns.Msg {
		if w.RemoteAddr().Network() == "tcp" {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"expected"},
			})
			return m
		}
		m := new(dns.Msg)
		m.SetReply(query)
		m.Truncated = true
		return m
	})

	// When
	hit, found, err := probeTXT(context.Background(), addr, "_acme-challenge.example.com.", "expected", false)

	// Then：TCP 承接后命中，而不是把截断的空 Answer 当 miss
	if err != nil {
		t.Fatalf("truncated UDP answer must fall back to TCP, got error: %v", err)
	}
	if !hit {
		t.Fatal("hit=false, want TCP fallback to observe the TXT record")
	}
	if len(found) != 1 || found[0] != "expected" {
		t.Fatalf("found=%v, want [expected]", found)
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

// N+8 伴随契约：返回 NXDOMAIN 的权威服务器是健康的（权威否定应答=记录
// 尚未写入的正常传播状态），必须保留在存活列表等待下一轮轮询；仅
// SERVFAIL/REFUSED 等真服务器故障才移除（见上）。
func TestIssuer_probeAuthServers_keeps_nxdomain_servers_alive(t *testing.T) {
	// Given
	expected := "expected-value"
	fqdn := "_acme-challenge.example.com."
	nxdomainAddr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(query, dns.RcodeNameError)
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
	alive, ready, _, _ := issuer.probeAuthServers(context.Background(), []string{nxdomainAddr, hitAddr}, fqdn, expected)

	// Then
	if len(alive) != 2 {
		t.Fatalf("alive=%v, want both servers kept: nxdomain is a healthy authoritative negative", alive)
	}
	if ready {
		t.Fatal("ready must be false while the nxdomain server has not seen the record yet")
	}
}

// F-D2：RequireRecursiveDNS 的递归确认预算必须覆盖公共递归负缓存
// （SOA negative TTL 通常 300~600s）的刷新抖动——权威快速路径收敛后记录
// 已在权威侧生效，但曾在写入前查询过的递归解析器会持续返回否定应答直到
// 各自缓存过期；预算若只给 30s，首轮会系统性失败烧掉一次尝试。解析器错峰
// 刷新（各自缓存到期时间不同），15 次轮询（45s 等效）内至少一个解析器
// 刷新即可放行，而 30s/3s=10 次的旧预算必然放弃。预算按 100 倍等比缩放，
// 保持墙钟快速且对生产值敏感（deadline 回退 30s 时本测试转红）。
func TestIssuer_checkRecursiveDNS_outlasts_negative_cache_churn(t *testing.T) {
	const (
		speedup        = 100
		flipAfter      = 15 // 负定应答次数：45s 等效，介于旧预算 10 次与新预算 40 次之间
		expected       = "expected-value"
		fqdn           = "_acme-challenge.example.com."
		oldDeadlineSec = 30 // 旧行为的预算，用于机制对照
	)

	restoreSeams := func(origResolvers []string, origInterval, origDeadline time.Duration) {
		propagationRecursiveResolvers = origResolvers
		recursiveDNSPollInterval = origInterval
		recursiveDNSDeadline = origDeadline
	}

	// negativeThenHit 返回一个先否定（NODATA）后命中的假解析器地址，
	// 以查询次数（闭包计数）而非墙钟翻转，模拟负缓存过期。
	newNegativeThenHitResolver := func(t *testing.T) string {
		t.Helper()
		var mu sync.Mutex
		queries := 0
		return startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
			mu.Lock()
			defer mu.Unlock()
			queries++
			m := new(dns.Msg)
			m.SetReply(query)
			if queries <= flipAfter {
				return m // NODATA：负缓存窗口内的否定应答
			}
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{expected},
			}
			m.Answer = append(m.Answer, rr)
			return m
		})
	}

	scaleSeams := func(interval, deadline time.Duration) {
		propagationRecursiveResolvers = []string{newNegativeThenHitResolver(t)}
		recursiveDNSPollInterval = interval / speedup
		recursiveDNSDeadline = deadline / speedup
	}

	origResolvers, origInterval, origDeadline := propagationRecursiveResolvers, recursiveDNSPollInterval, recursiveDNSDeadline
	t.Cleanup(func() { restoreSeams(origResolvers, origInterval, origDeadline) })
	issuer := &Issuer{}

	t.Run("生产预算须覆盖负缓存刷新抖动", func(t *testing.T) {
		scaleSeams(origInterval, origDeadline)
		if !issuer.checkRecursiveDNS(context.Background(), fqdn, expected) {
			t.Fatalf("recursive check gave up during negative-cache churn: deadline=%v allows %d attempts, needs %d",
				recursiveDNSDeadline*speedup, recursiveDNSDeadline/recursiveDNSPollInterval, flipAfter)
		}
	})

	t.Run("欠预算按期放弃", func(t *testing.T) {
		scaleSeams(origInterval, oldDeadlineSec*time.Second)
		if issuer.checkRecursiveDNS(context.Background(), fqdn, expected) {
			t.Fatalf("undersized deadline=%vs must give up after %d attempts", oldDeadlineSec, oldDeadlineSec*time.Second/origInterval)
		}
	})
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

// presentThenFailProvider 模拟 provider 的「双失败」形态（A-2 第 73 轮）：记录
// 已写入 DNS，但 Present 仍返回错误（ownership.Add 失败且回滚删除亦失败）。此时
// 签发侧若只在 Present 成功后登记 deferred 清理，临时 TXT 会永久残留。
type presentThenFailProvider struct {
	mu             sync.Mutex
	written        map[string]string
	presentedValue string
	deletedValues  []string
}

func (p *presentThenFailProvider) Present(_ context.Context, _, tokenFQDN, value string, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.written == nil {
		p.written = make(map[string]string)
	}
	p.written[value] = tokenFQDN
	p.presentedValue = value
	return errors.New("present failed after record write")
}

func (p *presentThenFailProvider) CleanUp(_ context.Context, _, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.written = nil
	return nil
}

func (p *presentThenFailProvider) CleanUpValue(_ context.Context, _, _, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.written[value]; !ok {
		return nil
	}
	delete(p.written, value)
	p.deletedValues = append(p.deletedValues, value)
	return nil
}

// U06-F01（第 78 轮）：challenge 必须在 Present 调用前登记进 deferred 清理集合。
// Present 自身失败（且内部回滚删除亦失败）时记录已落 DNS——登记顺序修复前
// deferred Cleanup 看不到该挑战，临时 TXT 无任何删除尝试。
func TestIssuer_Issue_cleans_challenge_when_present_itself_fails(t *testing.T) {
	// Given: 单授权 stub ACME 服务 + 写后报错的 provider
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
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	provider := &presentThenFailProvider{}
	issuer := &Issuer{Client: client, Provider: provider}

	// When
	_, _, issueErr := issuer.Issue(context.Background(), []string{"example.com"})

	// Then：签发失败，但已落 DNS 的挑战值必须被 deferred 清理删除
	if issueErr == nil {
		t.Fatal("issuance succeeded despite present failure")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.presentedValue == "" {
		t.Fatal("provider.Present was never called")
	}
	cleaned := false
	for _, value := range provider.deletedValues {
		if value == provider.presentedValue {
			cleaned = true
		}
	}
	if !cleaned {
		t.Fatalf("deferred cleanup did not delete presented value %q (deleted=%v)：Present 失败路径的临时 TXT 残留", provider.presentedValue, provider.deletedValues)
	}
	if len(provider.written) != 0 {
		t.Fatalf("records=%v, want empty after deferred cleanup", provider.written)
	}
}
