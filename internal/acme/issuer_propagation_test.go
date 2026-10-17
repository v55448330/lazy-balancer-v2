package acme

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// W1/W2（第 72 轮，用户裁定）：waitForDNS 放行判据锚定「准确公共 DNS 已命中」——
// 权威全 miss 而公共递归共识命中（≥2 台 × 连续 2 轮）即放行。生产实证形态：
// 权威全部「无 TXT 记录」而 nslookup 公共递归已命中（CNAME 委托/NS 变更/集群
// 分裂三形态），LE 验证均能跟随实际 DNS 状态成功，客户端死等权威即恒超时。

type captureLogger struct{ lines []string }

func (l *captureLogger) Log(stage, message string) {
	l.lines = append(l.lines, stage+" | "+message)
}

// txtResponder 返回恒命中/恒 NODATA 的假 DNS 应答构造器。
func txtResponder(hit bool, expected string) func(*dns.Msg) *dns.Msg {
	return func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(query)
		if hit {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{expected},
			}
			m.Answer = append(m.Answer, rr)
		}
		return m // hit=false 时为 NODATA（正常未命中应答）
	}
}

// setupPropagationSeams 缩放 waitForDNS 全部时间接缝并替换权威解析，
// 返回还原函数。
func setupPropagationSeams(t *testing.T, authServers []string) *captureLogger {
	t.Helper()
	origResolve := resolveAuthoritativeNSFn
	origInterval := propagationPollInterval
	origDiagAfter := propagationDivergenceDiagAfter
	origRecList := propagationRecursiveResolvers
	origConsensusMinHits := propagationConsensusMinHits
	origConsensusMinRounds := propagationConsensusMinRounds
	logger := &captureLogger{}
	t.Cleanup(func() {
		resolveAuthoritativeNSFn = origResolve
		propagationPollInterval = origInterval
		propagationDivergenceDiagAfter = origDiagAfter
		propagationRecursiveResolvers = origRecList
		propagationConsensusMinHits = origConsensusMinHits
		propagationConsensusMinRounds = origConsensusMinRounds
	})
	resolveAuthoritativeNSFn = func(ctx context.Context, fqdn, bootstrap string) []string {
		return authServers
	}
	propagationPollInterval = 20 * time.Millisecond
	propagationDivergenceDiagAfter = 100 * time.Millisecond
	propagationRecursiveResolvers = []string{"223.5.5.5:53", "119.29.29.29:53", "8.8.8.8:53", "1.1.1.1:53"} // 按测试覆盖
	propagationConsensusMinHits = 3
	propagationConsensusMinRounds = 2
	return logger
}

// W1 主形态：权威全部 NODATA（生产「全 miss」实证形态）+ 3 台递归恒命中 →
// 连续 2 轮共识即放行。未实现共识放行时 waitForDNS 烧满预算超时（RED）。
func TestIssuer_waitForDNS_recursiveConsensusReleasesWhenAuthoritativeBlind(t *testing.T) {
	const expected = "consensus-value"
	const fqdn = "_acme-challenge.blind.example.com."
	auth1 := startFakeDNSServer(t, txtResponder(false, expected))
	auth2 := startFakeDNSServer(t, txtResponder(false, expected))
	rec1 := startFakeDNSServer(t, txtResponder(true, expected))
	rec2 := startFakeDNSServer(t, txtResponder(true, expected))
	rec3 := startFakeDNSServer(t, txtResponder(true, expected))
	logger := setupPropagationSeams(t, []string{auth1, auth2})
	propagationRecursiveResolvers = []string{rec1, rec2, rec3}

	issuer := &Issuer{Logger: logger}
	start := time.Now()
	if err := issuer.waitForDNS(context.Background(), fqdn, expected, 3*time.Second); err != nil {
		t.Fatalf("recursive consensus (3 resolvers x 2 rounds) must release when authoritative is blind: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("consensus release took %v; expected sub-second after two 20ms rounds", elapsed)
	}
	found := false
	for _, line := range logger.lines {
		if strings.Contains(line, "递归共识放行") {
			found = true
		}
	}
	if !found {
		t.Fatalf("release must log the recursive-consensus reason, got %v", logger.lines)
	}
}

// W1 混合形态：权威部分命中部分 miss（authReady 恒假=滞后+分歧混合），
// 递归共识命中同样放行（用户裁定确认②）。
func TestIssuer_waitForDNS_partialAuthoritativeHits_stillReleaseOnConsensus(t *testing.T) {
	const expected = "partial-auth-value"
	const fqdn = "_acme-challenge.mixed.example.com."
	authHit := startFakeDNSServer(t, txtResponder(true, expected))
	authMiss := startFakeDNSServer(t, txtResponder(false, expected))
	rec1 := startFakeDNSServer(t, txtResponder(true, expected))
	rec2 := startFakeDNSServer(t, txtResponder(true, expected))
	rec3 := startFakeDNSServer(t, txtResponder(true, expected))
	logger := setupPropagationSeams(t, []string{authHit, authMiss})
	propagationRecursiveResolvers = []string{rec1, rec2, rec3}

	issuer := &Issuer{Logger: logger}
	if err := issuer.waitForDNS(context.Background(), fqdn, expected, 3*time.Second); err != nil {
		t.Fatalf("recursive consensus must release even when some authoritative servers already hit: %v", err)
	}
	found := false
	for _, line := range logger.lines {
		if strings.Contains(line, "递归共识放行") {
			found = true
		}
	}
	if !found {
		t.Fatalf("mixed-shape release must log the recursive-consensus reason, got %v", logger.lines)
	}
}

// M9 回归钉：单台递归命中（即便恒定多轮）不构成共识，不得放行——
// 公共递归缓存可取自已刷新单台，CA 问滞后权威时挑战仍会失败。
func TestIssuer_waitForDNS_singleResolverHit_does_not_release(t *testing.T) {
	const expected = "single-hit-value"
	const fqdn = "_acme-challenge.single.example.com."
	auth := startFakeDNSServer(t, txtResponder(false, expected))
	recHit := startFakeDNSServer(t, txtResponder(true, expected))
	recMiss := startFakeDNSServer(t, txtResponder(false, expected))
	setupPropagationSeams(t, []string{auth})
	propagationRecursiveResolvers = []string{recHit, recMiss}

	issuer := &Issuer{Logger: &captureLogger{}}
	if err := issuer.waitForDNS(context.Background(), fqdn, expected, 500*time.Millisecond); err == nil {
		t.Fatalf("single-resolver hit must NOT release (M9 anti-quota-burn guard)")
	}
}

// 现行快速路径回归：权威全部命中仍立即放行（不依赖递归）。
func TestIssuer_waitForDNS_authoritativeFullHit_releases(t *testing.T) {
	const expected = "auth-hit-value"
	const fqdn = "_acme-challenge.authhit.example.com."
	auth1 := startFakeDNSServer(t, txtResponder(true, expected))
	auth2 := startFakeDNSServer(t, txtResponder(true, expected))
	recMiss := startFakeDNSServer(t, txtResponder(false, expected))
	logger := setupPropagationSeams(t, []string{auth1, auth2})
	propagationRecursiveResolvers = []string{recMiss}

	issuer := &Issuer{Logger: logger}
	if err := issuer.waitForDNS(context.Background(), fqdn, expected, 3*time.Second); err != nil {
		t.Fatalf("authoritative full hit must release immediately: %v", err)
	}
	for _, line := range logger.lines {
		if strings.Contains(line, "递归共识放行") {
			t.Fatalf("authoritative release must not be attributed to recursive consensus: %v", logger.lines)
		}
	}
}

// W2：权威存活台全 miss 持续超过诊断阈值 → 显式诊断日志（两方清单）；
// 预算耗尽的错误信息同样携带权威/递归清单——生产排障 30 秒自明根因。
func TestIssuer_waitForDNS_divergenceDiagnosedAndTimeoutListsBothSides(t *testing.T) {
	const expected = "divergence-value"
	const fqdn = "_acme-challenge.divergent.example.com."
	auth1 := startFakeDNSServer(t, txtResponder(false, expected))
	auth2 := startFakeDNSServer(t, txtResponder(false, expected))
	rec1 := startFakeDNSServer(t, txtResponder(false, expected))
	rec2 := startFakeDNSServer(t, txtResponder(false, expected))
	logger := setupPropagationSeams(t, []string{auth1, auth2})
	propagationRecursiveResolvers = []string{rec1, rec2}

	issuer := &Issuer{Logger: logger}
	err := issuer.waitForDNS(context.Background(), fqdn, expected, 500*time.Millisecond)
	if err == nil {
		t.Fatalf("all-blind propagation must time out")
	}
	joined := strings.Join(logger.lines, "\n")
	if !strings.Contains(joined, "疑似 CNAME 委托") {
		t.Fatalf("divergence diagnostic must be logged after threshold, got:\n%s", joined)
	}
	if !strings.Contains(err.Error(), auth1) || !strings.Contains(err.Error(), auth2) {
		t.Fatalf("timeout error must list authoritative servers %s/%s, got: %v", auth1, auth2, err)
	}
	if !strings.Contains(err.Error(), rec1) || !strings.Contains(err.Error(), rec2) {
		t.Fatalf("timeout error must list recursive resolvers %s/%s, got: %v", rec1, rec2, err)
	}
}

// 防御：共识阈值接缝不得被生产代码改写为 1（M9 底线的机器可验证形态）。
func TestPropagationConsensusDefaults(t *testing.T) {
	if propagationConsensusMinHits < 3 {
		t.Fatalf("propagationConsensusMinHits=%d < 3 would weaken the anti-cache-premature-release guard (2026-10-13 user ruling: 2→3)", propagationConsensusMinHits)
	}
	if propagationConsensusMinRounds < 2 {
		t.Fatalf("propagationConsensusMinRounds=%d < 2 would release on a single poll round", propagationConsensusMinRounds)
	}
}
