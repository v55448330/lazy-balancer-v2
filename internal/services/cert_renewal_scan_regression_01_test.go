package services

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given 同一规则存在两条 canonical 等价但原始写法不同的到期任务行。
// When 现有证书选择读失败。
// Then 本轮不得把同规则后续行当作「没有可用证书」入队，失败行按扫描失败计数。
func TestCheckExpiration_selectionFailureSkipsRemainingRowsOfRule(t *testing.T) {
	useCertSweepTickTestEnv(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_scan_fail','scan-fail','example.com','http',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,updated_at) VALUES
		('lb_scan_fail','example.com','issued',datetime('now','+1 day'),datetime('now')),
		('lb_scan_fail',' example.com','issued',datetime('now','+1 day'),datetime('now'))`); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}
	original := selectStoredRuleCertificate
	selectStoredRuleCertificate = func(context.Context, string, string, time.Time) (CertificateSelection, bool, error) {
		return CertificateSelection{}, false, errors.New("injected selection read failure")
	}
	t.Cleanup(func() { selectStoredRuleCertificate = original })

	jobs, skipped, err := (&CertificateService{}).CheckExpiration(context.Background())
	if err != nil {
		t.Fatalf("CheckExpiration: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("candidates=%d, want 0（读失败规则的全部行都移出候选集）", len(jobs))
	}
	if skipped != 1 {
		t.Fatalf("scanSkipped=%d, want 1（同一规则只计一次读失败）", skipped)
	}
}

// Given 规则域名已变更，旧任务行的 domain 是变更前快照。When 证书已过期且
// 旧证书的 SAN 仍覆盖当前规则域名。Then 回退路径按覆盖判定呈现 expired，
// 而不是误报「尚未签发或不存在」（与选择路径 VerifyHostname 同口径）。
func TestExpiredACMECertInfoFallback_acceptsSanCoveredHistoricalDomain(t *testing.T) {
	now := time.Now()
	certPEM, _ := certificatePairForDomains(t, now.Add(-48*time.Hour), now.Add(-time.Hour), "example.com", "www.example.com")
	candidates := []CertificateCandidate{{
		ID: 1, Domain: "old.example.com", Status: "issued", CertPEM: certPEM,
	}}
	info := ExpiredACMECertInfoFallback(candidates, "lb_rule", "example.com", 30, now)
	if info == nil {
		t.Fatal("回退结果为 nil，旧域名的已过期证书被误报为尚未签发")
	}
	if info.Status != "expired" {
		t.Fatalf("status=%q, want expired", info.Status)
	}

	otherPEM, _ := certificatePairForDomains(t, now.Add(-48*time.Hour), now.Add(-time.Hour), "unrelated.test")
	other := []CertificateCandidate{{ID: 2, Domain: "old.example.com", Status: "issued", CertPEM: otherPEM}}
	if info := ExpiredACMECertInfoFallback(other, "lb_rule", "example.com", 30, now); info != nil {
		t.Fatalf("不覆盖规则域名的证书不得呈现（status=%q）", info.Status)
	}
}

// Given 未来生效证书登记了延迟重载。When 服务暂停部署定时器。
// Then 该一次性定时器必须被停止，不得在暂停/停止后触发重载。
func TestScheduleDelayedReload_isCancelledByPause(t *testing.T) {
	ResetCAQueueManagerForTest()
	var reloads atomic.Int32
	InitCAQueueManager(func() error {
		reloads.Add(1)
		return nil
	}, t.TempDir())
	t.Cleanup(ResetCAQueueManagerForTest)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service := &CertificateService{ctx: ctx, cancel: cancel}
	service.scheduleDelayedReload(7, "lb_delayed", 50*time.Millisecond)
	service.pauseDeploymentRetries()

	time.Sleep(200 * time.Millisecond)
	if got := reloads.Load(); got != 0 {
		t.Fatalf("reloads=%d, want 0（暂停后不得再触发一次性重载）", got)
	}

	// 对照：未暂停时定时器按登记执行（证明上面的 0 不是登记本身失效）。
	resumed := &CertificateService{ctx: ctx, cancel: cancel}
	resumed.scheduleDelayedReload(8, "lb_delayed_ok", 20*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for reloads.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := reloads.Load(); got == 0 {
		t.Fatal("未暂停时延迟重载未触发（登记链路失效）")
	}
}

// ACME 域名校验的字符集与标签约束：结构合法但 CA 必然拒绝的形态必须在签发
// 入口就被拦住（避免白烧订单配额并污染 lower(replace(domain,' ')) 比较）。
func TestIsValidACMEIssuanceDomain_enforcesLDHAndPublicFQDN(t *testing.T) {
	cases := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"xn--fiq228c.cn", true},
		{"a-b.example.com", true},
		{"localhost", false},
		{"exa mple.com", false},
		{"foo_bar.example.com", false},
		{"例子.example.com", false},
		{"-bad.example.com", false},
		{"bad-.example.com", false},
		{"a.-b.example.com", false},
		{"*.example.com", false},
		{"127.0.0.1", false},
		{"example.com.", false},
		{"example..com", false},
		{strings.Repeat("a", 64) + ".com", false},
	}
	for _, tc := range cases {
		if got := isValidACMEIssuanceDomain(tc.domain); got != tc.want {
			t.Errorf("isValidACMEIssuanceDomain(%q)=%v, want %v", tc.domain, got, tc.want)
		}
	}
}

// NotAfter 取时单源：签发链的 parseCertNotAfter 与任务列表/回填的
// CertNotAfterFromPEM 必须给出同一结果（两份实现曾各自存在，错误行为有差异）。
func TestParseCertNotAfter_matchesSingleSource(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	certPEM, _ := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(48*time.Hour), "single-source.example")
	want, ok := CertNotAfterFromPEM(certPEM)
	if !ok {
		t.Fatal("CertNotAfterFromPEM failed on valid PEM")
	}
	got, err := parseCertNotAfter(certPEM)
	if err != nil {
		t.Fatalf("parseCertNotAfter: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("parseCertNotAfter=%s, CertNotAfterFromPEM=%s（必须同源）", got, want)
	}
	if _, err := parseCertNotAfter("not-a-pem"); err == nil {
		t.Fatal("非法 PEM 必须返回错误")
	}
}
