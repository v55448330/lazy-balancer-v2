package acme

// 权威 NS 发现的加固——EDNS0（避免 512B UDP 截断把 NODATA
// 当答案）、TC=1 走 TCP 重查、NS 查询有限重试、SOA 停止条件（不误走父域）、
// 发现的区必须是 fqdn 后缀、失败原因留痕。测试通过 dnsExchange 接缝注入固定
// 应答，不依赖网络与时序。

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

const nsTestBootstrap = "127.0.0.1:53"

// fakeDNSExchange 是可编程的 DNS 交换替身：记录每次查询（名字/qtype/网络），
// 由 handler 决定应答；handler 返回 nil 表示本次交换失败（超时/网络错误）。
type fakeDNSExchange struct {
	mu          sync.Mutex
	queries     []string
	missingEDNS int
	handler     func(m *dns.Msg, network string) *dns.Msg
}

func (f *fakeDNSExchange) exchange(ctx context.Context, m *dns.Msg, network, addr string) *dns.Msg {
	f.mu.Lock()
	f.queries = append(f.queries, fmt.Sprintf("%s/%s/%s", network, m.Question[0].Name, dns.TypeToString[m.Question[0].Qtype]))
	if m.IsEdns0() == nil {
		f.missingEDNS++
	}
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil
	}
	return f.handler(m, network)
}

func (f *fakeDNSExchange) queried(name string, qtype uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	needle := fmt.Sprintf("%s/%s", name, dns.TypeToString[qtype])
	count := 0
	for _, query := range f.queries {
		// 记录格式为 network/name/qtype：按「网络 + 名字 + qtype」整体比较。
		// 后缀匹配会把 sub.example.com. 的查询算到 com. 头上。
		if parts := strings.SplitN(query, "/", 2); len(parts) == 2 && parts[1] == needle {
			count++
		}
	}
	return count
}

// installFakeDNSExchange 装配替身并关闭 IPv6 出口探测（避免 AAAA 分支改变
// 查询序列）。
func installFakeDNSExchange(t *testing.T, handler func(m *dns.Msg, network string) *dns.Msg) *fakeDNSExchange {
	t.Helper()
	fake := &fakeDNSExchange{handler: handler}
	originalExchange := dnsExchange
	originalIPv6 := ipv6EgressAvailable
	dnsExchange = fake.exchange
	ipv6EgressAvailable = func() bool { return false }
	// 失败告警按域名限流：每个用例从干净窗口开始，避免用例间共享抑制状态。
	resetAuthoritativeNSWarnForTest()
	t.Cleanup(func() {
		dnsExchange = originalExchange
		ipv6EgressAvailable = originalIPv6
		resetAuthoritativeNSWarnForTest()
	})
	return fake
}

func answerNS(query *dns.Msg, owner string, servers ...string) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	if len(servers) > 0 {
		response.Authoritative = true
	}
	for _, server := range servers {
		response.Answer = append(response.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  server,
		})
	}
	return response
}

func answerA(query *dns.Msg, owner, ip string) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip),
	})
	return response
}

// Given：example.com 的 NS 查询第一次超时（UDP 丢包），第二次正常应答。
// When：resolveAuthoritativeNS。
// Then：有限重试后仍拿到权威地址（原实现一次超时即静默返回 nil）。
func TestResolveAuthoritativeNS_retriesTransientQueryFailure(t *testing.T) {
	// Given
	nsAttempts := 0
	var mu sync.Mutex
	fake := installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg {
		question := m.Question[0]
		switch {
		case question.Qtype == dns.TypeNS && question.Name == "example.com.":
			mu.Lock()
			nsAttempts++
			attempt := nsAttempts
			mu.Unlock()
			if attempt == 1 {
				return nil // 第一次：超时/网络错误
			}
			return answerNS(m, "example.com.", "ns1.example.com.")
		case question.Qtype == dns.TypeA && question.Name == "ns1.example.com.":
			return answerA(m, "ns1.example.com.", "192.0.2.10")
		}
		return nil
	})

	// When
	servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.example.com.", nsTestBootstrap)

	// Then
	if len(servers) != 1 || servers[0] != "192.0.2.10:53" {
		t.Fatalf("servers=%v, want 重试后拿到 [192.0.2.10:53]", servers)
	}
	if got := fake.queried("example.com.", dns.TypeNS); got != 2 {
		t.Fatalf("NS 查询次数=%d, want 2（首次失败 + 一次重试）", got)
	}
	// EDNS0 4096：避免 512B UDP 载荷截断（截断应答的 Answer 段为空会被误判
	// 为 NODATA，进而上溯到父域/顶级域）。
	fake.mu.Lock()
	missing := fake.missingEDNS
	fake.mu.Unlock()
	if missing != 0 {
		t.Fatalf("%d 次查询未带 EDNS0（OPT 记录缺失）", missing)
	}
}

// Given：UDP 应答被截断（TC=1，Answer 段为空），TCP 应答完整。
// When：resolveAuthoritativeNS。
// Then：走 TCP 重查并拿到权威地址（原实现把截断应答当 NODATA，一路误走上溯）。
func TestResolveAuthoritativeNS_retriesTruncatedAnswerOverTCP(t *testing.T) {
	// Given
	var sawTCP bool
	var mu sync.Mutex
	installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg {
		question := m.Question[0]
		switch {
		case question.Qtype == dns.TypeNS && question.Name == "example.com.":
			if network == "udp" {
				truncated := new(dns.Msg)
				truncated.SetReply(m)
				truncated.Truncated = true
				return truncated
			}
			mu.Lock()
			sawTCP = true
			mu.Unlock()
			return answerNS(m, "example.com.", "ns1.example.com.")
		case question.Qtype == dns.TypeA && question.Name == "ns1.example.com.":
			return answerA(m, "ns1.example.com.", "192.0.2.10")
		}
		return nil
	})

	// When
	servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.example.com.", nsTestBootstrap)

	// Then
	if len(servers) != 1 || servers[0] != "192.0.2.10:53" {
		t.Fatalf("servers=%v, want TCP 重查后拿到权威地址", servers)
	}
	mu.Lock()
	tcpUsed := sawTCP
	mu.Unlock()
	if !tcpUsed {
		t.Fatal("UDP 截断应答未触发 TCP 重查")
	}
}

// Given：example.com 不是委托点，NS 查询返回 NOERROR/NODATA + 所属区 SOA。
// When：resolveAuthoritativeNS（挑战名比区多一层：sub.example.com）。
// Then：直接到 SOA owner 上取 NS，不按标签上溯到 com.；地址来自 example.com
// 的权威（不误走父域）。
func TestResolveAuthoritativeNS_stopsAtSOAInsteadOfWalkingToParent(t *testing.T) {
	// Given
	fake := installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg {
		question := m.Question[0]
		switch {
		case question.Qtype == dns.TypeNS && question.Name == "sub.example.com.":
			response := answerNS(m, "sub.example.com.") // NOERROR/NODATA
			response.Ns = append(response.Ns, &dns.SOA{
				Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns1.example.com.",
				Mbox:    "hostmaster.example.com.",
				Serial:  1,
				Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
			})
			return response
		case question.Qtype == dns.TypeNS && question.Name == "example.com.":
			return answerNS(m, "example.com.", "ns1.example.com.")
		case question.Qtype == dns.TypeA && question.Name == "ns1.example.com.":
			return answerA(m, "ns1.example.com.", "192.0.2.10")
		}
		return answerNS(m, question.Name) // 其余一律 NODATA（com. 也会有应答）
	})

	// When
	servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.sub.example.com.", nsTestBootstrap)

	// Then
	if len(servers) != 1 || servers[0] != "192.0.2.10:53" {
		t.Fatalf("servers=%v, want SOA 所属区的权威地址", servers)
	}
	if got := fake.queried("com.", dns.TypeNS); got != 0 {
		t.Fatalf("查询了父域 com.（%d 次）：SOA 停止条件失效；queries=%v", got, fake.queries)
	}
}

// Given：仅顶级域 com. 有 NS 应答（example.com 查不到 NS）。
// When：resolveAuthoritativeNS。
// Then：返回 nil（拒绝把顶级域当权威）并给出失败原因。
func TestResolveAuthoritativeNS_rejectsTopLevelAsAuthority(t *testing.T) {
	// Given：example.com 是 NODATA；只有顶级域 com. 有 NS 应答，且该 NS 有 A
	// 记录（pre-fix 形态会把它当成本域权威并返回地址）。
	installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg {
		question := m.Question[0]
		switch {
		case question.Qtype == dns.TypeNS && question.Name == "com.":
			return answerNS(m, "com.", "a.gtld-servers.net.")
		case question.Qtype == dns.TypeA && question.Name == "a.gtld-servers.net.":
			return answerA(m, "a.gtld-servers.net.", "192.0.2.99")
		}
		return answerNS(m, question.Name)
	})

	// When
	servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.example.com.", nsTestBootstrap)

	// Then
	if len(servers) != 0 {
		t.Fatalf("servers=%v, want nil（顶级域不是该域的权威）", servers)
	}
}

// Given：候选区 foo.co.uk 不是委托点（NODATA + SOA owner = co.uk），而 co.uk
// 是**多标签公共后缀**且其注册局 NS 有 A 记录。
// When：resolveAuthoritativeNS。
// Then：返回 nil 且从不向 co.uk 发 NS 查询——注册局服务器不是该域的权威，把它
// 当本域区会让 authReady 恒假、传播判定退化为递归共识并输出误导性诊断。
func TestResolveAuthoritativeNS_rejectsMultiLabelPublicSuffix(t *testing.T) {
	// Given
	fake := installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg {
		question := m.Question[0]
		switch {
		case question.Qtype == dns.TypeNS && question.Name == "foo.co.uk.":
			response := answerNS(m, "foo.co.uk.") // NOERROR/NODATA
			response.Ns = append(response.Ns, &dns.SOA{
				Hdr:     dns.RR_Header{Name: "co.uk.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns1.registry.uk.",
				Mbox:    "hostmaster.co.uk.",
				Serial:  1,
				Refresh: 60, Retry: 60, Expire: 60, Minttl: 60,
			})
			return response
		case question.Qtype == dns.TypeNS && question.Name == "co.uk.":
			return answerNS(m, "co.uk.", "ns1.registry.uk.")
		case question.Qtype == dns.TypeA && question.Name == "ns1.registry.uk.":
			return answerA(m, "ns1.registry.uk.", "192.0.2.99")
		}
		return answerNS(m, question.Name)
	})

	// When
	servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.foo.co.uk.", nsTestBootstrap)

	// Then
	if len(servers) != 0 {
		t.Fatalf("servers=%v, want nil（公共后缀 co.uk 不是该域的权威）", servers)
	}
	if got := fake.queried("co.uk.", dns.TypeNS); got != 0 {
		t.Fatalf("向公共后缀 co.uk 发起了 %d 次 NS 查询，want 0（SOA 停止条件必须拒绝公共后缀）", got)
	}
}

// Given：NS 应答的 owner 不是被查询名（污染/上级区串答）。
// When：resolveAuthoritativeNS。
// Then：这些 NS 不被采纳（否则会拿别人的服务器探测本挑战记录）。
func TestResolveAuthoritativeNS_ignoresAnswerWithForeignOwner(t *testing.T) {
	// Given
	fake := installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg {
		question := m.Question[0]
		if question.Qtype == dns.TypeNS && question.Name == "example.com." {
			// owner=other.net. 的 NS 记录：不是本次查询的对象
			return answerNS(m, "other.net.", "ns1.other.net.")
		}
		return answerNS(m, question.Name)
	})

	// When
	servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.example.com.", nsTestBootstrap)

	// Then
	if len(servers) != 0 {
		t.Fatalf("servers=%v, want nil（owner 不匹配的 NS 不得采纳）", servers)
	}
	if got := fake.queried("ns1.other.net.", dns.TypeA); got != 0 {
		t.Fatalf("对他域的 NS 做了地址解析 %d 次", got)
	}
}

// Given：所有 NS 查询都超时。
// When：resolveAuthoritativeNS。
// Then：返回 nil，且经包级日志留一条带原因的告警（原实现静默 nil）。
func TestResolveAuthoritativeNS_logsFailureReason(t *testing.T) {
	// Given
	installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg { return nil })
	var warnings strings.Builder
	originalLogf := logf
	logf = func(level, format string, args ...any) {
		if level == "warn" {
			warnings.WriteString(fmt.Sprintf(format, args...) + "\n")
		}
	}
	t.Cleanup(func() { logf = originalLogf })

	// When
	servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.example.com.", nsTestBootstrap)

	// Then
	if len(servers) != 0 {
		t.Fatalf("servers=%v, want nil", servers)
	}
	logged := warnings.String()
	if !strings.Contains(logged, "权威 NS 发现失败") || !strings.Contains(logged, "超时") {
		t.Fatalf("warnings=%q, want 失败原因留痕", logged)
	}
}

// Given：同一域名的权威 NS 发现连续失败（等待循环的每轮重发现 + 任务重试）。
// When：resolveAuthoritativeNS 短时间内被多次调用。
// Then：同一 fqdn 在限流窗口内只留一条告警——否则多域名证书单次签发
// 最坏产生 域名数×(1+重发现次数) 条同源 warn（注释曾声称「每次至多一条」）。
func TestResolveAuthoritativeNS_throttlesRepeatedFailureWarn(t *testing.T) {
	// Given
	installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg { return nil })
	var warnings strings.Builder
	originalLogf := logf
	logf = func(level, format string, args ...any) {
		if level == "warn" {
			warnings.WriteString(fmt.Sprintf(format, args...) + "\n")
		}
	}
	t.Cleanup(func() { logf = originalLogf })

	// When：同一域名 3 次（首轮 + 2 次重发现），另一域名 1 次。
	for range 3 {
		if servers := resolveAuthoritativeNS(t.Context(), "_acme-challenge.a.example.com.", nsTestBootstrap); len(servers) != 0 {
			t.Fatalf("servers=%v, want nil", servers)
		}
	}
	resolveAuthoritativeNS(t.Context(), "_acme-challenge.b.example.com.", nsTestBootstrap)

	// Then：每个域名各一条（同一域名重复失败共享同一条告警）。
	if got := strings.Count(warnings.String(), "权威 NS 发现失败"); got != 2 {
		t.Fatalf("warnings=%d 条（%q），want 2（每域名窗口内至多一条）", got, warnings.String())
	}
}

// Given：同一域名失败告警已发出，且限流窗口内仍继续失败。
// When：窗口内再次失败。
// Then：被抑制的调用不得重置窗口（必须持续抑制到窗口结束，而不是每条都放行）。
func TestResolveAuthoritativeNS_throttleWindowSuppressesBurst(t *testing.T) {
	// Given
	installFakeDNSExchange(t, func(m *dns.Msg, network string) *dns.Msg { return nil })
	var warns int
	originalLogf := logf
	logf = func(level, format string, args ...any) {
		if level == "warn" {
			warns++
		}
	}
	t.Cleanup(func() { logf = originalLogf })

	// When
	for range 20 {
		resolveAuthoritativeNS(t.Context(), "_acme-challenge.c.example.com.", nsTestBootstrap)
	}

	// Then
	if warns != 1 {
		t.Fatalf("warns=%d, want 1（20 次连续失败共享同一限流窗口）", warns)
	}
}
