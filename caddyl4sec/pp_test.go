package caddyl4sec

// TCP 规则 PROXY v2 入站解析信任门控（layer4.handlers.lb_l4_pp）钉测：
// 上游 l4proxyprotocol 在 go-proxyproto v0.15 下 NewConn 恒施加 DefaultPolicy
// （REQUIRE——直连无头即拒 + 任意来源声明源被采信），其 allow/fallback_policy
// 字段不进 NewConn，属死配置。本模块以逐连接显式策略替代：
// 对端 ∈ Allow（受信代理网段）→ USE（采信声明源）；其余 → IGNORE（头被
// 消费不采信，按直连地址；无头直连照常透传）。
import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/pires/go-proxyproto"
)

// ppBytesConn 是带预置线路字节的最小 net.Conn（addrOnlyConn 复用 RemoteAddr 面，
// 追加 Read 消费预置字节——PROXY 头解析走真实 go-proxyproto 读取路径）。
// go-proxyproto 读头前会触碰读截止时间（readHeaderTimeout=0 时仍读当前值），
// deadline 系列需可调用。
type ppBytesConn struct {
	addrOnlyConn
	r *bytes.Reader
}

func (c *ppBytesConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *ppBytesConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *ppBytesConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *ppBytesConn) SetDeadline(t time.Time) error      { return nil }

// ppCapture 捕获链上后续 handler 视角的对端地址与可读载荷。
type ppCapture struct {
	called  bool
	remote  net.Addr
	payload []byte
}

func (c *ppCapture) Handle(cx *layer4.Connection) error {
	c.called = true
	c.remote = cx.RemoteAddr()
	buf := make([]byte, 256)
	n, _ := cx.Read(buf)
	c.payload = append([]byte(nil), buf[:n]...)
	return nil
}

func newPPHandlerForTest(t *testing.T, allow []string) *L4PPHandler {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	h := &L4PPHandler{Allow: allow}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}
	return h
}

// L4PPHandler 无死 logger 字段守卫：logger 字段与 Provision 赋值全仓零消费
// （模块无任何日志消费面，caddy 侧统一接管）——回加即失败，防死重量回归。
func TestL4PPHandlerHasNoDeadLoggerField(t *testing.T) {
	source, err := os.ReadFile("pp.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "logger") {
		t.Fatal("pp.go 仍含 logger 字段或赋值（全仓零消费的死重量），不得回加")
	}
}

// ppProxyV2Wire 构造真实 PROXY v2 头（声明源 declaredSource）+ 载荷 PING。
func ppProxyV2Wire(t *testing.T, declaredSource string) []byte {
	t.Helper()
	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP(declaredSource),
			Port: 41000,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("203.0.113.7"),
			Port: 9000,
		},
	}
	wire, err := header.Format()
	if err != nil {
		t.Fatalf("format proxy v2 header: %v", err)
	}
	return append(wire, []byte("PING")...)
}

func newPPTestConn(ip string, wire []byte) *layer4.Connection {
	return &layer4.Connection{
		Conn:    &ppBytesConn{addrOnlyConn: addrOnlyConn{remote: tcpAddr(ip)}, r: bytes.NewReader(wire)},
		Context: context.Background(),
	}
}

func ppRemoteHost(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// TestL4PPModuleID 锁定模块 ID（与渲染侧发射逐字对账，另见 services 侧
// l4sec_module_contract_test.go）。
func TestL4PPModuleID(t *testing.T) {
	h := &L4PPHandler{}
	if id := h.CaddyModule().ID; id != "layer4.handlers.lb_l4_pp" {
		t.Fatalf("handler module ID = %q, want layer4.handlers.lb_l4_pp", id)
	}
	var _ layer4.NextHandler = h
}

// TestL4PPProvisionValidation 非法 CIDR 显性报错（配置加载期拒绝，不得运行期
// 静默漂移）；空 Allow 合法（全部来源按 IGNORE）；v4-mapped 全空间写法与裸
// 全空间/过宽网段拒绝（渲染侧过宽门是生产单源，模块侧兜住裸配置形态），
// 合法网段（/24、/64）必须通过。
func TestL4PPProvisionValidation(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	ctx.Logger()
	if err := (&L4PPHandler{Allow: []string{"203.0.113.0/24", "not-a-cidr"}}).Provision(ctx); err == nil {
		t.Fatalf("非法 CIDR 必须显性报错")
	}
	if err := (&L4PPHandler{Allow: []string{"::ffff:0.0.0.1/96"}}).Provision(ctx); err == nil {
		t.Fatalf("v4-mapped 全空间写法必须显性报错（等价信任全部 IPv4 来源）")
	}
	// 裸全空间/过宽写法与渲染侧过宽门同判据拒绝：::/0 与 0.0.0.0/8 覆盖全部
	// 地址空间，2000::/1 低于 IPv6 最小前缀长度 /29。
	for _, wide := range []string{"::/0", "0.0.0.0/8", "2000::/1"} {
		if err := (&L4PPHandler{Allow: []string{wide}}).Provision(ctx); err == nil {
			t.Fatalf("过宽网段 %q 必须显性拒绝（等同信任任意来源/低于最小前缀长度）", wide)
		}
	}
	if err := (&L4PPHandler{Allow: []string{"203.0.113.0/24", "2001:db8::/64"}}).Provision(ctx); err != nil {
		t.Fatalf("合法网段（/24、/64）必须通过: %v", err)
	}
	if err := (&L4PPHandler{Allow: nil}).Provision(ctx); err != nil {
		t.Fatalf("空 Allow 必须合法（全部来源按 IGNORE）: %v", err)
	}
}

// TestL4PPHandleTrustedSourceAdoptsDeclaredAddr 受信网段来源发 PROXY v2 头：
// 声明源被采信（后续 handler 视角 RemoteAddr=声明源），载荷透传不丢。
func TestL4PPHandleTrustedSourceAdoptsDeclaredAddr(t *testing.T) {
	h := newPPHandlerForTest(t, []string{"203.0.113.0/24"})
	next := &ppCapture{}
	if err := h.Handle(newPPTestConn("203.0.113.7", ppProxyV2Wire(t, "198.51.100.9")), next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if !next.called {
		t.Fatalf("后续 handler 未被调用")
	}
	if got := ppRemoteHost(next.remote); got != "198.51.100.9" {
		t.Fatalf("受信来源声明源未采信: remote host=%s, want 198.51.100.9", got)
	}
	if string(next.payload) != "PING" {
		t.Fatalf("载荷透传缺失: %q, want PING", next.payload)
	}
}

// TestL4PPHandleUntrustedSourceKeepsRealAddr 非受信来源发 PROXY v2 头：头被
// 消费但不采信（RemoteAddr 保持真实对端），载荷照常透传（无 REQUIRE 拒连）。
func TestL4PPHandleUntrustedSourceKeepsRealAddr(t *testing.T) {
	h := newPPHandlerForTest(t, []string{"203.0.113.0/24"})
	next := &ppCapture{}
	if err := h.Handle(newPPTestConn("8.8.8.8", ppProxyV2Wire(t, "198.51.100.9")), next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if got := ppRemoteHost(next.remote); got != "8.8.8.8" {
		t.Fatalf("非受信来源声明源必须不采信: remote host=%s, want 8.8.8.8", got)
	}
	if string(next.payload) != "PING" {
		t.Fatalf("载荷透传缺失: %q, want PING", next.payload)
	}
}

// TestL4PPHandleHeaderlessDirectClient 直连客户端（无 PROXY 头）照常透传：
// 显式 IGNORE 不要求头（与上游 v0.15 REQUIRE 默认值分叉的本体）。
func TestL4PPHandleHeaderlessDirectClient(t *testing.T) {
	h := newPPHandlerForTest(t, []string{"203.0.113.0/24"})
	next := &ppCapture{}
	if err := h.Handle(newPPTestConn("8.8.8.8", []byte("PING")), next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if got := ppRemoteHost(next.remote); got != "8.8.8.8" {
		t.Fatalf("无头直连对端不得改变: remote host=%s, want 8.8.8.8", got)
	}
	if string(next.payload) != "PING" {
		t.Fatalf("无头直连载荷透传缺失: %q, want PING", next.payload)
	}
}
