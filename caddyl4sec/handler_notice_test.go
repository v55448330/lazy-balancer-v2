package caddyl4sec

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// TCP 拦截提示（2026-11-06 用户裁定）：denied 分支在断连前写入提示文本
// （渲染侧单源生成，Provision 校验形状）；透传形态（allow_sample/trust_detect）
// 不写。

// noticeConn 捕获写字节的最小 net.Conn（addrOnlyConn 复用 RemoteAddr 面）。
type noticeConn struct {
	addrOnlyConn
	buf bytes.Buffer
}

func (c *noticeConn) Write(p []byte) (int, error) { return c.buf.Write(p) }

func newNoticeConn(ip string) *layer4.Connection {
	return &layer4.Connection{Conn: &noticeConn{addrOnlyConn: addrOnlyConn{remote: tcpAddr(ip)}}, Context: context.Background()}
}

func TestHandleDenyWritesNoticeBeforeClose(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-notice", Reason: "deny", PolicyID: 5, BlockNotice: "Connection blocked by Lazy Balancer v2"})
	next := &nextCapture{}
	cx := newNoticeConn("203.0.113.50")
	if err := h.Handle(cx, next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if !next.called {
		t.Fatal("deny 形态必须透传（断连由下游 close 负责）")
	}
	conn := cx.Conn.(*noticeConn)
	if got := conn.buf.String(); got != "Connection blocked by Lazy Balancer v2\r\n" {
		t.Fatalf("写入字节 = %q, want 提示文本+CRLF", got)
	}
	s := connStatsSnapshot()
	if rule := s.Rules["r-notice"]; rule == nil || rule.DeniedTotal != 1 {
		t.Fatalf("denied 计数形态被提示写入破坏: %+v", rule)
	}
}

// 透传形态不写字节：allow_sample 与 trust_detect。
func TestHandlePassthroughFormsWriteNoNotice(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-pass", Mode: modeAllowSample, BlockNotice: "should-not-write"})
	cx := newNoticeConn("203.0.113.51")
	if err := h.Handle(cx, &nextCapture{}); err != nil {
		t.Fatalf("Handle(allow_sample) = %v", err)
	}

	h2 := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-pass2", Reason: "trust_detect", BlockNotice: "should-not-write"})
	cx2 := newNoticeConn("203.0.113.52")
	if err := h2.Handle(cx2, &nextCapture{}); err != nil {
		t.Fatalf("Handle(trust_detect) = %v", err)
	}

	for i, c := range []*layer4.Connection{cx, cx2} {
		if got := c.Conn.(*noticeConn).buf.String(); got != "" {
			t.Fatalf("形态 %d 写入了字节: %q", i, got)
		}
	}
}

// Provision 校验：控制字符与超长拒绝；合法（含 UTF-8 品牌段）通过。
func TestProvisionBlockNoticeValidation(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	base := L4SecHandler{RuleCaddyID: "r-v", Reason: "deny", PolicyID: 1}
	for name, notice := range map[string]string{
		"控制字符": "bad\x00notice",
		"换行":   "bad\nnotice",
		"超长":   strings.Repeat("x", 257),
	} {
		h := base
		h.BlockNotice = notice
		if err := h.Provision(ctx); err == nil {
			t.Fatalf("%s 形态未被拒绝", name)
		}
	}
	h := base
	h.BlockNotice = "Connection blocked by 甲板面板"
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("合法 UTF-8 文案被拒: %v", err)
	}
}
