package caddyl4sec

// TCP 规则 PROXY v2 入站解析信任门控（layer4.handlers.lb_l4_pp）：
// 上游 l4proxyprotocol 在 go-proxyproto v0.15 下 NewConn 恒施加 DefaultPolicy
// （REQUIRE——直连无头即拒 + 任意来源声明源被采信），其 allow/fallback_policy
// 字段不进 NewConn，属死配置。本模块以逐连接显式策略替代上游裸发射：
// 对端 ∈ Allow（受信代理网段，渲染侧经受信代理解析单源展开）→ USE（采信
// 声明源）；其余 → IGNORE（头被消费不采信，按直连地址处理；无头直连照常
// 透传）。策略逐连接显式设置，不依赖上游版本默认值。
import (
	"fmt"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

// L4PPHandler 采信面 = Allow 网段内的对端。空 Allow（渲染侧未启用受信代理/
// 零有效网段）= 全部来源按 IGNORE——严格但与 HTTP 侧「仅受信网段采信」口径
// 一致；直连客户端（无头）不受影响。Allow 内容由渲染侧受信代理解析单源
// 产出（含过宽门/规范形态），模块侧只兜裸配置形态（非 CIDR、v4-mapped
// 全空间写法）显性拒绝。
type L4PPHandler struct {
	Allow []string `json:"allow,omitempty"`

	allow  []netip.Prefix
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*L4PPHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.lb_l4_pp",
		New: func() caddy.Module { return new(L4PPHandler) },
	}
}

// Provision 解析 Allow 为前缀集（非法显性报错——配置加载期拒绝，不得运行期
// 静默漂移）；v4-mapped 写法折成等价 v4 前缀（Contains 的地址族才一致），
// 折后覆盖全部 IPv4 的 /0 形态拒绝（等价信任全部来源，渲染侧过宽门同判据）。
func (h *L4PPHandler) Provision(ctx caddy.Context) error {
	if h.logger == nil {
		h.logger = ctx.Logger()
	}
	allow := make([]netip.Prefix, 0, len(h.Allow))
	for _, cidr := range h.Allow {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("lb_l4_pp: allow 网段 %q 不是有效 CIDR: %v", cidr, err)
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		if prefix.Addr().Is4() && prefix.Bits() == 0 {
			return fmt.Errorf("lb_l4_pp: allow 网段 %q 覆盖全部 IPv4 地址空间（等价信任全部来源），拒绝", cidr)
		}
		allow = append(allow, prefix)
	}
	h.allow = allow
	return nil
}

// trustedRemote 报告对端地址是否 ∈ Allow（4in6 对端 Unmap 后按 v4 判）。
func (h *L4PPHandler) trustedRemote(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range h.allow {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Handle 按对端归属显式定策（受信 USE / 其余 IGNORE）并安装改写连接：
// 受信来源的声明源经 RemoteAddr 呈现给链上后续 matcher/handler（lb_l4_sec
// 的事件归因与发往上游的 PROXY 头都按采信后的对端）；其余来源的头被消费、
// 地址保持真实对端。无 PROXY 头的连接在 IGNORE/USE 下照常透传（go-proxyproto
// 仅 REQUIRE 拒无头）。
func (h *L4PPHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	policy := proxyproto.IGNORE
	if h.trustedRemote(cx.RemoteAddr()) {
		policy = proxyproto.USE
	}
	var opts []func(*proxyproto.Conn)
	opts = append(opts, proxyproto.WithPolicy(policy))
	// Buffer 尺寸与上游 l4proxyprotocol 同取 layer4.MaxBufLen：go-proxyproto 内部
	// bufio 需一次吞下 cx 预取块，默认 256B 会触发流错位（后续 matcher 读到
	// 中段数据或等不到数据超时）。
	opts = append(opts, proxyproto.WithBufferSize(layer4.MaxBufLen))
	pconn := proxyproto.NewConn(cx, opts...)
	// 安装手法同上游 Handle：包装连接替换 cx 的底层连接（vars/repl 等上下文
	// 随 Wrap 透传），链上后续 matcher/handler 经 RemoteAddr() 读采信后对端。
	return next.Handle(cx.Wrap(pconn))
}
