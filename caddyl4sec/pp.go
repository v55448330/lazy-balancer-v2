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
)

// L4PPHandler 采信面 = Allow 网段内的对端。空 Allow（渲染侧未启用受信代理/
// 零有效网段）= 全部来源按 IGNORE——严格但与 HTTP 侧「仅受信网段采信」口径
// 一致；直连客户端（无头）不受影响。Allow 内容由渲染侧受信代理解析单源
// 产出（含过宽门/规范形态），模块侧只兜裸配置/带外直写配置文件形态（非
// CIDR、全空间与过宽网段含 v4-mapped 变体）显性拒绝，判据与渲染侧过宽门
// 逐字同步（见 ppAllow* 各函数与 services 侧机械守卫钉测）。
type L4PPHandler struct {
	Allow []string `json:"allow,omitempty"`

	allow []netip.Prefix
}

// CaddyModule returns the Caddy module information.
func (*L4PPHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.lb_l4_pp",
		New: func() caddy.Module { return new(L4PPHandler) },
	}
}

// Provision 解析 Allow 为前缀集（非法显性报错——配置加载期拒绝，不得运行期
// 静默漂移）；过宽门与渲染侧受信代理同判据（覆盖全部地址空间=等同信任任意
// 来源，低于最小前缀长度 v4 /8、v6 /29），归一按规范形态（Masked 剥主机位 +
// v4-mapped 折等价 v4）执行——判据逐字同步见下方 ppAllow* 函数。
func (h *L4PPHandler) Provision(ctx caddy.Context) error {
	allow := make([]netip.Prefix, 0, len(h.Allow))
	for _, cidr := range h.Allow {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("lb_l4_pp: allow 网段 %q 不是有效 CIDR: %v", cidr, err)
		}
		if ppAllowPrefixAllSpace(prefix) {
			return fmt.Errorf("lb_l4_pp: allow 网段 %q 覆盖全部地址空间（等同信任任意来源），拒绝", cidr)
		}
		if ppAllowPrefixBelowMinBits(prefix) {
			return fmt.Errorf("lb_l4_pp: allow 网段 %q 过宽：最小允许 /8（IPv4）与 /29（IPv6）", cidr)
		}
		allow = append(allow, ppAllowPrefixCanonical(prefix))
	}
	h.allow = allow
	return nil
}

// 以下四个判据函数与 internal/services/caddy.go 的
// TrustedProxyPrefixCanonical / trustedProxyMinPrefixBits /
// TrustedProxyPrefixAllSpace / TrustedProxyPrefixBelowMinBits 逐字同判据
// （独立模块不能 import services，两侧逐字同步，改动必须成对；机械守卫见
// services 侧 l4_pp_gate_sync_test.go）。渲染侧过宽门是生产单源，模块侧只兜
// 裸配置/带外直写形态，报错文案各自语境化、判据不得分叉。

// ppAllowPrefixCanonical 把前缀归一为规范形态：Masked() 剥掉主机位，
// 4in6 映射形态折成等价 v4 前缀；位数 <96 的 mapped 写法覆盖整个
// v4-mapped 空间（=全部 IPv4），归一为 0.0.0.0/0。非映射前缀只剥主机位。
func ppAllowPrefixCanonical(prefix netip.Prefix) netip.Prefix {
	if !prefix.IsValid() {
		return prefix
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}
		return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
	}
	return prefix.Masked()
}

// ppAllowMinPrefixBits 报告地址族的最小允许前缀长度（IPv6 /29、IPv4 /8）。
func ppAllowMinPrefixBits(addr netip.Addr) int {
	if addr.Is6() {
		return 29
	}
	return 8
}

// ppAllowPrefixAllSpace 报告前缀（按规范形态归一后）是否覆盖全部地址空间
// （等同信任任意来源）：0.0.0.0/8、0.0.0.0/0、::/0，以及归一到等价 v4 后
// 落入这组的 v4-mapped 变体。
func ppAllowPrefixAllSpace(prefix netip.Prefix) bool {
	switch ppAllowPrefixCanonical(prefix).String() {
	case "0.0.0.0/8", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

// ppAllowPrefixBelowMinBits 报告（按规范形态归一后的）前缀长度低于最小
// 允许值：4in6 映射形态按等价 v4 判宽（最小 /8 折合 mapped /104）。
func ppAllowPrefixBelowMinBits(prefix netip.Prefix) bool {
	canonical := ppAllowPrefixCanonical(prefix)
	return canonical.Bits() < ppAllowMinPrefixBits(canonical.Addr())
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
// caddy-l4 的路由 matcher 集先于 handle 链评估，链内 Wrap 只惠及其后同链
// handler——改写面=lb_l4_sec 的事件归因（client_ip）与发往上游的 PROXY
// 头，均按采信后的对端；名单/地域判定（lb_ipfile/lb_geoip 是路由 matcher）
// 恒读 socket 对端，改写到不了任何 matcher（渲染侧携带本 handler 的路由都
// 以 close/proxy 在自身内终止，Wrap 不进入后续路由匹配）。其余来源的头被
// 消费、地址保持真实对端。无 PROXY 头的连接在 IGNORE/USE 下照常透传
// （go-proxyproto 仅 REQUIRE 拒无头）。
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
	// 随 Wrap 透传），同链后续 handler（lb_l4_sec、proxy）经 RemoteAddr() 读
	// 采信后对端；路由 matcher 先于本 handler 评估，不受改写影响。
	return next.Handle(cx.Wrap(pconn))
}
