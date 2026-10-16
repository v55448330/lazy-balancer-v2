package caddygeoip

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
)

// securityBlockedMetricName 是安全拦截计数器指标名。
const securityBlockedMetricName = "security_blocked_total"

// newSecurityBlockedCounterVec 每次 Provision 新建 CounterVec 并注册——
// caddy-l4 newProxyMetrics 同模式(l4proxy/metrics.go:54):同 registry 时
// registerOrExisting 复用已注册实例(不丢数据),跨 reload 新 registry 时
// 全新注册(归零,与 caddy_http_* 同纪元)——P3-1(第 28.5 轮审计):包级
// singleton 跨 reload 不归零,与 caddy_http_* 纪元错位,扣除常态钳 4xx 到 0。
func newSecurityBlockedCounterVec(reg *prometheus.Registry) *prometheus.CounterVec {
	return registerOrExisting(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "lazybalancer",
			Name:      securityBlockedMetricName,
			Help:      "Requests interrupted by the security engine (WAF/GeoIP/IP ACL) with a 4xx status.",
		},
		[]string{"rule"},
	))
}

// registerOrExisting 注册到 reg,已注册时复用既有实例——Caddy reload 会重
// Provision,重复注册 MustRegister 会 panic(崩溃风险,用户裁定零容忍);
// 与 caddy-l4 的 registerOrExisting(l4proxy/metrics.go:34)同模式。
func registerOrExisting[C prometheus.Collector](reg *prometheus.Registry, c C) C {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(C); ok {
				return existing
			}
		}
		// 其他注册错误=指标不可用——回落未注册实例(计数 no-op 而非崩溃)。
	}
	return c
}

func init() {
	caddy.RegisterModule(SecurityBlockedCounter{})
}

// SecurityBlockedCounter 是安全拦截计数中间件:包装 WAF handler,检测安全层
// 中断(caddyhttp.HandlerError 且 4xx status,且 len(ID)==16 或 status==429)并
// 按规则计数。覆盖:coraza 中断(WAF/GeoIP/IP ACL,ID=tx.ID() 16 字符)+限流 429;
// 排除:proxy 499/request_body 413/其他 caddyhttp.Error 4xx(ID 9 字符)/coraza
// 引擎 500(4xx 约束);上游 4xx 不产 HandlerError 不误计。
// 稳定优先设计(2026-09-15 用户裁定,负载均衡/WAF 稳定最重要):
//   - Provision 无操作——无 I/O/无外部依赖/无失败模式,配置加载零风险;
//   - ServeHTTP 只读检测——不修改请求/响应/错误,链语义与无插件时逐字节一致;
//   - 无锁/无共享态——prometheus counter 线程安全,reload 幂等;
//   - API 兼容面:caddy.Module/caddyhttp.HandlerError 稳定(v2.0 起);
//     ctx.GetMetricsRegistry() 是 EXPERIMENTAL(Caddy 标注 subject to change)
//     ——已 nil 守卫(移除则降级为不计数而非崩溃),P5-3(第 28.5 轮审计)。
type SecurityBlockedCounter struct {
	// Rule 是所属负载均衡规则的 caddy_id(渲染期静态注入)。
	Rule string `json:"rule,omitempty"`

	metrics *prometheus.CounterVec
}

// CaddyModule returns the Caddy module information.
func (SecurityBlockedCounter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_security_blocked_counter",
		New: func() caddy.Module { return new(SecurityBlockedCounter) },
	}
}

// Provision 注册计数器到 Caddy 的 metrics registry(非默认 registry——
// 默认 registry 的指标不暴露在 Caddy /metrics 端点);registerOrExisting
// 保证 reload 幂等(重复注册复用实例,不 panic)。计时写目标是进程内注册表
// （auditTimingRecord，auditwriter.go）——无后台管线生命周期，本 handler
// 不再持有 Provision/Cleanup 引用计数（第 76 轮侧车退役）。
func (h *SecurityBlockedCounter) Provision(ctx caddy.Context) error {
	if reg := ctx.GetMetricsRegistry(); reg != nil {
		h.metrics = newSecurityBlockedCounterVec(reg)
	}
	return nil
}

// ServeHTTP 调用链下游处理器,只读检查返回错误:安全层中断(HandlerError 且
// 4xx status,且 len(ID)==16[coraza tx.ID] 或 status==429[限流])时按规则计数;
// 上游 4xx 不产 HandlerError(反向代理直写响应)不误计;返回值原样透传。
//
// 安全处理耗时(2026-09-27 用户裁定;第 76 轮侧车退役):请求进入时注入
// X-Lb-Security-Timing-Id 请求头(coraza 审计日志 request.headers 天然收录——
// 审计写插件从审计事务头提取该 ID 作进程内计时注册表的关联键),next 返回后
// 把耗时写入注册表——经审计写插件注入审计行 lb_timing 字段,弹框「处理耗时」
// 的数据源。写侧在本方法(拦截事件+终态标记)+security_timing_pre/end(放行
// 事件分段);读侧在 internal/services/securityevents.go 的
// securityEventsParseTransaction(直接读审计行内嵌 lb_timing)。
func (h *SecurityBlockedCounter) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 安全处理耗时:注入 timing ID + 起始纳秒双头(coraza 审计日志收录 ID;
	// SecurityTimingPre 记 pre 后把起始头重写为「预检完成」分段锚点,
	// SecurityTimingEnd 读锚点计算 logged 事件的 WAF 段耗时)。起始头与 ID 头
	// 均在 proxyRequestHeaders 删除清单剥离,不上泄上游。
	timingID := securityTimingID()
	var timingStartVal string
	if timingID != "" {
		timingStartVal = strconv.FormatInt(time.Now().UnixNano(), 10)
		r.Header.Set(securityTimingHeader, timingID)
		r.Header.Set(securityTimingStartHeader, timingStartVal)
	}
	start := time.Now()

	err := next.ServeHTTP(w, r)

	var herr caddyhttp.HandlerError
	// P3-2(第 28.5 轮审计):「ID 非空+4xx」误纳非安全 4xx——caddyhttp.Error
	// 恒生成 ID(randString 9 字符),proxy 499/request_body 413 也被计入。
	// 精确判定:len(ID)==16(coraza tx.ID,randomString(16))或 status==429
	// (限流,caddyhttp.Error 生成 9 字符 ID)——覆盖安全拦截全部,排除
	// proxy 499/request_body 413/其他 caddyhttp.Error 4xx(全 9 字符)。
	// 脆弱点:coraza 若改 tx.ID 长度→断;但 v2.x 一直 16 且 coraza 由
	// Dockerfile pin+构建断言控制——可控。
	isSecurityBlock := err != nil && errors.As(err, &herr) &&
		herr.StatusCode >= 400 && herr.StatusCode < 500 &&
		(len(herr.ID) == 16 || herr.StatusCode == http.StatusTooManyRequests)

	// 安全处理耗时——分段选键(第 75 轮,预检拦口径):单一写点保证同 ID 恰一段,
	// 无双段混乱。此刻中断已裁决、403 响应尚未写出(错误路由在 Server
	// 层于本 handler 返回后才执行)——两种键都是纯评估口径(决策→计时→注册表
	// →入队注入的顺序保证降级模式下耗时数字不受污染,见 auditwriter.go):
	//   起始头仍=注入原值 → 链未抵达预检收点(SecurityTimingPre 未重写锚点)
	//     =预检段拦(IP ACL/GeoIP/信任/威胁)→ 写 pre=预检决策耗时;
	//   头已被重写 → 预检已放行,中断出自 WAF/限流段 → 写 end=链首至此全链
	//     (读侧 - pre 得 WAF 段)。
	// timingID 为空(随机源失败)时全程无计时,不写(下分支同门)。
	if timingID != "" && isSecurityBlock {
		if r.Header.Get(securityTimingStartHeader) == timingStartVal {
			auditTimingRecord(timingID, timingSegmentPre, time.Since(start).Microseconds())
		} else {
			auditTimingRecord(timingID, timingSegmentEnd, time.Since(start).Microseconds())
		}
	}
	// 终态标记:本 handler 是链最外层收点,post-next 时全部分段写点(timing_pre/
	// timing_end/本方法)均已完成——审计写插件的 drain goroutine 见终态即注入
	// 落盘,不再等待。计时数字在上方决策点测得,终态标记与注入均不改变数值。
	if timingID != "" {
		auditTimingClose(timingID)
	}

	if isSecurityBlock {
		// F1(第 28.6 轮审计):P3-2 判定丢失 4xx 约束——coraza 引擎 500
		// (16 字符 tx.ID)被误计为安全拦截且吃掉一个合法 4xx。恢复 4xx 约束。
		if h.metrics != nil {
			h.metrics.WithLabelValues(h.Rule).Inc()
		}
	}
	// 大屏全请求实时流量计数（Plan B）：链尾分类点——attack=安全中断
	// （isSecurityBlock 同口径）、normal=非安全中断的已处理请求（含上游
	// 透传）；国名取 X-LB-GeoIP-Country（geoip handler 已剥伪造头并按
	// 客户端 IP 回填，未解析=空串由计数器跳过）。
	trafficRecord(r.Header.Get("X-LB-GeoIP-Country"), isSecurityBlock)
	return err
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddy.Provisioner           = (*SecurityBlockedCounter)(nil)
	_ caddyhttp.MiddlewareHandler = (*SecurityBlockedCounter)(nil)
)
