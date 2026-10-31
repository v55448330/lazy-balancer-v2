package caddyl4sec

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// lb_l4_sec 的 reason 形态取值（契约 C2）。
const (
	reasonDeny      = "deny"
	reasonBlacklist = "blacklist"
	reasonAllow     = "allow"
	reasonGeoIP     = "geoip"
	// reasonTrustDetect 是信任检测（trust_detection=1）形态：产 logged 事件
	// 后透传（渲染侧路由序短路后续拦截路由——HTTP id:12 DetectionOnly 的
	// L4 等价物）。
	reasonTrustDetect = "trust_detect"
	modeAllowSample   = "allow_sample"

	// headerRuleID 是归因头；headerProtocol=event_type='tcp' 的唯一判据
	// （摄取侧构造处按它改判，缺失按 waf 向后兼容）。
	headerRuleID   = "X-LB-Rule-ID"
	headerProtocol = "X-LB-Protocol"
	protocolTCP    = "tcp"

	// 段位沿用 HTTP 预检 id：deny=2、独立黑名单=4、allow 交集外拒绝=7、
	// GeoIP=800000+policyID（geoipPrecheckRuleBase 同值）、信任检测=12（HTTP
	// 保留检测段位——摄取侧 IsStage1PrecheckEventID(12) 预检档评分 + logged
	// 信任白名单归因分支零新增复用）。
	segIDDeny        = 2
	segIDBlacklist   = 4
	segIDAllow       = 7
	segIDTrustDetect = 12
	geoipRuleBase    = 800000
	// geoipPolicyMax 使 800000+policyID 停留在普通 GeoIP 段 [800001,810000)
	// （与渲染侧 encodeGeoIPPrecheckRuleID 段界一致，policyID≥10000 会溢入
	// 爬虫段——Provision 显性拒绝而非送进错误归因段）。
	geoipPolicyMax = 9999
)

// eventSegment 把 reason 形态映射为契约 C1 的 messages[0]（data.id 段位 +
// 与 internal/services/security.go 预检指令逐字同款的文案——评分/归因走面板
// 既有预检分支，零新增）。
func eventSegment(reason string, policyID int64) (int64, string, bool) {
	switch reason {
	// deny/blacklist/allow/trust_detect：合并段 policy_id=0 合法（渲染侧多策略
	// 并集无单策略归因；事件归因走 X-LB-Rule-ID 头）；逐策略形态 [1,9999] 亦合法。
	case reasonDeny:
		return segIDDeny, "IP 黑名单拒绝", policyID >= 0 && policyID <= geoipPolicyMax
	case reasonBlacklist:
		return segIDBlacklist, "IP 黑名单", policyID >= 0 && policyID <= geoipPolicyMax
	case reasonAllow:
		return segIDAllow, "IP 白名单拒绝", policyID >= 0 && policyID <= geoipPolicyMax
	case reasonTrustDetect:
		// 段位对齐 HTTP 保留检测 id:12：摄取侧评分走既有预检档（12 分高危）、
		// logged 归因走信任白名单分支（securityevents.go 零新增）。文案与
		// 渲染侧 l4SecTrustDetectReason 同族语义（HTTP id:12 本体 nolog 无文案，
		// 此处取名单族命名「IP 信任名单检测」）。
		return segIDTrustDetect, "IP 信任名单检测", policyID >= 0 && policyID <= geoipPolicyMax
	case reasonGeoIP:
		if policyID < 1 || policyID > geoipPolicyMax {
			return 0, "", false
		}
		return geoipRuleBase + policyID, "GeoIP 区域拦截", true
	}
	return 0, "", false
}

// L4SecHandler 是 layer4.handlers.lb_l4_sec：两种形态——
//
//  1. reason 形态（deny/blacklist/allow/geoip/trust_detect + policy_id）：上报
//     合成事件行（契约 C1）后透传后续 handler——deny/blacklist/allow/geoip 行
//     is_interrupted=true（→ action=blocked，断连由路由里的 close handler 负责）；
//     trust_detect 行 is_interrupted=false（→ action=logged，仅记录不拦截）。
//     本 handler 只产事件与计数（安全决策与遥测解耦：队列满/IPC 失败不改变
//     拦截路径）。
//  2. mode:"allow_sample"（兜底段）：放行连接全量计数 + 按 1/16 采样做国家
//     归属累计，随后透传 proxy。
//
// client_ip 取 cx.RemoteAddr：规则开 PROXY protocol 时由渲染侧在其之前放置
// layer4.handlers.proxy_protocol（caddy-l4 将连接改写为 PROXY 源地址），自然
// 取得真实客户端；未渲染时降级 socket 对端。
type L4SecHandler struct {
	// RuleCaddyID 归因键（事件头 X-LB-Rule-ID 与计数端点的 per-rule 键）。
	RuleCaddyID string `json:"rule_caddy_id,omitempty"`
	// Reason 为 deny/blacklist/allow/geoip/trust_detect 之一（与 mode 互斥）。
	Reason string `json:"reason,omitempty"`
	// PolicyID 是绑定策略编号（事件段位 geoip 归因 800000+policyID）。
	PolicyID int64 `json:"policy_id,omitempty"`
	// Mode 仅 allow_sample（兜底段采样形态）。
	Mode string `json:"mode,omitempty"`

	// XdbPath 可选：allow_sample 采样查库用；空值用容器默认（自定义 data_dir
	// 由渲染侧发射，与 lb_geoip 同语义）。
	XdbPath string `json:"xdb_path,omitempty"`

	ruleID   string
	logger   *zap.Logger
	counters *ruleConnCounters
}

// CaddyModule returns the Caddy module information.
func (*L4SecHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.lb_l4_sec",
		New: func() caddy.Module { return new(L4SecHandler) },
	}
}

// Provision 校验配置（畸形显性报错——配置加载期拒绝，不得运行期静默漂移）、
// 标记本配置载次（计数器随 /load 重建归零，契约 C3）并注册 per-rule 计数。
func (h *L4SecHandler) Provision(ctx caddy.Context) error {
	if h.logger == nil {
		h.logger = ctx.Logger()
	}
	if h.Mode == "" {
		if h.RuleCaddyID == "" {
			return fmt.Errorf("lb_l4_sec: rule_caddy_id 不能为空（事件归因与计数键）")
		}
		if _, _, ok := eventSegment(h.Reason, h.PolicyID); !ok {
			return fmt.Errorf("lb_l4_sec: 非法 reason 形态（reason=%q policy_id=%d）——geoip 需 policy_id ∈ [1,%d]；deny/blacklist/allow/trust_detect 允许 0（合并段无单策略归因）或 [1,%d]", h.Reason, h.PolicyID, geoipPolicyMax, geoipPolicyMax)
		}
	} else {
		if h.Mode != modeAllowSample {
			return fmt.Errorf("lb_l4_sec: 未知 mode %q（仅支持 allow_sample）", h.Mode)
		}
		if h.Reason != "" {
			return fmt.Errorf("lb_l4_sec: mode=allow_sample 与 reason 形态互斥（兜底段不产事件）")
		}
		if h.RuleCaddyID == "" {
			return fmt.Errorf("lb_l4_sec: rule_caddy_id 不能为空（计数键）")
		}
	}
	h.ruleID = h.RuleCaddyID
	beginLoad(ctx)
	h.counters = getOrCreateRuleCounters(h.ruleID)
	acquirePipeline() // 惰性启动投递管线（进程级单例，见 shipper.go）
	return nil
}

// Cleanup 按指针身份注销本实例的计数条目（同载次同规则多实例共享同一计数，
// 指针不符不误删；换载次整体重置由 beginLoad 承担）。
func (h *L4SecHandler) Cleanup() error {
	if h.ruleID != "" && h.counters != nil {
		deregisterRuleCounters(h.ruleID, h.counters)
	}
	return nil
}

// Handle 实现 layer4.NextHandler。
func (h *L4SecHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	ip := clientIPFromConn(cx)
	if h.Mode == modeAllowSample {
		h.allowConnection(ip)
		return next.Handle(cx)
	}
	segID, msg, ok := eventSegment(h.Reason, h.PolicyID)
	if !ok {
		// Provision 已拒绝全部非法形态；此处为纵深防御（不可达分支按
		// 可见放行处理——L4 无 HTTP 拦截语义兜底，静默丢弃最不可辩护）。
		h.logger.Error("lb_l4_sec: unreachable reason form reached Handle, passing through",
			zap.String("reason", h.Reason), zap.Int64("policy_id", h.PolicyID))
		return next.Handle(cx)
	}
	if h.Reason == reasonTrustDetect {
		// 信任检测（logged）：事件行 is_interrupted=false（摄取侧 action=logged，
		// 仅记录不拦截）；连接到达上游=正常流量口径计 allowed（与 HTTP 信任检测
		// 请求计入流量统计一致），denied 不动；透传后续 handler（渲染侧 proxy）。
		line := buildL4EventLine(segID, msg, h.ruleID, ip, time.Now(), l4EventNonce(), false)
		publishL4Event(line)
		h.allowConnection(ip)
		return next.Handle(cx)
	}
	h.counters.denied.Add(1)
	line := buildL4EventLine(segID, msg, h.ruleID, ip, time.Now(), l4EventNonce(), true)
	publishL4Event(line)
	return next.Handle(cx)
}

// allowConnection 全量 allowed 计数 + 每 l4SampleEvery 连接采样 1 次做国家
// 归属累计（查库失败/无效国家键跳过桶计数，allowed_total 不受影响）。
func (h *L4SecHandler) allowConnection(ip string) {
	n := h.counters.allowed.Add(1)
	if n%l4SampleEvery != 1 {
		return
	}
	country, ok := l4SampleLookup(h.sampleXdbPath(), ip)
	if !ok {
		return
	}
	h.counters.recordCountry(country)
}

// sampleXdbPath 采样查库的 xdb 路径：空值=容器默认（与 lb_geoip 同语义）。
func (h *L4SecHandler) sampleXdbPath() string {
	if h.XdbPath == "" {
		return l4DefaultXdbPath
	}
	return h.XdbPath
}

// recordCountry 国家桶累计（键与 HTTP 流量统计同域：归一国名/「中国」；
// 无效键跳过）。
func (c *ruleConnCounters) recordCountry(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	c.countries[key]++
	c.mu.Unlock()
}

// l4EventNonce 生成 4 字节随机 nonce（事务 id 唯一性=去重键；math/rand/v2
// 全局源并发安全，进程内唯一性足够——跨重启由 unixnano 前缀区分）。
func l4EventNonce() [4]byte {
	var nonce [4]byte
	v := rand.Uint64()
	nonce[0] = byte(v)
	nonce[1] = byte(v >> 8)
	nonce[2] = byte(v >> 16)
	nonce[3] = byte(v >> 24)
	return nonce
}

// l4EventLine 是契约 C1 的合成审计事件行（逐字段对齐摄取侧
// securityEventsAuditTransaction：messages 是 transaction 的顶层兄弟；method/
// uri 恒空串、body 缺席；is_interrupted=true → action=blocked）。
type l4EventLine struct {
	Transaction l4EventTransaction `json:"transaction"`
	Messages    []l4EventMessage   `json:"messages"`
}

type l4EventTransaction struct {
	// UnixTimestamp 纳秒（摄取侧按纳秒转 UTC，契约 C1）。
	UnixTimestamp int64          `json:"unix_timestamp"`
	ID            string         `json:"id"`
	ClientIP      string         `json:"client_ip"`
	ServerID      string         `json:"server_id"`
	Request       l4EventRequest `json:"request"`
	IsInterrupted bool           `json:"is_interrupted"`
}

type l4EventRequest struct {
	Method  string              `json:"method"`
	URI     string              `json:"uri"`
	Headers map[string][]string `json:"headers"`
}

type l4EventMessage struct {
	Data struct {
		ID int64 `json:"id"`
	} `json:"data"`
	Message string `json:"message"`
}

// buildL4EventLine 构造一行合成事件 JSON（每行独立序列化：行进队列时已定形，
// drain 侧零反射零再分配）。interrupted=false 用于信任检测（trust_detect）
// 形态——is_interrupted=false → 摄取侧 action=logged；拦截族恒 true。
func buildL4EventLine(segID int64, msg, ruleID, clientIP string, now time.Time, nonce [4]byte, interrupted bool) []byte {
	line := l4EventLine{
		Transaction: l4EventTransaction{
			UnixTimestamp: now.UnixNano(),
			ID:            fmt.Sprintf("l4-%d-%s", now.UnixNano(), hex.EncodeToString(nonce[:])),
			ClientIP:      clientIP,
			Request: l4EventRequest{
				Headers: map[string][]string{
					headerRuleID:   {ruleID},
					headerProtocol: {protocolTCP},
				},
			},
			IsInterrupted: interrupted,
		},
	}
	line.Messages = append(line.Messages, l4EventMessage{Message: msg})
	line.Messages[0].Data.ID = segID
	raw, err := json.Marshal(line)
	if err != nil {
		// 结构恒可序列化（纯标量/映射）；防御分支按丢弃计数兜底。
		return nil
	}
	return raw
}

// publishL4Event 把事件行交给进程级投递管线（队列满/字节预算超限在管线内
// 计数丢弃，不阻塞连接路径超过 enqueue 超时）。
func publishL4Event(line []byte) {
	if line == nil {
		return
	}
	acquirePipeline().enqueueEvent(line)
}

// compile-time interface guards。
var (
	_ layer4.NextHandler = (*L4SecHandler)(nil)
	_ layer4.ConnMatcher = (*L4GeoIPMatcher)(nil)
	_ caddy.Module       = (*L4SecHandler)(nil)
)

func init() {
	caddy.RegisterModule(&L4SecHandler{})
	caddy.RegisterModule(&L4GeoIPMatcher{})
	caddy.RegisterModule(L4StatsAdmin{})
}
