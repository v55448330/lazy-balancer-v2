package caddygeoip

// 审计写插件（第 76 轮，架构改进：耗时侧车文件退役 → 审计行内嵌 timing）。
//
// coraza 以 `SecAuditLogType lbfile` 选用本插件（security.go 渲染层发射）。
// 与退役的 serial 直写相比的两个职责：
//
//  1. timing 注入：进程内 per-request 计时注册表（auditTiming*，写点=
//     blocked_counter / SecurityTimingPre / SecurityTimingEnd，键=blocked_counter
//     注入的 X-Lb-Security-Timing-Id 头值——审计 JSON 的 request.headers 天然
//     收录该头，Write 无需解析正文即可取得关联键）在刷盘前注入审计 JSON 顶层
//     lb_timing 字段：{"pre_us":N,"end_us":M}（缺席分段省略）。读侧
//     （internal/services/securityevents.go）直接从审计行取值，
//     侧车文件与读侧 tick 级查表已整体退役。
//
//  2. 异步批量落盘 + 格式化后置：Write 只构建审计快照入队（formatter.Format
//     已移出请求路径——快照是 headers map 深拷贝+不可变字符串持有的 memcpy 级
//     开销，防 tx.Close 归还 sync.Pool 后的 live 引用污染），专职 drain goroutine
//     用注册 formatter 格式化、限时等待计时终态、注入 lb_timing、bufio 批量刷盘
//     （阈值/周期双触发）。入队阻塞式（零丢弃；队列满时请求路径阻塞等 drain
//     消化，退化价=退役前 serial 同步写）；管线已关（重载窗口在途写入）时回退
//     同步直写（短生命周期 fd O_APPEND 单行追加+计时同步短等注入），同样零丢弃。
//
// 时序契约（为什么注入在 drain 侧而非 Write 侧）：coraza-caddy 在 WAF 中间件
// 退出时 defer tx.ProcessLogging()——审计 Write 严格早于 blocked_counter（外层
// 包装）恢复执行与 SecurityTimingEnd（下游收点）执行，此刻该请求的分段耗时
// 尚未产生。drain goroutine 对每条审计行限时等待注册表终态（closed），等待
// 发生在请求路径之外；耗时数值在决策点测得（time.Since 决策瞬间），入队/
// 队列等待/刷盘延迟永不进入数值——「决策→计时→入队」的顺序保证降级模式下
// 耗时数字不受污染。
//
// 轮转兼容（auditlog_rotation.go 核对）：轮转 = copytruncate（复制后截断，
// 长生命周期 fd 恒有效，O_APPEND 恒写当前 EOF），本插件不做 rename 重开；
// bufio 中暂存的字节在截断后落盘会出现在新文件头部，摄取按行解码+transaction_id
// 幂等去重，乱序无影响、零丢失。

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// auditWriterName 是插件注册名——渲染层以 `SecAuditLogType lbfile` 选用
// （coraza GetWriter 大小写不敏感）。
const auditWriterName = "lbfile"

func init() {
	plugins.RegisterAuditLogWriter(auditWriterName, func() plugintypes.AuditLogWriter {
		return &lbAuditWriter{}
	})
}

// 管线参数（var 供测试收窄）。
var (
	// auditQueueSize 有界队列容量：2048 条 × 典型 2-8KB ≈ 上限 16MB 内存，
	// 打满即请求路径阻塞（零丢弃的退化价，与退役前 serial 同步写同价）。
	auditQueueSize = 2048
	// auditFlushThreshold bufio 批量刷盘字节数阈值；auditFlushInterval 周期
	// 兜底（低流量下 bufio 滞留行不超周期）。
	auditFlushThreshold = 32 * 1024
	auditFlushInterval  = 500 * time.Millisecond
	// auditTimingWaitLimit drain 对「条目在场但未终态」分段的限时等待：正常形态
	// （blocked_counter 是链最外层收点，紧随 coraza 中间件 defer）等待 <1ms；
	// 上限仅兜底异常形态（计时写点缺失），超时按已到场分段注入。未知 tid
	// （注册表无条目）不进本等待——auditTimingWait 首轮查表未命中即返（AUD-1，
	// 第 76 轮：单 drain goroutine 逐行满等=无背压阀下的 drain 沉陷）。
	auditTimingWaitLimit = 2 * time.Second
	auditTimingPollStep  = 200 * time.Microsecond
	// auditSyncTimingWaitLimit 同步回退写（管线已关的重载窗口在途行）的计时
	// 短等上限：等待发生在请求路径，正常形态 µs 级置位终态；上限只兜底异常
	// 形态，超限按已到场分段落盘（行不丢、缺段省略）。
	auditSyncTimingWaitLimit = 5 * time.Millisecond
	// auditTimingEntryTTL 注册表条目存活上限：条目由周期性清扫回收（消费不删——
	// 同一请求可产多条审计行[预检+策略引擎]，共享同一注册表条目）。
	auditTimingEntryTTL = 30 * time.Second
)

// —— per-request 计时注册表 ——
// 写点：SecurityTimingPre(:pre)/SecurityTimingEnd(:end)/blocked_counter(:pre 或
// :end + 终态 close)。读点：audit drain goroutine（限时等待终态后注入）。
// 键=X-Lb-Security-Timing-Id 头值（16 字符随机 hex，进程内唯一；coraza tx ID
// 每引擎独立生成，一个请求多个引擎多个 tx ID，不能作请求级键）。

type auditTimingEntry struct {
	mu     sync.Mutex
	preUs  int64
	endUs  int64
	preSet bool
	endSet bool
	// closed 终态标记：链最外层收点（blocked_counter post-next）在全部分段
	// 写点完成后的空值写法（guard）下置位——drain 见 closed 即注入并停止等待。
	closed  bool
	created time.Time
}

// auditTimingSnapshot 是 wait 的只读快照；preSet/endSet 区分「未记录」与
// 「记录为 0」（0µs 是合法计时值）。
type auditTimingSnapshot struct {
	preUs  int64
	preSet bool
	endUs  int64
	endSet bool
	closed bool
}

func (s auditTimingSnapshot) hasAny() bool { return s.preSet || s.endSet }

var (
	auditTimingMu      sync.Mutex
	auditTimingEntries = map[string]*auditTimingEntry{}
	// auditTimingCreateCount 记录创建次数——每 64 次创建触发一次过期清扫
	// （摊销 O(1)；size 超限时立即清扫兜底突发）。
	auditTimingCreateCount int
	auditTimingSweepMin    = 4096
)

// auditTimingRecord 写入一个分段计时（µs）。id 为空（计时 ID 生成失败的降级
// 形态）静默忽略——耗时是增强信息，不产生请求路径错误。
func auditTimingRecord(id, segment string, us int64) {
	if id == "" {
		return
	}
	now := time.Now()
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	if e == nil {
		e = &auditTimingEntry{created: now}
		auditTimingEntries[id] = e
		auditTimingSweepIfDueLocked(now)
	}
	auditTimingMu.Unlock()
	e.mu.Lock()
	switch segment {
	case "pre":
		e.preUs, e.preSet = us, true
	case "end":
		e.endUs, e.endSet = us, true
	}
	e.mu.Unlock()
}

// auditTimingClose 标记该请求的全部分段已写完（终态）。由链最外层收点
// （blocked_counter post-next）调用——此刻整个安全链已返回，不会再有分段写点。
// 条目不存在（极形态：链上无任何分段写点执行）时创建空终态条目——审计 drain
// 见终态立即注入空快照（无 lb_timing 字段），不等满超时。
func auditTimingClose(id string) {
	if id == "" {
		return
	}
	now := time.Now()
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	if e == nil {
		e = &auditTimingEntry{created: now}
		auditTimingEntries[id] = e
		// U14-03（第 78 轮）：close 建条路径与 record 共用同一「自增 + 摊销
		// 清扫」helper——纯 close 流量（无任何分段写点）此前完全不触发清扫，
		// 过期条目积压到下一次 record 才清。
		auditTimingSweepIfDueLocked(now)
	}
	auditTimingMu.Unlock()
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

// auditTimingSweepIfDueLocked 建条计数 + 摊销清扫（调用方持 auditTimingMu）。
func auditTimingSweepIfDueLocked(now time.Time) {
	auditTimingCreateCount++
	if auditTimingCreateCount%64 == 0 || len(auditTimingEntries) > auditTimingSweepMin {
		auditTimingSweepLocked(now)
	}
}

// auditTimingWait 限时等待该请求的计时终态并返回快照。正常形态下 blocked_counter
// 在 coraza 中间件 defer 之后数微秒内置位终态，等待≈一个调度间隙；上限只兜底
// 「条目在场但未终态」的异常形态（计时写点缺失，超时返回已到场分段，行不丢、
// 缺段省略）。id 为空（无 timing 头的审计行）或首轮查表无条目（未知 tid）立即
// 返回空快照。
//
// AUD-1（第 76 轮）：未知 tid 首轮即返，不轮询到超时。「条目暂未创建」的唯一
// 合法窗口是同一请求 goroutine 内 Write（coraza defer ProcessLogging）→
// blocked_counter 收点置位终态之间的微秒级间隙，而 drain 侧先格式化（整行
// json.Marshal）再查表，恒晚于该间隙——首轮未命中只可能是陈旧行（队列积压超
// TTL，条目已被清扫）或写点缺失的异常行，分段数据永不到场。旧行为对未知 tid
// 轮询满超时：单 drain goroutine × 逐行满等 2s × 入队阻塞式零丢弃（无背压阀）
// = 积压行批量到场时 drain 沉陷、请求路径被拖住。代价：预检拦行的终态由
// blocked_counter post-next 在 Write 后微秒级补写，首轮恰落在该间隙内的行
// （drain 抢先完成格式化的极小竞态窗）不注入 lb_timing——耗时是增强信息，
// 展示层报「—」，可接受。
func auditTimingWait(id string, timeout time.Duration) auditTimingSnapshot {
	if id == "" {
		return auditTimingSnapshot{}
	}
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	auditTimingMu.Unlock()
	if e == nil {
		return auditTimingSnapshot{}
	}
	deadline := time.Now().Add(timeout)
	var lastSeen auditTimingSnapshot
	for {
		e.mu.Lock()
		snap := auditTimingSnapshot{preUs: e.preUs, preSet: e.preSet, endUs: e.endUs, endSet: e.endSet, closed: e.closed}
		e.mu.Unlock()
		if snap.closed {
			return snap
		}
		lastSeen = snap
		if time.Now().After(deadline) {
			// 超时：有部分分段就带部分分段（与退役前读侧「按到场键选值」同形）
			return lastSeen
		}
		time.Sleep(auditTimingPollStep)
	}
}

// auditTimingSweepLocked 清扫超龄条目（调用方持 auditTimingMu）。
func auditTimingSweepLocked(now time.Time) {
	for id, e := range auditTimingEntries {
		if now.Sub(e.created) > auditTimingEntryTTL {
			delete(auditTimingEntries, id)
		}
	}
}

// securityTimingIDFromHeaders 从审计事务的请求头提取计时关联键（大小写不敏感；
// coraza 按收到形态收录 canonical 键，容错非常规形态）。缺失返回空串=不注入。
func securityTimingIDFromHeaders(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, securityTimingHeader) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// injectAuditTiming 把计时快照注入审计 JSON 顶层 lb_timing 字段。缺席分段省略
// （preSet/endSet 区分「未记录」与 0——0µs 是合法计时值）。解析失败原样返回
// （畸形行不因注入丢失，摄取侧自行跳过）。在 drain goroutine 内执行，不在
// 请求路径。
func injectAuditTiming(body []byte, snap auditTimingSnapshot) []byte {
	if !snap.hasAny() {
		return body
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	payload := make([]byte, 0, 64)
	payload = append(payload, '{')
	if snap.preSet {
		payload = append(payload, `"pre_us":`...)
		payload = strconv.AppendInt(payload, snap.preUs, 10)
		if snap.endSet {
			payload = append(payload, ',')
		}
	}
	if snap.endSet {
		payload = append(payload, `"end_us":`...)
		payload = strconv.AppendInt(payload, snap.endUs, 10)
	}
	payload = append(payload, '}')
	doc["lb_timing"] = payload
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

// —— 审计快照（plugintypes.AuditLog 的自持拷贝）——
//
// coraza 内部 Log 持有事务变量的 live 引用（request/response headers map、args
// 集合视图），tx.Close 会 reset 全部变量集合并把事务归还 sync.Pool 供下一请求
// 复用——格式化若晚于 Close（drain 侧延迟格式化）读到的是被清空甚至被复写的
// 数据。快照在 Write 时点（Close 之前）拷贝全部 formatter 消费面：字符串在 Go
// 不可变直接持有，headers map/文件列表/消息切片重建隔离。畸形兼容：零值事务
// （无 Transaction 的畸形 AuditLog）走零值快照，格式化输出 zero 对象，不 panic。

// auditSnapshot 实现 plugintypes.AuditLog。字段标签与 coraza 内部 Log 逐一对齐
// （transaction 恒在场、messages omitempty、parts 不入 JSON），注册 formatter
// （内置 JSON=json.Marshal 直出）的输出信封与同步格式化时代逐字段一致。
type auditSnapshot struct {
	Parts_       types.AuditLogParts           `json:"-"`
	Transaction_ auditSnapshotTransaction      `json:"transaction"`
	Messages_    []plugintypes.AuditLogMessage `json:"messages,omitempty"`
}

func (s *auditSnapshot) Parts() types.AuditLogParts { return s.Parts_ }

func (s *auditSnapshot) Transaction() plugintypes.AuditLogTransaction { return &s.Transaction_ }

func (s *auditSnapshot) Messages() []plugintypes.AuditLogMessage { return s.Messages_ }

// auditSnapshotTransaction 实现 plugintypes.AuditLogTransaction。request 恒在场
// （coraza 的 tx.AuditLog 总是分配 Request_），pointer nil=原始缺失。
type auditSnapshotTransaction struct {
	Timestamp_       string                 `json:"timestamp"`
	UnixTimestamp_   int64                  `json:"unix_timestamp"`
	ID_              string                 `json:"id"`
	ClientIP_        string                 `json:"client_ip"`
	ClientPort_      int                    `json:"client_port"`
	HostIP_          string                 `json:"host_ip"`
	HostPort_        int                    `json:"host_port"`
	ServerID_        string                 `json:"server_id"`
	Request_         *auditSnapshotRequest  `json:"request,omitempty"`
	Response_        *auditSnapshotResponse `json:"response,omitempty"`
	Producer_        *auditSnapshotProducer `json:"producer,omitempty"`
	HighestSeverity_ string                 `json:"highest_severity"`
	IsInterrupted_   bool                   `json:"is_interrupted"`
}

func (t *auditSnapshotTransaction) Timestamp() string {
	if t == nil {
		return ""
	}
	return t.Timestamp_
}

func (t *auditSnapshotTransaction) UnixTimestamp() int64 {
	if t == nil {
		return 0
	}
	return t.UnixTimestamp_
}

func (t *auditSnapshotTransaction) ID() string {
	if t == nil {
		return ""
	}
	return t.ID_
}

func (t *auditSnapshotTransaction) ClientIP() string {
	if t == nil {
		return ""
	}
	return t.ClientIP_
}

func (t *auditSnapshotTransaction) ClientPort() int {
	if t == nil {
		return 0
	}
	return t.ClientPort_
}

func (t *auditSnapshotTransaction) HostIP() string {
	if t == nil {
		return ""
	}
	return t.HostIP_
}

func (t *auditSnapshotTransaction) HostPort() int {
	if t == nil {
		return 0
	}
	return t.HostPort_
}

func (t *auditSnapshotTransaction) ServerID() string {
	if t == nil {
		return ""
	}
	return t.ServerID_
}

func (t *auditSnapshotTransaction) HasRequest() bool {
	return t != nil && t.Request_ != nil
}

// Request 缺席时返回 nil 接口（比 coraza 的 typed-nil 更保守：formatter 侧的
// != nil 哨兵在此语义下成立）。
func (t *auditSnapshotTransaction) Request() plugintypes.AuditLogTransactionRequest {
	if t == nil || t.Request_ == nil {
		return nil
	}
	return t.Request_
}

func (t *auditSnapshotTransaction) HasResponse() bool {
	return t != nil && t.Response_ != nil
}

func (t *auditSnapshotTransaction) Response() plugintypes.AuditLogTransactionResponse {
	if t == nil {
		return nil
	}
	return t.Response_
}

func (t *auditSnapshotTransaction) Producer() plugintypes.AuditLogTransactionProducer {
	if t == nil {
		return nil
	}
	return t.Producer_
}

func (t *auditSnapshotTransaction) HighestSeverity() string {
	if t == nil {
		return ""
	}
	return t.HighestSeverity_
}

func (t *auditSnapshotTransaction) IsInterrupted() bool {
	return t != nil && t.IsInterrupted_
}

// auditSnapshotRequest 实现 plugintypes.AuditLogTransactionRequest。嵌入原始请求
// 接口仅为提升 Args()——其返回类型是 coraza 内部 collections.ConcatKeyed，外部
// 包无法命名实现；其余访问器全部走本快照（影子方法遮蔽提升方法）。Args() 仅
// OCSF 格式化器消费（本项目固定 JSON 渲染，JSON 输出经下方标签字段与内置
// 格式化器一致：args 恒 {} 空对象）；其视图随 tx.Close 失效为空读，不产错误数据。
type auditSnapshotRequest struct {
	plugintypes.AuditLogTransactionRequest `json:"-"`
	Method_                                string                                        `json:"method"`
	Protocol_                              string                                        `json:"protocol"`
	URI_                                   string                                        `json:"uri"`
	HTTPVersion_                           string                                        `json:"http_version"`
	Headers_                               map[string][]string                           `json:"headers"`
	Body_                                  string                                        `json:"body"`
	Files_                                 []plugintypes.AuditLogTransactionRequestFiles `json:"files"`
	ArgsStub                               struct{}                                      `json:"args"`
	Length_                                int32                                         `json:"length"`
}

func (r *auditSnapshotRequest) Method() string {
	if r == nil {
		return ""
	}
	return r.Method_
}

func (r *auditSnapshotRequest) Protocol() string {
	if r == nil {
		return ""
	}
	return r.Protocol_
}

func (r *auditSnapshotRequest) URI() string {
	if r == nil {
		return ""
	}
	return r.URI_
}

func (r *auditSnapshotRequest) HTTPVersion() string {
	if r == nil {
		return ""
	}
	return r.HTTPVersion_
}

func (r *auditSnapshotRequest) Headers() map[string][]string {
	if r == nil {
		return nil
	}
	return r.Headers_
}

func (r *auditSnapshotRequest) Body() string {
	if r == nil {
		return ""
	}
	return r.Body_
}

func (r *auditSnapshotRequest) Files() []plugintypes.AuditLogTransactionRequestFiles {
	if r == nil {
		return nil
	}
	return r.Files_
}

func (r *auditSnapshotRequest) Length() int32 {
	if r == nil {
		return 0
	}
	return r.Length_
}

// auditSnapshotFile 实现 plugintypes.AuditLogTransactionRequestFiles（值类型，
// 与 coraza 内部形态一致）。
type auditSnapshotFile struct {
	Name_ string `json:"name"`
	Size_ int64  `json:"size"`
	Mime_ string `json:"mime"`
}

func (f auditSnapshotFile) Name() string { return f.Name_ }

func (f auditSnapshotFile) Size() int64 { return f.Size_ }

func (f auditSnapshotFile) Mime() string { return f.Mime_ }

// auditSnapshotResponse 实现 plugintypes.AuditLogTransactionResponse。
type auditSnapshotResponse struct {
	Protocol_ string              `json:"protocol"`
	Status_   int                 `json:"status"`
	Headers_  map[string][]string `json:"headers"`
	Body_     string              `json:"body"`
}

func (r *auditSnapshotResponse) Protocol() string {
	if r == nil {
		return ""
	}
	return r.Protocol_
}

func (r *auditSnapshotResponse) Status() int {
	if r == nil {
		return 0
	}
	return r.Status_
}

func (r *auditSnapshotResponse) Headers() map[string][]string {
	if r == nil {
		return nil
	}
	return r.Headers_
}

func (r *auditSnapshotResponse) Body() string {
	if r == nil {
		return ""
	}
	return r.Body_
}

// auditSnapshotProducer 实现 plugintypes.AuditLogTransactionProducer。
type auditSnapshotProducer struct {
	Connector_  string   `json:"connector"`
	Version_    string   `json:"version"`
	Server_     string   `json:"server"`
	RuleEngine_ string   `json:"rule_engine"`
	Stopwatch_  string   `json:"stopwatch"`
	Rulesets_   []string `json:"rulesets"`
}

func (p *auditSnapshotProducer) Connector() string {
	if p == nil {
		return ""
	}
	return p.Connector_
}

func (p *auditSnapshotProducer) Version() string {
	if p == nil {
		return ""
	}
	return p.Version_
}

func (p *auditSnapshotProducer) Server() string {
	if p == nil {
		return ""
	}
	return p.Server_
}

func (p *auditSnapshotProducer) RuleEngine() string {
	if p == nil {
		return ""
	}
	return p.RuleEngine_
}

func (p *auditSnapshotProducer) Stopwatch() string {
	if p == nil {
		return ""
	}
	return p.Stopwatch_
}

func (p *auditSnapshotProducer) Rulesets() []string {
	if p == nil {
		return nil
	}
	return p.Rulesets_
}

// 快照类型接口合规钉（编译期）。
var (
	_ plugintypes.AuditLog                        = (*auditSnapshot)(nil)
	_ plugintypes.AuditLogTransaction             = (*auditSnapshotTransaction)(nil)
	_ plugintypes.AuditLogTransactionRequest      = (*auditSnapshotRequest)(nil)
	_ plugintypes.AuditLogTransactionRequestFiles = auditSnapshotFile{}
	_ plugintypes.AuditLogTransactionResponse     = (*auditSnapshotResponse)(nil)
	_ plugintypes.AuditLogTransactionProducer     = (*auditSnapshotProducer)(nil)
)

// snapshotAuditLog 把 live AuditLog 拷贝为自持快照。接口 nil 检查穿透 typed-nil
// （coraza 的 Response()/Producer() 返回 typed-nil 指针——接口非 nil 但底层为
// nil，按缺失处理保持 JSON 信封一致：response/producer omitempty）。
func snapshotAuditLog(al plugintypes.AuditLog) *auditSnapshot {
	s := &auditSnapshot{Parts_: append(types.AuditLogParts(nil), al.Parts()...)}
	if tx := al.Transaction(); !isNilInterface(tx) {
		s.Transaction_ = *snapshotTransaction(tx)
	}
	s.Messages_ = append(s.Messages_, al.Messages()...)
	return s
}

func snapshotTransaction(tx plugintypes.AuditLogTransaction) *auditSnapshotTransaction {
	t := &auditSnapshotTransaction{
		Timestamp_:       tx.Timestamp(),
		UnixTimestamp_:   tx.UnixTimestamp(),
		ID_:              tx.ID(),
		ClientIP_:        tx.ClientIP(),
		ClientPort_:      tx.ClientPort(),
		HostIP_:          tx.HostIP(),
		HostPort_:        tx.HostPort(),
		ServerID_:        tx.ServerID(),
		HighestSeverity_: tx.HighestSeverity(),
		IsInterrupted_:   tx.IsInterrupted(),
	}
	if req := tx.Request(); !isNilInterface(req) {
		r := &auditSnapshotRequest{
			Method_:      req.Method(),
			Protocol_:    req.Protocol(),
			URI_:         req.URI(),
			HTTPVersion_: req.HTTPVersion(),
			Body_:        req.Body(),
			Length_:      req.Length(),
			ArgsStub:     struct{}{},
		}
		if hs := req.Headers(); hs != nil {
			r.Headers_ = make(map[string][]string, len(hs))
			for k, v := range hs {
				r.Headers_[k] = append([]string(nil), v...)
			}
		}
		for _, f := range req.Files() {
			r.Files_ = append(r.Files_, auditSnapshotFile{Name_: f.Name(), Size_: f.Size(), Mime_: f.Mime()})
		}
		r.AuditLogTransactionRequest = req
		t.Request_ = r
	}
	if resp := tx.Response(); !isNilInterface(resp) {
		q := &auditSnapshotResponse{
			Protocol_: resp.Protocol(),
			Status_:   resp.Status(),
			Body_:     resp.Body(),
		}
		if hs := resp.Headers(); hs != nil {
			q.Headers_ = make(map[string][]string, len(hs))
			for k, v := range hs {
				q.Headers_[k] = append([]string(nil), v...)
			}
		}
		t.Response_ = q
	}
	if prod := tx.Producer(); !isNilInterface(prod) {
		p := &auditSnapshotProducer{
			Connector_:  prod.Connector(),
			Version_:    prod.Version(),
			Server_:     prod.Server(),
			RuleEngine_: prod.RuleEngine(),
			Stopwatch_:  prod.Stopwatch(),
		}
		if rs := prod.Rulesets(); rs != nil {
			p.Rulesets_ = append([]string(nil), rs...)
		}
		t.Producer_ = p
	}
	return t
}

// isNilInterface 判定接口值为 nil 或持 typed-nil 指针。
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	}
	return false
}

// —— 审计写插件与共享管线 ——

// lbAuditItem 是队列元素：审计快照 + 注册格式化器 + 计时关联键（空=无计时）。
// 格式化已移出请求路径——Write 只构建快照，drain/同步回退侧用随行 formatter
// 格式化（同一 target 的 writer 同构，但保守以 Write 时点的 formatter 为准）。
type lbAuditItem struct {
	snap      *auditSnapshot
	formatter plugintypes.AuditLogFormatter
	tid       string
}

// auditPipeline 是按目标路径共享的落盘管线（单 drain goroutine + 单 fd +
// bufio）。多个 coraza WAF 实例（预检+各策略引擎，各自 NewWAF→独立 writer
// 实例）追加同一审计文件时共享一条管线，避免 reload 池换血累积 goroutine/fd。
type auditPipeline struct {
	// mu 保护生命周期字段（queue/done/refs/closed）：enqueue 全程持 RLock 发送
	// （发送完成前 release 的 Lock 排队等待），release 持 Lock 置 queue=nil 并
	// close——close(q) 与发送严格定序，不会 send-on-closed。
	mu     sync.RWMutex
	target string
	queue  chan lbAuditItem
	done   chan struct{}
	refs   int
	closed bool
	// ioMu 保护 fd/bufio（仅 drain goroutine 触碰，独立于 mu 防止请求路径
	// enqueue 的 RLock 与刷盘互斥）。target/mode 创建后只读，无锁读。
	ioMu sync.Mutex
	fd   *os.File
	bw   *bufio.Writer
	mode os.FileMode
	// ioErrMu 保护 IO 错误节流状态（drain 与其关闭路径并发可见）。
	ioErrMu      sync.Mutex
	lastIOErrLog time.Time
	ioErrCount   int
}

// auditIOLogf 审计落盘错误日志缝（测试注入；缺省 caddy.Log）。
var auditIOLogf = func(format string, args ...any) {
	caddy.Log().Named("auditwriter").Sugar().Errorf(format, args...)
}

// reportIOError 记录落盘 IO 错误（U14-04）：首次立即记录，其后每分钟至多
// 一条（携带被抑制计数），保证「静默丢行」不可能。错误不再只是被丢弃的
// error 返回值——drain 侧旧实现 `_, _ = p.bw.Write(...)` 完全不可观测。
func (p *auditPipeline) reportIOError(op string, err error) {
	if err == nil {
		return
	}
	p.ioErrMu.Lock()
	now := time.Now()
	p.ioErrCount++
	suppressed := p.ioErrCount - 1
	logNow := p.lastIOErrLog.IsZero() || now.Sub(p.lastIOErrLog) >= time.Minute
	if logNow {
		p.lastIOErrLog = now
		p.ioErrCount = 0
	}
	p.ioErrMu.Unlock()
	if logNow {
		auditIOLogf("audit writer: %s failed for %s (suppressed %d since last report): %v", op, p.target, suppressed, err)
	}
}

// reopenLocked 丢弃当前 bufio/fd 并重建（O_APPEND 兼容 copytruncate）。
func (p *auditPipeline) reopenLocked() {
	if p.bw != nil {
		_ = p.bw.Flush()
		p.bw = nil
	}
	if p.fd != nil {
		_ = p.fd.Close()
		p.fd = nil
	}
	fd, err := os.OpenFile(p.target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, p.mode)
	if err != nil {
		p.reportIOError("reopen", err)
		return
	}
	p.fd = fd
	p.bw = bufio.NewWriterSize(fd, 64*1024)
}

// appendLine 写入一行并处理错误（U14-04）：粘性写错误先记录、再重建 fd，
// 后续行继续落盘；调用方持 ioMu。
func (p *auditPipeline) appendLine(body []byte) {
	if p.bw == nil {
		p.reopenLocked()
		if p.bw == nil {
			return
		}
	}
	if _, err := p.bw.Write(body); err != nil {
		p.reportIOError("write", err)
		p.reopenLocked()
		return
	}
	if _, err := p.bw.WriteString("\n"); err != nil {
		p.reportIOError("write", err)
		p.reopenLocked()
		return
	}
	if p.bw.Buffered() >= auditFlushThreshold {
		p.flushLocked()
	}
}

// flushLocked 刷盘并处理错误（U14-04）。调用方持 ioMu。
func (p *auditPipeline) flushLocked() {
	if p.bw == nil {
		return
	}
	if err := p.bw.Flush(); err != nil {
		p.reportIOError("flush", err)
		p.reopenLocked()
	}
}

var (
	auditPipelinesMu sync.Mutex
	auditPipelines   = map[string]*auditPipeline{}
)

// acquireAuditPipeline 取目标路径的共享管线（不存在则创建：打开 fd + 启动
// drain）。fd 打开失败返回错误——coraza NewWAF 会把 Init 错误上抛为配置拒绝
// （/load fail-fast，与退役前 serial writer 同语义）。
func acquireAuditPipeline(target string, mode os.FileMode) (*auditPipeline, error) {
	auditPipelinesMu.Lock()
	defer auditPipelinesMu.Unlock()
	if p, ok := auditPipelines[target]; ok && !p.isClosed() {
		p.mu.Lock()
		p.refs++
		p.mu.Unlock()
		return p, nil
	}
	p := &auditPipeline{
		target: target,
		mode:   mode,
		queue:  make(chan lbAuditItem, auditQueueSize),
		done:   make(chan struct{}),
	}
	if err := p.openFile(mode); err != nil {
		return nil, err
	}
	p.refs = 1
	auditPipelines[target] = p
	go p.drain()
	return p, nil
}

func (p *auditPipeline) isClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// openFile 打开目标文件（O_APPEND——copytruncate 轮转下 fd 恒有效）。
func (p *auditPipeline) openFile(mode os.FileMode) error {
	fd, err := os.OpenFile(p.target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, mode)
	if err != nil {
		return err
	}
	p.ioMu.Lock()
	p.fd = fd
	p.bw = bufio.NewWriterSize(fd, 64*1024)
	p.ioMu.Unlock()
	return nil
}

// enqueue 阻塞式入队（零丢弃）：队列满时等待 drain 消化——退化价=退役前
// serial 同步写。发送持 RLock 全程（release 的 Lock 排队等到发送完成），与
// release 的 close(q) 定序互斥，不会 send-on-closed。管线已关（refs 归零后的
// 重载窗口在途写入，q==nil）或 done 已闭时回退同步直写——同样零丢弃。
func (p *auditPipeline) enqueue(item lbAuditItem) error {
	p.mu.RLock()
	q, done := p.queue, p.done
	if q == nil {
		p.mu.RUnlock()
		return p.syncWrite(item)
	}
	// done 只在 drain 退出（晚于 release 的 Lock→close(q)）时闭合，而 close(q)
	// 需要写锁、被本 RLock 排除——done 分支为防御性保留（未来重构若放宽锁序，
	// 此处仍走零丢弃回退而非静默丢行）。
	select {
	case q <- item:
		p.mu.RUnlock()
		return nil
	case <-done:
		p.mu.RUnlock()
		return p.syncWrite(item)
	}
}

// syncWrite 是管线关闭后（重载窗口在途写入）的零丢弃回退：短生命周期 fd
// O_APPEND 直写该行。与 drain 残余 bufio 批量写按行粒度交错——摄取按行解码+
// transaction_id 幂等去重，乱序无影响。计时注入同步完成（短等终态：重载窗口
// 内 blocked_counter 紧随 ProcessLogging，µs 级置位；上限只兜底异常形态，避免
// 请求路径长等）。
func (p *auditPipeline) syncWrite(item lbAuditItem) error {
	if item.snap == nil || item.formatter == nil {
		return nil
	}
	body, err := item.formatter.Format(item.snap)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	if item.tid != "" {
		snap := auditTimingWait(item.tid, auditSyncTimingWaitLimit)
		body = injectAuditTiming(body, snap)
	}
	fd, err := os.OpenFile(p.target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, p.mode)
	if err != nil {
		return err
	}
	defer fd.Close()
	_, err = fd.Write(append(body, '\n'))
	return err
}

// release 递减引用；最后一个引用释放时关闭队列——drain 排空余量、刷盘、关
// fd 后退出（close 与 enqueue 的互斥见 mu 注释）。
func (p *auditPipeline) release() {
	waitDrain := false
	auditPipelinesMu.Lock()
	p.mu.Lock()
	if p.refs > 0 {
		p.refs--
	}
	if p.refs == 0 && !p.closed {
		p.closed = true
		q := p.queue
		p.queue = nil
		waitDrain = true
		delete(auditPipelines, p.target)
		close(q)
	}
	p.mu.Unlock()
	auditPipelinesMu.Unlock()
	// U14-10（第 78 轮）：等待 drain 退出（fd 关闭确认）不得持注册表锁——
	// 旧实现持 auditPipelinesMu 阻塞在 <-p.done，drain 排空期间所有
	// acquireAuditPipeline（新 WAF/重载）被卡住。删除+close 已在锁内完成，
	// 新的同路径管线可并发创建（各自独立 fd，O_APPEND 追加安全）。
	if waitDrain {
		<-p.done
	}
}

// drain 专职落盘 goroutine：注入 timing → bufio 批量写 → 阈值/周期双触发刷盘。
// 队列关闭后排空余量再退出（零丢弃语义覆盖 teardown 路径）。队列句柄在启动时
// 捕获一次——release 会把 p.queue 置 nil（防后续 enqueue），select 若每轮重读
// 字段会读到 nil channel（永不完全就绪的 case），ticker 分支将使本 goroutine
// 永不退出（实测 livelock）。
func (p *auditPipeline) drain() {
	defer close(p.done)
	p.mu.RLock()
	q := p.queue
	p.mu.RUnlock()
	if q == nil {
		return
	}
	ticker := time.NewTicker(auditFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case item, ok := <-q:
			if !ok {
				p.flushPending()
				p.closeFile()
				return
			}
			p.process(item)
		case <-ticker.C:
			p.flushPending()
		}
	}
}

// process 处理单条审计行：注册 formatter 格式化快照（请求路径之外）→ 限时等待
// 计时终态 → 注入 → bufio 写（阈值刷盘）。计时等待在请求路径之外（见文件头
// 时序契约注释）。格式化失败/空输出跳过该行（与旧同步链 Write 返回错误同效，
// coraza 已在写错误点记日志）。
func (p *auditPipeline) process(item lbAuditItem) {
	if item.snap == nil || item.formatter == nil {
		return
	}
	body, err := item.formatter.Format(item.snap)
	if err != nil {
		// 单行格式化失败只跳过该行，不阻断后续（错误可见化：旧实现静默丢弃）。
		p.reportIOError("format", err)
		return
	}
	if len(body) == 0 {
		return
	}
	if item.tid != "" {
		snap := auditTimingWait(item.tid, auditTimingWaitLimit)
		body = injectAuditTiming(body, snap)
	}
	p.ioMu.Lock()
	p.appendLine(body)
	p.ioMu.Unlock()
}

func (p *auditPipeline) flushPending() {
	p.ioMu.Lock()
	if p.bw != nil && p.bw.Buffered() > 0 {
		p.flushLocked()
	}
	p.ioMu.Unlock()
}

func (p *auditPipeline) closeFile() {
	p.ioMu.Lock()
	if p.bw != nil {
		p.flushLocked()
		p.bw = nil
	}
	if p.fd != nil {
		if err := p.fd.Close(); err != nil {
			p.reportIOError("close", err)
		}
		p.fd = nil
	}
	p.ioMu.Unlock()
}

// lbAuditWriter 是 coraza 审计写插件实例（每个 coraza WAF 一个；多实例共享
// 按路径的落盘管线）。Write 只构建审计快照入队（formatter.Format 已移出请求
// 路径——黑名单预检计时窗内只剩快照拷贝，memcpy 级），格式化/计时等待/落盘
// 全部后置到 drain（或管线关闭时的同步回退直写）。
type lbAuditWriter struct {
	formatter plugintypes.AuditLogFormatter
	pipeline  *auditPipeline
	// failed 标记 Init 失败（fd 打不开）：后续 Write 静默 no-op——与 coraza
	// serial writer Init 失败后 Write 短路同形态（coraza 已在 Init 错误点
	// 上抛/记日志，配置加载被拒）。
	failed bool
}

func (w *lbAuditWriter) Init(c plugintypes.AuditLogConfig) error {
	w.formatter = c.Formatter
	if c.Target == "" {
		return nil
	}
	p, err := acquireAuditPipeline(c.Target, c.FileMode)
	if err != nil {
		w.failed = true
		return err
	}
	w.pipeline = p
	return nil
}

func (w *lbAuditWriter) Write(al plugintypes.AuditLog) error {
	if w.failed || w.pipeline == nil || w.formatter == nil || al == nil {
		return nil
	}
	tid := ""
	if al.Transaction() != nil && al.Transaction().HasRequest() {
		tid = securityTimingIDFromHeaders(al.Transaction().Request().Headers())
	}
	return w.pipeline.enqueue(lbAuditItem{snap: snapshotAuditLog(al), formatter: w.formatter, tid: tid})
}

func (w *lbAuditWriter) Close() error {
	if w.pipeline != nil {
		w.pipeline.release()
		w.pipeline = nil
	}
	return nil
}
