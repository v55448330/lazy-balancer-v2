package lbhuman

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 人机验证事件上报（2026-11-12 用户裁定：挑战/通过/失败入 security_events）：
// 异步 UDS 投递（复用安全事件 IPC socket 契约），独立端点
// /security-events/ingest-human；失败丢弃但**计数可观测**（events_deliver_failed
// 经 stats 端点下发——监控事件不阻塞请求路径，丢失量必须可对账；无重试/spool，
// 保持请求路径零阻塞裁定）。

const (
	humanEventSocketEnv = "LB_SECURITY_EVENTS_IPC_SOCKET"
	humanEventIngestURI = "/security-events/ingest-human"
	// humanEventQueueCap 事件缓冲队列容量：单 worker 串行投递（UDS 2s 超时），
	// 队列满即丢弃并计数——逐事件 goroutine 的无界扇出已退役。
	humanEventQueueCap = 1024
)

// humanEvent 人机事件行。**契约：人机不携带 UA**（用户裁定）：
// 摄取侧 handleIngestHuman 解析 ua 但从不落库（security_events 无
// UA 列），端到端采集即丢——产生侧停止采集，不再发射 ua 键。取证上下文
// 与 WAF 的不对称是有意取舍（落库方案影响面大不取）；cookie UA 绑定/CC
// UA 指纹/实时会话 UA 展示各有独立消费面，不经本事件通道。
type humanEvent struct {
	ruleID string
	ip     string
	method string
	uri    string
	kind   string
	reason string        // CC 触发原因（session_anomaly/rps_spike/4xx_ratio；非 CC 触发空）
	ts     int64         // 发生（入队）时刻 unix 毫秒——投递时刻会随队列积压漂移
	done   chan struct{} // 非 nil=排空探针：worker 处理到该事件即关闭
}

type humanEventPoster struct {
	mu       sync.Mutex
	client   *http.Client
	url      string // 投递地址（默认 UDS；测试可注入本地端点）
	disabled bool   // env 显式空串/空白=关闭上报（不建客户端、不拨号）
}

var poster = &humanEventPoster{}

// humanEventQueue 缓冲投递队列；humanEventDropped 队列满丢弃计数、
// humanEventDeliverFailed 投递失败丢弃计数（连接拒绝/非 204/序列化失败/
// panic 隔离——都是可观测对账源，经 /lb/human/stats 下发）。
var (
	humanEventQueue         = make(chan humanEvent, humanEventQueueCap)
	humanEventDropped       atomic.Int64
	humanEventDeliverFailed atomic.Int64
	humanEventShutdownLost  atomic.Int64
	// worker 可停止化（测试隔离）：sync.Once 常驻 goroutine 不可停，shuffle
	// 顺序下前序排空测试启动的 worker 会与停机收尾钉测竞争消费队列。mutex+
	// stop chan 支持测试停 worker 隔离 FlushHumanEvents；生产侧首次上报启动
	// 单 worker 串行投递（进程级单例），Cleanup/FlushHumanEvents 经
	// stopHumanEventWorker 停 worker 后排空，后续上报自动重启。
	humanEventWorkerMu   sync.Mutex
	humanEventWorkerStop chan struct{}
)

func (p *humanEventPoster) initClient() {
	if p.client != nil {
		return
	}
	// socket env 契约与 caddygeoip/caddyl4sec 同口径：未设置=容器默认 socket；
	// 显式空串/纯空白=关闭上报（不拨号）；有效值 TrimSpace。
	// disabled 每次重解析（不粘滞）：client 被重置后按当前 env 重新判定。
	socket := "/app/data/security-events.sock"
	if v, ok := os.LookupEnv(humanEventSocketEnv); ok {
		socket = strings.TrimSpace(v)
	}
	p.disabled = socket == ""
	if p.disabled {
		return
	}
	p.client = &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socket, 2*time.Second)
			},
		},
	}
	p.url = "http://unix" + humanEventIngestURI
}

// initClientWithURL 测试注入投递地址（复用同一 worker/队列语义）。
func (p *humanEventPoster) initClientWithURL(rawURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = &http.Client{Timeout: 2 * time.Second}
	p.url = rawURL
	p.disabled = false
}

// shouldReport 挑战发放/通过/失败全部逐请求上报（2026-11-13 用户裁定：
// 限流日志≠限流请求，发放限流无实际防护意义，取消后事件日志与实时运行态
// 口径一致）。真正的拦截交给自动封禁（挑战发放/失败可计入统计口径）。
func (p *humanEventPoster) shouldReport(ip, kind string, now time.Time) bool {
	return true
}

// ccTriggerReasons CC 触发原因暂存（ruleID|normalizeIP → reason）：触发点
// （ServeHTTP CC 判定）与发放事件上报点（serveChallengeForRequest 族）分离，
// 按键暂存-一次性消费贯通原因，不改 reportHumanEvent 签名（13 调用点零扰动）。
// 同键并发触发按后值覆盖（同窗口同原因，语义无损）；消费即删不滞留。
// 消费按 kind 门控（takeCCTriggerReason）：仅发放族消费，防跨 kind 窃取。
var ccTriggerReasons sync.Map

// stashCCTriggerReason 触发点暂存原因（仅 CC 判定触发时调用）。
func stashCCTriggerReason(ruleID, ip, reason string) {
	ccTriggerReasons.Store(ruleID+"|"+normalizeIP(ip), reason)
}

// takeCCTriggerReason 发放上报点消费原因（一次性；无暂存返回空串）。
// 仅发放族 kind 消费：pass/fail 是验证流程事件，不得跨 kind 窃取待发放
// 挑战的原因；rate_reject 即消但不携带（blocked 口径不做挑战归因，
// 防滞留原因污染后续挑战归因）。
func takeCCTriggerReason(ruleID, ip, kind string) string {
	if kind != "challenge" && kind != "rate_reject" {
		return ""
	}
	if v, ok := ccTriggerReasons.LoadAndDelete(ruleID + "|" + normalizeIP(ip)); ok {
		if kind == "challenge" {
			return v.(string)
		}
	}
	return ""
}

// reportHumanEvent 异步上报（非阻塞：投递到缓冲 channel，单 worker 串行发送；
// 队列满即丢弃计数，投递失败计数——监控事件不阻塞请求路径）。
// ts 在入队时刻定格：事件时间戳=发生时刻，不随队列积压/投递阻塞漂移。
// 不采集 UA（契约见 humanEvent 注释：人机不携带 UA，摄取侧不落库）。
func reportHumanEvent(ruleID, ip, method, uri, kind string) {
	startHumanEventWorker()
	select {
	case humanEventQueue <- humanEvent{ruleID: ruleID, ip: ip, method: method, uri: uri, kind: kind, reason: takeCCTriggerReason(ruleID, ip, kind), ts: time.Now().UnixMilli()}:
	default:
		humanEventDropped.Add(1)
	}
}

// startHumanEventWorker 幂等启动单 worker（mutex 守护，stop chan 标记运行态）。
// 每次启动 make 新鲜退出信号并与 stop chan 一同在锁内登记、作为参数交给本代
// worker——停机收尾停 worker 后后续上报重启时信号必须新鲜，且各代互不串用。
func startHumanEventWorker() {
	humanEventWorkerMu.Lock()
	defer humanEventWorkerMu.Unlock()
	if humanEventWorkerStop != nil {
		return // 已在运行
	}
	stop := make(chan struct{})
	exited := make(chan struct{})
	humanEventWorkerStop = stop
	humanEventWorkerExited = exited
	go humanEventWorkerLoop(stop, exited)
}

// humanEventWorkerExited 当前代 worker 的退出信号（start 锁内 make 登记，
// worker goroutine 退出时 defer close 传入的同一 chan）。stopHumanEventWorker
// 必须在锁内把它与 stop chan 一同捕获为局部引用再锁外等待——若锁外读包级 var，
// 并发 start 会在「置 nil 释放锁」与「等待」之间替换它，stop 死等新代信号。
// 等待退出确保「已取出未投递」的在途事件落定（deliver 的失败计数先于收尾排空
// 完成），shutdown_lost 只计真正滞留队列的尾部——对账不重不漏。
var humanEventWorkerExited = make(chan struct{})

// humanEventStopWaitHook 测试缝（生产恒 nil，不参与任何生产路径；与
// timeNow/initClientWithURL 同款测试注入约定）：stop 释放锁后、close(stop)/
// 等待退出信号前调用——正是并发 start 可插入替换退出信号的窗口。确定性交错
// 钉测在此注入并发 start，复现「锁外等待被替换的退出信号」死等形态。
var humanEventStopWaitHook func()

func humanEventWorkerLoop(stop, exited chan struct{}) {
	defer close(exited)
	for {
		select {
		case <-stop:
			return
		case ev := <-humanEventQueue:
			if ev.done != nil {
				close(ev.done) // 排空探针：此前入队事件均已处理完毕
				continue
			}
			poster.deliver(ev)
		}
	}
}

// stopHumanEventWorker 停止常驻 worker 并等待其退出（幂等；无 worker=直接返回）。
// 停机收尾与测试隔离共用：先停消费再排空，杜绝 worker 与收尾竞争消费队列导致
// shutdown_lost 计数失真。stop+exited 在锁内一并捕获为局部引用，锁外 close(stop)
// 后等待的是**本代** exited——并发 start 重启新 worker 不影响本次等待。退出信号
// 由 start 每次 make 新鲜值，stop 不复位（复位冗余且是「等待被替换信号」竞态源）。
func stopHumanEventWorker() {
	humanEventWorkerMu.Lock()
	stop := humanEventWorkerStop
	exited := humanEventWorkerExited
	humanEventWorkerStop = nil
	humanEventWorkerMu.Unlock()
	if humanEventStopWaitHook != nil {
		humanEventStopWaitHook()
	}
	if stop != nil {
		close(stop)
		<-exited
	}
}

// FlushHumanEvents 停机收尾：把队列内未投递的尾部事件计入 shutdown_lost
// 对账源（人机通道无 spool/重试是用户裁定，但丢失量必须可对账——此前停机
// 尾部静默蒸发不入任何计数，与「丢弃必须可观测」契约张力）。Caddy 模块
// Cleanup（reload/优雅停机）调用；幂等（排空后队列空，重复调用计 0）。
//
// 先停常驻 worker 再独占排空：worker 活着时并发消费队列，会把尾部事件绕进
// deliver_failed（投递失败计数）而非 shutdown_lost——reload 竞态下对账计数
// 失真。停 worker 后后续上报经 reportHumanEvent 重启 worker（生产语义不变）。
func FlushHumanEvents() {
	stopHumanEventWorker()
	for {
		select {
		case ev := <-humanEventQueue:
			if ev.done == nil {
				humanEventShutdownLost.Add(1)
			}
		default:
			return
		}
	}
}

func (p *humanEventPoster) deliver(ev humanEvent) {
	defer func() {
		if recover() != nil {
			// panic 隔离同样计入丢失对账：recover 吞掉异常不等于事件送达，
			// 零计数会让监控盲区（events_deliver_failed 是唯一丢失量观测源）。
			humanEventDeliverFailed.Add(1)
		}
	}()
	if !p.shouldReport(ev.ip, ev.kind, time.Now()) {
		return
	}
	p.mu.Lock()
	p.initClient()
	client := p.client
	target := p.url
	disabled := p.disabled
	p.mu.Unlock()
	if disabled {
		return // env 显式关闭：不拨号不计失败（关闭≠投递故障）
	}
	if client == nil {
		humanEventDeliverFailed.Add(1)
		return
	}
	// 契约：人机不携带 UA（不发射 ua 键；摄取侧 humanEventRow.UA 解析
	// 兼容旧版写侧，落库本就不消费——见 handleIngestHuman）。
	entry := map[string]any{
		"ts": ev.ts, "rule_id": ev.ruleID, "client_ip": ev.ip,
		"method": ev.method, "uri": ev.uri, "kind": ev.kind,
	}
	if ev.reason != "" {
		entry["reason"] = ev.reason
	}
	payload := []map[string]any{entry}
	raw, err := json.Marshal(payload)
	if err != nil {
		humanEventDeliverFailed.Add(1)
		return
	}
	resp, err := client.Post(target, "application/json", bytes.NewReader(raw))
	if err != nil {
		humanEventDeliverFailed.Add(1)
		return
	}
	defer resp.Body.Close()
	// 跨进程契约（与 L4/审计写侧同口径）：只有 204 代表本批 DB commit 完成；
	// 其余状态码（含 2xx 非 204）=入库未完成，按投递失败计数。
	if resp.StatusCode != http.StatusNoContent {
		humanEventDeliverFailed.Add(1)
	}
}

// drainHumanEventsForTest 等待队列排空（测试等待语义）：入队一个排空探针，
// worker 处理到它即证明此前全部入队事件已处理完毕。
func drainHumanEventsForTest(timeout time.Duration) bool {
	startHumanEventWorker()
	done := make(chan struct{})
	select {
	case humanEventQueue <- humanEvent{done: done}:
	case <-time.After(timeout):
		return false
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// stopHumanEventWorkerForTest 停止常驻 worker 并排空队列残留（测试隔离）：
// 停机收尾钉测须独占消费队列计 shutdown_lost，前序排空测试启动的 worker
// 不得竞争。停 worker 后清空队列残留事件，还原 clean 态（生产不调用）。
func stopHumanEventWorkerForTest() {
	stopHumanEventWorker()
	for {
		select {
		case <-humanEventQueue:
		default:
			return
		}
	}
}
