package lbhuman

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// 人机验证事件上报（2026-11-12 用户裁定：挑战/通过/失败入 security_events）：
// 异步 UDS 投递（复用安全事件 IPC socket 契约），独立端点
// /security-events/ingest-human；失败静默丢弃（监控事件不阻塞请求路径）。

const (
	humanEventSocketEnv = "LB_SECURITY_EVENTS_IPC_SOCKET"
	humanEventIngestURI = "/security-events/ingest-human"
	// humanEventQueueCap 事件缓冲队列容量：单 worker 串行投递（UDS 2s 超时），
	// 队列满即丢弃并计数——逐事件 goroutine 的无界扇出已退役。
	humanEventQueueCap = 1024
)

type humanEvent struct {
	ruleID string
	ip     string
	method string
	uri    string
	ua     string
	kind   string
	done   chan struct{} // 非 nil=排空探针：worker 处理到该事件即关闭
}

type humanEventPoster struct {
	mu     sync.Mutex
	client *http.Client
	url    string // 投递地址（默认 UDS；测试可注入本地端点）
}

var poster = &humanEventPoster{}

// humanEventQueue 缓冲投递队列；humanEventDropped 队列满丢弃计数（可观测）。
var (
	humanEventQueue   = make(chan humanEvent, humanEventQueueCap)
	humanEventDropped atomic.Int64
	humanEventWorker  sync.Once
)

func (p *humanEventPoster) initClient() {
	if p.client != nil {
		return
	}
	socket := os.Getenv(humanEventSocketEnv)
	if socket == "" {
		socket = "/app/data/security-events.sock"
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
}

// shouldReport 挑战发放/通过/失败全部逐请求上报（2026-11-13 用户裁定：
// 限流日志≠限流请求，发放限流无实际防护意义，取消后事件日志与实时运行态
// 口径一致）。真正的拦截交给自动封禁（挑战发放/失败可计入统计口径）。
func (p *humanEventPoster) shouldReport(ip, kind string, now time.Time) bool {
	return true
}

// reportHumanEvent 异步上报（非阻塞：投递到缓冲 channel，单 worker 串行发送；
// 队列满即丢弃计数，失败静默——监控事件不阻塞请求路径）。
func reportHumanEvent(ruleID, ip, method, uri, ua, kind string) {
	humanEventWorker.Do(func() { go humanEventWorkerLoop() })
	select {
	case humanEventQueue <- humanEvent{ruleID: ruleID, ip: ip, method: method, uri: uri, ua: ua, kind: kind}:
	default:
		humanEventDropped.Add(1)
	}
}

func humanEventWorkerLoop() {
	for ev := range humanEventQueue {
		if ev.done != nil {
			close(ev.done) // 排空探针：此前入队事件均已处理完毕
			continue
		}
		poster.deliver(ev)
	}
}

func (p *humanEventPoster) deliver(ev humanEvent) {
	defer func() { _ = recover() }()
	if !p.shouldReport(ev.ip, ev.kind, time.Now()) {
		return
	}
	p.mu.Lock()
	p.initClient()
	client := p.client
	target := p.url
	p.mu.Unlock()
	if client == nil {
		return
	}
	payload := []map[string]any{{
		"ts": time.Now().UnixMilli(), "rule_id": ev.ruleID, "client_ip": ev.ip,
		"method": ev.method, "uri": ev.uri, "ua": ev.ua, "kind": ev.kind,
	}}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	resp, err := client.Post(target, "application/json", bytes.NewReader(raw))
	if err == nil {
		resp.Body.Close()
	}
}

// drainHumanEventsForTest 等待队列排空（测试等待语义）：入队一个排空探针，
// worker 处理到它即证明此前全部入队事件已处理完毕。
func drainHumanEventsForTest(timeout time.Duration) bool {
	humanEventWorker.Do(func() { go humanEventWorkerLoop() })
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
