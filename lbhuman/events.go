package lbhuman

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// 人机验证事件上报（2026-11-12 用户裁定：挑战/通过/失败入 security_events）：
// 异步 UDS 投递（复用安全事件 IPC socket 契约），独立端点
// /security-events/ingest-human；失败静默丢弃（监控事件不阻塞请求路径）。
// 每 IP 每分钟最多 1 条（防事件风暴打爆 metrics 库）。

const (
	humanEventSocketEnv = "LB_SECURITY_EVENTS_IPC_SOCKET"
	humanEventIngestURI = "/security-events/ingest-human"
)

type humanEventPoster struct {
	mu     sync.Mutex
	client *http.Client
}

var poster = &humanEventPoster{}

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
}

// shouldReport 挑战发放/通过/失败全部逐请求上报（2026-11-13 用户裁定：
// 限流日志≠限流请求，发放限流无实际防护意义，取消后事件日志与实时运行态
// 口径一致）。真正的拦截交给自动封禁（挑战发放/失败可计入统计口径）。
func (p *humanEventPoster) shouldReport(ip, kind string, now time.Time) bool {
	return true
}

// report 异步上报（非阻塞：投递到 channel，独立 goroutine 发送）。
func reportHumanEvent(ruleID, ip, method, uri, ua, kind string) {
	go func() {
		defer func() { _ = recover() }()
		if !poster.shouldReport(ip, kind, time.Now()) {
			return
		}
		poster.mu.Lock()
		poster.initClient()
		client := poster.client
		poster.mu.Unlock()
		if client == nil {
			return
		}
		payload := []map[string]any{{
			"ts": time.Now().UnixMilli(), "rule_id": ruleID, "client_ip": ip,
			"method": method, "uri": uri, "ua": ua, "kind": kind,
		}}
		raw, err := json.Marshal(payload)
		if err != nil {
			return
		}
		resp, err := client.Post("http://unix"+humanEventIngestURI, "application/json", bytes.NewReader(raw))
		if err == nil {
			resp.Body.Close()
		}
	}()
}
