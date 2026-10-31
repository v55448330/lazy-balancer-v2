package caddyl4sec

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

// nextCapture 记录链上后续 handler 是否被调用（透传语义断言）。
type nextCapture struct{ called bool }

func (n *nextCapture) Handle(_ *layer4.Connection) error { n.called = true; return nil }

func newHandlerForTest(t *testing.T, h *L4SecHandler) *L4SecHandler {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	ctx.Logger()
	h.logger = ctx.Logger()
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	return h
}

// TestL4SecModuleID 锁定契约 C2 模块 ID。
func TestL4SecModuleID(t *testing.T) {
	h := &L4SecHandler{}
	if id := h.CaddyModule().ID; id != "layer4.handlers.lb_l4_sec" {
		t.Fatalf("handler module ID = %q, want layer4.handlers.lb_l4_sec（契约 C2）", id)
	}
	var _ layer4.NextHandler = h
}

// TestL4SecProvisionValidation 畸形 config 显性报错（reason 形态与
// allow_sample 形态互斥；geoip policy 段位越界拒绝）。合法形态会惰性启动
// 投递管线——IPC 关闭形态下不建 spool、无落盘面。
func TestL4SecProvisionValidation(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	cases := []struct {
		name    string
		h       L4SecHandler
		wantErr bool
	}{
		{"valid deny", L4SecHandler{RuleCaddyID: "r1", Reason: "deny", PolicyID: 3}, false},
		{"valid blacklist", L4SecHandler{RuleCaddyID: "r1", Reason: "blacklist", PolicyID: 3}, false},
		{"valid allow", L4SecHandler{RuleCaddyID: "r1", Reason: "allow", PolicyID: 3}, false},
		{"valid geoip", L4SecHandler{RuleCaddyID: "r1", Reason: "geoip", PolicyID: 3}, false},
		{"geoip policy max", L4SecHandler{RuleCaddyID: "r1", Reason: "geoip", PolicyID: 9999}, false},
		{"valid allow_sample", L4SecHandler{RuleCaddyID: "r1", Mode: "allow_sample"}, false},
		{"valid trust_detect merged", L4SecHandler{RuleCaddyID: "r1", Reason: "trust_detect"}, false},
		{"valid trust_detect policy", L4SecHandler{RuleCaddyID: "r1", Reason: "trust_detect", PolicyID: 7}, false},
		{"missing rule id", L4SecHandler{Reason: "deny", PolicyID: 3}, true},
		{"bad reason", L4SecHandler{RuleCaddyID: "r1", Reason: "block", PolicyID: 3}, true},
		// 合并段 policy_id=0 合法（契约偏差裁定：渲染侧多策略并集无单策略归因）。
		{"deny merged segment policy 0", L4SecHandler{RuleCaddyID: "r1", Reason: "deny"}, false},
		{"deny policy negative", L4SecHandler{RuleCaddyID: "r1", Reason: "deny", PolicyID: -1}, true},
		{"trust_detect policy negative", L4SecHandler{RuleCaddyID: "r1", Reason: "trust_detect", PolicyID: -1}, true},
		{"geoip without policy", L4SecHandler{RuleCaddyID: "r1", Reason: "geoip"}, true},
		{"geoip policy overflows segment", L4SecHandler{RuleCaddyID: "r1", Reason: "geoip", PolicyID: 10000}, true},
		{"deny mixed with allow_sample", L4SecHandler{RuleCaddyID: "r1", Reason: "deny", PolicyID: 3, Mode: "allow_sample"}, true},
		{"allow_sample unknown mode", L4SecHandler{RuleCaddyID: "r1", Mode: "sample_all"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.h
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			err := h.Provision(ctx)
			if tc.wantErr && err == nil {
				t.Fatalf("Provision() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Provision() = %v, want nil", err)
			}
		})
	}
}

// TestEventLineShape 契约 C1 合成行逐字段断言 + 负向空间（零新增顶层键、
// method/uri 恒空、body 缺席）+ 两种 is_interrupted 形态（拦截=blocked /
// 信任检测=logged）。
func TestEventLineShape(t *testing.T) {
	now := time.Unix(1786447017, 841320426).UTC()
	line := buildL4EventLine(2, "IP 黑名单拒绝", "rule-abc", "1.2.3.4", now, [4]byte{0xde, 0xad, 0xbe, 0xef}, true)

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(line, &doc); err != nil {
		t.Fatalf("line is not JSON: %v\n%s", err, line)
	}
	if len(doc) != 2 {
		t.Fatalf("top-level keys = %v, want exactly [transaction messages]", doc)
	}
	var tx struct {
		UnixTimestamp int64  `json:"unix_timestamp"`
		ID            string `json:"id"`
		ClientIP      string `json:"client_ip"`
		ServerID      string `json:"server_id"`
		Request       struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
			Headers map[string][]string `json:"headers"`
			Body    json.RawMessage     `json:"body"`
		} `json:"request"`
		IsInterrupted bool `json:"is_interrupted"`
	}
	if err := json.Unmarshal(doc["transaction"], &tx); err != nil {
		t.Fatalf("transaction unmarshal: %v", err)
	}
	if tx.UnixTimestamp != 1786447017841320426 {
		t.Fatalf("unix_timestamp = %d, want 纳秒 1786447017841320426", tx.UnixTimestamp)
	}
	wantID := "l4-1786447017841320426-deadbeef"
	if tx.ID != wantID {
		t.Fatalf("transaction.id = %q, want %q", tx.ID, wantID)
	}
	if !strings.HasPrefix(tx.ID, "l4-") {
		t.Fatalf("transaction.id %q must carry the unique l4- prefix", tx.ID)
	}
	if tx.ClientIP != "1.2.3.4" {
		t.Fatalf("client_ip = %q", tx.ClientIP)
	}
	if tx.ServerID != "" {
		t.Fatalf("server_id = %q, want empty", tx.ServerID)
	}
	if tx.Request.Method != "" || tx.Request.URI != "" {
		t.Fatalf("method/uri = %q/%q, want empty (TCP 连接无 HTTP 语义)", tx.Request.Method, tx.Request.URI)
	}
	if tx.Request.Body != nil {
		t.Fatalf("body must be absent, got %s", tx.Request.Body)
	}
	if got := tx.Request.Headers["X-LB-Rule-ID"]; len(got) != 1 || got[0] != "rule-abc" {
		t.Fatalf("X-LB-Rule-ID = %v, want [rule-abc]（归因键）", got)
	}
	if got := tx.Request.Headers["X-LB-Protocol"]; len(got) != 1 || got[0] != "tcp" {
		t.Fatalf("X-LB-Protocol = %v, want [tcp]（event_type='tcp' 唯一信号）", got)
	}
	if len(tx.Request.Headers) != 2 {
		t.Fatalf("headers = %v, want exactly the two X-LB-* headers", tx.Request.Headers)
	}
	if !tx.IsInterrupted {
		t.Fatal("is_interrupted = false, want true（→ action=blocked）")
	}

	var msgs []struct {
		Data struct {
			ID json.Number `json:"id"`
		} `json:"data"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(doc["messages"], &msgs); err != nil {
		t.Fatalf("messages unmarshal: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("messages len = %d, want 1", len(msgs))
	}
	if msgs[0].Data.ID.String() != "2" {
		t.Fatalf("messages[0].data.id = %s, want numeric 2（段位沿用 HTTP 预检）", msgs[0].Data.ID)
	}
	if msgs[0].Message != "IP 黑名单拒绝" {
		t.Fatalf("messages[0].message = %q, want 与 HTTP 预检同款文案", msgs[0].Message)
	}

	// 信任检测形态：is_interrupted=false → 摄取侧 action=logged（仅记录不拦截）；
	// 其余字段与拦截形态逐字段同构（同一构造单源，仅中断位翻转）。
	loggedLine := buildL4EventLine(12, "IP 信任名单检测", "rule-abc", "1.2.3.4", now, [4]byte{0xde, 0xad, 0xbe, 0xef}, false)
	var logged struct {
		Transaction struct {
			IsInterrupted bool `json:"is_interrupted"`
		} `json:"transaction"`
		Messages []struct {
			Data struct {
				ID json.Number `json:"id"`
			} `json:"data"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(loggedLine, &logged); err != nil {
		t.Fatalf("logged line unmarshal: %v", err)
	}
	if logged.Transaction.IsInterrupted {
		t.Fatal("trust_detect 行 is_interrupted = true, want false（logged 不拦截语义）")
	}
	if len(logged.Messages) != 1 || logged.Messages[0].Data.ID.String() != "12" {
		t.Fatalf("logged messages=%v, want 单条 id=12（HTTP 保留检测段位）", logged.Messages)
	}
}

// TestEventSegmentTable 段位/文案表：deny=2、独立黑名单=4、allow 交集外拒绝=7、
// GeoIP=800000+policyID；文案与 internal/services/security.go 预检指令逐字同款。
func TestEventSegmentTable(t *testing.T) {
	cases := []struct {
		reason   string
		policyID int64
		wantID   int64
		wantMsg  string
	}{
		{"deny", 3, 2, "IP 黑名单拒绝"},
		{"blacklist", 3, 4, "IP 黑名单"},
		{"allow", 3, 7, "IP 白名单拒绝"},
		{"geoip", 3, 800003, "GeoIP 区域拦截"},
		// 信任检测（trust_detection=1）：段位沿用 HTTP 保留检测 id:12——评分/
		// 归因走摄取侧既有预检分支（IsStage1PrecheckEventID(12) → 预检档 12 分；
		// logged 归因走信任白名单分支），零新增。
		{"trust_detect", 0, 12, "IP 信任名单检测"},
		{"trust_detect", 7, 12, "IP 信任名单检测"},
	}
	for _, tc := range cases {
		id, msg, ok := eventSegment(tc.reason, tc.policyID)
		if !ok {
			t.Fatalf("eventSegment(%s) not ok", tc.reason)
		}
		if id != tc.wantID || msg != tc.wantMsg {
			t.Fatalf("eventSegment(%s,%d) = (%d,%q), want (%d,%q)", tc.reason, tc.policyID, id, msg, tc.wantID, tc.wantMsg)
		}
	}
	if _, _, ok := eventSegment("bogus", 1); ok {
		t.Fatal("eventSegment(bogus) must not be ok")
	}
	if _, _, ok := eventSegment("trust_detect", -1); ok {
		t.Fatal("eventSegment(trust_detect,-1) must not be ok（policy_id 非 [0,max] 拒绝）")
	}
}

// TestHandleDenyReportsEvents deny reason 形态：上报合成事件 + denied 计数 +
// 透传后续 handler（close 负责断连，本 handler 不断连）。
func TestHandleDenyReportsEvents(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "") // IPC 显式关闭：事件只入队计数丢弃
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-deny", Reason: "deny", PolicyID: 5})
	next := &nextCapture{}
	cx := newTestConn("203.0.113.99")
	if err := h.Handle(cx, next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if !next.called {
		t.Fatal("deny 形态必须透传（断连由下游 close 负责）")
	}
	s := connStatsSnapshot()
	rule := s.Rules["r-deny"]
	if rule == nil {
		t.Fatal("r-deny not registered")
	}
	if rule.DeniedTotal != 1 || rule.AllowedTotal != 0 {
		t.Fatalf("denied/allowed = %d/%d, want 1/0", rule.DeniedTotal, rule.AllowedTotal)
	}
	// 事件行已产出（IPC 关闭形态：drain 消费后按丢弃计数）
	p.flushQuiescedForTest()
	if p.dropped.Load() != 1 {
		t.Fatalf("dropped = %d, want 1（IPC 关闭时事件行按丢弃计数）", p.dropped.Load())
	}
}

// TestHandleTrustDetectLogsNotBlocks trust_detect 形态（SEC-P1-1）：产 logged
// 事件行（is_interrupted=false，仅记录）+ 透传不断连；计数走 allowed（连接
// 到达上游=正常流量口径，与 HTTP 信任检测请求计入流量统计一致），denied 不动。
func TestHandleTrustDetectLogsNotBlocks(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()

	lookups := 0
	restore := setSampleCountryLookuperForTest(func(ip string) (string, bool) {
		lookups++
		return "美国", true
	})
	defer restore()

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-trust", Reason: "trust_detect"})
	next := &nextCapture{}
	if err := h.Handle(newTestConn("203.0.113.77"), next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	if !next.called {
		t.Fatal("trust_detect 必须透传（HTTP DetectionOnly 等价：记录不拦截）")
	}
	rule := connStatsSnapshot().Rules["r-trust"]
	if rule == nil || rule.DeniedTotal != 0 || rule.AllowedTotal != 1 {
		t.Fatalf("denied/allowed = %v, want 0/1（logged 连接计 allowed）", rule)
	}
	if lookups != 1 {
		t.Fatalf("country lookups = %d, want 1（首连接命中 1/16 采样）", lookups)
	}
	// 事件行已产出（IPC 关闭形态：drain 消费后按丢弃计数）。
	p.flushQuiescedForTest()
	if p.dropped.Load() != 1 {
		t.Fatalf("dropped = %d, want 1（trust_detect 产 logged 事件行）", p.dropped.Load())
	}
}

// TestHandleAllowSampleSampling allow_sample 形态：全量 allowed 计数 + 每 16
// 连接采样 1 次做国家归属累计；透传 proxy。
func TestHandleAllowSampleSampling(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()

	lookups := 0
	restore := setSampleCountryLookuperForTest(func(ip string) (string, bool) {
		lookups++
		return "中国", true
	})
	defer restore()

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-allow", Mode: "allow_sample"})
	for range 16 {
		next := &nextCapture{}
		if err := h.Handle(newTestConn("114.114.114.114"), next); err != nil {
			t.Fatalf("Handle = %v", err)
		}
		if !next.called {
			t.Fatal("allow_sample must pass through")
		}
	}
	rule := connStatsSnapshot().Rules["r-allow"]
	if rule == nil || rule.AllowedTotal != 16 || rule.DeniedTotal != 0 {
		t.Fatalf("allowed/denied = %v, want 16/0", rule)
	}
	if lookups != 1 {
		t.Fatalf("country lookups = %d, want 1（1/16 采样）", lookups)
	}
	if len(rule.Countries) != 1 || rule.Countries["中国"] != 1 {
		t.Fatalf("countries = %v, want {中国:1}", rule.Countries)
	}
	if p.dropped.Load() != 0 {
		t.Fatalf("dropped = %d, want 0（allow_sample 零事件线）", p.dropped.Load())
	}
	p.flushQuiescedForTest()
}

// TestHandleDenyStillsCountsOnQueueFull 队列满（风暴自防）时拦截决策与
// denied 计数不受影响，事件行按丢弃计数。
func TestHandleDenyStillsCountsOnQueueFull(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	// 队列容量 1 的收窄必须先于管线构造（chan 容量构造期定格）
	defer restoreTunables(setTunablesForTest(1, 1<<20, 10*time.Millisecond))
	p := acquirePipelineForTest()
	defer p.resetForTest()

	p.blockDrainForTest(true) // 先暂停消费，保证队列满形态确定
	// 占满队列（容量 1）
	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-storm", Reason: "deny", PolicyID: 1})
	if err := h.Handle(newTestConn("198.51.100.1"), &nextCapture{}); err != nil {
		t.Fatalf("Handle #1 = %v", err)
	}
	if err := h.Handle(newTestConn("198.51.100.2"), &nextCapture{}); err != nil {
		t.Fatalf("Handle #2 (queue full) = %v", err)
	}
	rule := connStatsSnapshot().Rules["r-storm"]
	if rule == nil || rule.DeniedTotal != 2 {
		t.Fatalf("denied = %+v, want 2（计数与遥测解耦）", rule)
	}
	if p.dropped.Load() != 1 {
		t.Fatalf("dropped = %d, want 1（队列满丢弃不回灌拦截路径）", p.dropped.Load())
	}
	p.blockDrainForTest(false)
	p.flushQuiescedForTest()
	// 排空后 #1 行消费：IPC 关闭 → submit 侧按丢弃计数
	if p.dropped.Load() != 2 {
		t.Fatalf("dropped after quiesce = %d, want 2", p.dropped.Load())
	}
}

// TestCleanupDeregistersRule 实例 Cleanup 按指针身份注销；同载次多实例共享
// 计数（不互相覆盖）。
func TestCleanupDeregistersRule(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-life", Reason: "deny", PolicyID: 2})
	if connStatsSnapshot().Rules["r-life"] == nil {
		t.Fatal("rule not registered after provision")
	}
	if err := h.Cleanup(); err != nil {
		t.Fatalf("Cleanup() = %v", err)
	}
	if connStatsSnapshot().Rules["r-life"] != nil {
		t.Fatal("rule still registered after cleanup")
	}
}

// TestBeginLoadResetsPerLoad 换载次（新 caddy.Context）→ 计数注册表整体重置
// （契约 C3：计数器随 /load 重建归零）；同载次内保留。
func TestBeginLoadResetsPerLoad(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	ctxA, cancelA := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancelA()
	// 独立底座 context 制造不同载次身份
	ctxB, cancelB := caddy.NewContext(caddy.Context{Context: context.WithValue(context.Background(), ctxKeyLoad{}, "b")})
	defer cancelB()

	beginLoad(ctxA)
	getOrCreateRuleCounters("r1").denied.Add(1)
	if s := connStatsSnapshot(); s.Rules["r1"] == nil || s.Rules["r1"].DeniedTotal != 1 {
		t.Fatal("setup: r1 counters missing")
	}
	beginLoad(ctxB) // 新载次：重置
	if s := connStatsSnapshot(); len(s.Rules) != 0 {
		t.Fatalf("new load must reset counters, got %v", s.Rules)
	}
	beginLoad(ctxB) // 同载次：不重置
	getOrCreateRuleCounters("r2").allowed.Add(1)
	beginLoad(ctxB)
	if s := connStatsSnapshot(); s.Rules["r2"] == nil {
		t.Fatal("same-load re-provision must keep counters")
	}
}

// 编译期契约：handler 持 zap logger（caddy 侧注入）。
var _ = zap.NewNop
