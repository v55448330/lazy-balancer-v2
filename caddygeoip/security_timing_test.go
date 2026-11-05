package caddygeoip

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// 计时注册表契约测试（侧车退役，耗时写入进程内
// 注册表，由审计写插件注入审计行——写侧三写点的行为钉）。

// useTestTimingRegistry 隔离全局注册表并收窄等待参数到测试量级。
func useTestTimingRegistry(t *testing.T) {
	t.Helper()
	origWait, origPoll := auditTimingWaitLimit, auditTimingPollStep
	auditTimingWaitLimit = 200 * time.Millisecond
	auditTimingPollStep = time.Millisecond
	resetAuditTimingRegistryForTest()
	t.Cleanup(func() {
		auditTimingWaitLimit, auditTimingPollStep = origWait, origPoll
		resetAuditTimingRegistryForTest()
	})
}

// auditTimingLookup 测试取值 helper（按分片路由读条目）。
func auditTimingLookupForTest(t *testing.T, id string) auditTimingSnapshot {
	t.Helper()
	e := auditTimingEntryForTest(id)
	if e == nil {
		return auditTimingSnapshot{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return auditTimingSnapshot{preUs: e.preUs, preSet: e.preSet, endUs: e.endUs, endSet: e.endSet, closed: e.closed}
}

// auditTimingEntryForTest 按 ID 路由读所属分片的条目指针（含分片锁）。
func auditTimingEntryForTest(id string) *auditTimingEntry {
	sh := auditTimingShardFor(id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.entries[id]
}

// auditTimingEntryCountForTest 跨片汇总在册条目数（含分片锁）。
func auditTimingEntryCountForTest() int {
	n := 0
	for i := range auditTimingShards {
		sh := auditTimingShards[i]
		sh.mu.Lock()
		n += len(sh.entries)
		sh.mu.Unlock()
	}
	return n
}

// auditTimingRetainedPreLookupForTest 按 ID 路由读所属分片的预检保留区。
func auditTimingRetainedPreLookupForTest(id string) (int64, bool) {
	sh := auditTimingShardFor(id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.retainedPreLookupLocked(id)
}

// auditRetainedPreLiveForTest 跨片汇总保留区在册条目数（逐片计数，与原子
// 准入计数互为对账）。
func auditRetainedPreLiveForTest() int {
	n := 0
	for i := range auditTimingShards {
		sh := auditTimingShards[i]
		sh.mu.Lock()
		n += len(sh.retainedPre)
		sh.mu.Unlock()
	}
	return n
}

// Given: 正常调用
// When: securityTimingID
// Then: 16 字符 hex(8 字节; 扩容后)
func TestSecurityTimingID_length(t *testing.T) {
	id := securityTimingID()
	if len(id) != 16 {
		t.Errorf("len=%d; want 16 (8 bytes hex)", len(id))
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Errorf("non-hex char %q in %q", c, id)
		}
	}
}

// security_timing_pre/end 两 ServeHTTP 逐字重复收敛为
// recordSecurityTiming helper——钉 helper 契约：合法头对写一段注册表耗时，
// 缺头对零写入（静默降级语义不变）。
func TestRecordSecurityTiming_writesRegistrySegment(t *testing.T) {
	useTestTimingRegistry(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, "abcdef0123456789")
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(time.Now().UnixNano()-12345000, 10))

	// When
	recordSecurityTiming(req, timingSegmentPre)

	// Then：注册表出现 pre 段且耗时为正整数（12ms 前起算）
	snap := auditTimingLookupForTest(t, "abcdef0123456789")
	if !snap.preSet || snap.preUs <= 0 {
		t.Fatalf("snapshot = %+v; want positive pre segment", snap)
	}

	// And 畸形形状：缺头对的请求零写入
	recordSecurityTiming(httptest.NewRequest(http.MethodGet, "/", nil), timingSegmentEnd)
	snapAfter := auditTimingLookupForTest(t, "abcdef0123456789")
	if snapAfter.endSet {
		t.Fatalf("missing headers must write nothing: %+v", snapAfter)
	}

	// And 降级形态：计时 ID 生成失败（空头值）零写入
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set(securityTimingHeader, "")
	recordSecurityTiming(req2, timingSegmentPre)
	if got := auditTimingLookupForTest(t, ""); got.preSet {
		t.Fatal("empty id must short-circuit")
	}
}

// 历史（预检拦耗时口径）：分段锚点交接契约——timing_pre 放行路径在记录
// pre 后，把起始纳秒头重写为「预检完成」锚点。下游 SecurityTimingEnd 的 end
// 自此从预检后起算（WAF 段值）；blocked_counter 以「起始头是否仍等于注入原值」
// 判定拦截出处（原值=预检段拦，头未动 → 写 pre 决策耗时；已重写=WAF/限流段
// 拦 → 写 end 全链）。放行形态：pre 段落注册表 + 头已重写为更大纳秒值。
func TestSecurityTimingPre_passAnchorsSegmentViaHeaderRewrite(t *testing.T) {
	useTestTimingRegistry(t)
	h := &SecurityTimingPre{}
	const id = "abcdef0123456789"
	startNs := time.Now().UnixNano()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(startNs, 10))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

	// When
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	// Then：pre 段落注册表（放行口径不变）
	snap := auditTimingLookupForTest(t, id)
	if !snap.preSet || snap.preUs <= 0 {
		t.Fatalf("snapshot = %+v; want positive pre segment", snap)
	}
	// And：起始头重写为分段锚点（严格晚于注入值；下游 end/WAF 段由此起算）
	rewritten, perr := strconv.ParseInt(req.Header.Get(securityTimingStartHeader), 10, 64)
	if perr != nil || rewritten <= startNs {
		t.Fatalf("start header = %q; want rewritten to ns > %d (segment anchor)",
			req.Header.Get(securityTimingStartHeader), startNs)
	}
	// And：ID 头保持（审计写插件的注册表关联键不受锚点交接影响）
	if req.Header.Get(securityTimingHeader) != id {
		t.Fatalf("timing id header = %q; want %q (audit correlation)", req.Header.Get(securityTimingHeader), id)
	}
}

// 畸形形态——缺关联头对的请求零写入、零改写、不 panic（静默降级）。
func TestSecurityTimingPre_missingHeadersNoop(t *testing.T) {
	useTestTimingRegistry(t)
	h := &SecurityTimingPre{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if len(auditTimingEntriesSnapshotForTest(t)) != 0 {
		t.Error("missing headers must not write registry entries")
	}
	if req.Header.Get(securityTimingStartHeader) != "" {
		t.Error("missing headers must not set segment anchor header")
	}
}

// logged 事件链末收点：timing_end 读重写后的锚点计算 end 段（自锚点起算=WAF
// 段值），原样透传下游。
func TestSecurityTimingEnd_recordsEndSegmentFromAnchor(t *testing.T) {
	useTestTimingRegistry(t)
	h := &SecurityTimingEnd{}
	const id = "0123456789abcdef"
	anchor := time.Now().UnixNano() - 5_000_000 // 锚点 5ms 前（timing_pre 已交接）
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(anchor, 10))
	passed := false
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { passed = true; return nil })

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !passed {
		t.Fatal("next must be invoked (pass-through)")
	}
	snap := auditTimingLookupForTest(t, id)
	if !snap.endSet || snap.endUs < 5 {
		t.Fatalf("snapshot = %+v; want end segment ≥5ms (from anchor)", snap)
	}
	if snap.closed {
		t.Fatal("timing_end must not close the entry (terminal marker owned by blocked_counter)")
	}
}

// 挂钟回拨/异常起始头（未来时刻）产生的负时长不得注入审计行——
// 耗时下限钳 0（0µs 是合法计时值）。
func TestRecordSecurityTiming_negativeClampedToZero(t *testing.T) {
	useTestTimingRegistry(t)
	const id = "ffffffffffffffff"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(time.Now().Add(time.Minute).UnixNano(), 10))

	recordSecurityTiming(req, timingSegmentPre)

	snap := auditTimingLookupForTest(t, id)
	if !snap.preSet {
		t.Fatalf("snapshot = %+v; want recorded pre segment", snap)
	}
	if snap.preUs != 0 {
		t.Fatalf("negative duration must clamp to 0, got %d", snap.preUs)
	}
}

func auditTimingEntriesSnapshotForTest(t *testing.T) map[string]*auditTimingEntry {
	t.Helper()
	out := map[string]*auditTimingEntry{}
	for i := range auditTimingShards {
		sh := auditTimingShards[i]
		sh.mu.Lock()
		for id, e := range sh.entries {
			out[id] = e
		}
		sh.mu.Unlock()
	}
	return out
}

// 计时 ID 是注册表 key，客户端可对无 counter 的
// 路由伪造任意头值灌入注册表（内存 DoS）。recordSecurityTiming 只接受与
// 服务端 securityTimingID 同形态的 16 字符 hex ID，其余一律静默忽略。
func TestRecordSecurityTiming_rejectsForgedID(t *testing.T) {
	useTestTimingRegistry(t)
	start := strconv.FormatInt(time.Now().UnixNano(), 10)

	forged := []struct {
		name string
		id   string
	}{
		{"超长 ID（64KiB）", strings.Repeat("a", 64*1024)},
		{"超长 ID（17 字符）", "abcdef0123456789a"},
		{"短 ID", "abc"},
		{"非 hex 16 字符", "zzzzzzzzzzzzzzzz"},
		{"大写 hex", "ABCDEF0123456789"},
		{"空白", " "},
	}
	for _, tt := range forged {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(securityTimingHeader, tt.id)
			req.Header.Set(securityTimingStartHeader, start)
			recordSecurityTiming(req, timingSegmentPre)
			if snap := auditTimingLookupForTest(t, tt.id); snap.preSet {
				t.Fatalf("forged id %q must not create registry entries", tt.id)
			}
		})
	}
	if got := len(auditTimingEntriesSnapshotForTest(t)); got != 0 {
		t.Fatalf("registry must stay empty under forged ids, got %d entries", got)
	}

	// 回归形状：合法 16-hex ID 照常记录。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, "abcdef0123456789")
	req.Header.Set(securityTimingStartHeader, start)
	recordSecurityTiming(req, timingSegmentPre)
	if snap := auditTimingLookupForTest(t, "abcdef0123456789"); !snap.preSet {
		t.Fatal("valid 16-hex id must still record")
	}
}
