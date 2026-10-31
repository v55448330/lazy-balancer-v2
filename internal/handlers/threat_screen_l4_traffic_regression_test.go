package handlers

// threat traffic 端点 L4 差分回归测试：
//   - 并发 serve 数据竞态：attachL4TrafficDelta 对 l4TrafficLastServe
//     的读未持锁 + 对共享缓存 gin.H 写 l4 键——race detector 下并发 serve
//     必然报 DATA RACE（Go 运行时 fatal 生产形态：多客户端大屏轮询即触发）。
//   - 抓取失败推进基线：l4 抓取失败时基线被写为空快照，恢复轮把
//     Caddy 全量累计当一轮增量（假尖峰）——与 metrics 采集侧「抓取失败不
//     推进基线」（l4connstats.go）同语义背离。
// 首轮（无基线）全量计数的既有契约不变（threat_screen_l4_traffic_test.go 钉测）。
import (
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestThreatTrafficSnapshot_concurrentServeNoRace：并发 serve 无竞态。
func TestThreatTrafficSnapshot_concurrentServeNoRace(t *testing.T) {
	resetThreatTrafficStateForTest(t)
	var l4Body atomic.Value
	admin := newL4TrafficAdmin(t, &l4Body)
	l4Body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":10,"denied_total":3}}}`)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := threatTrafficSnapshot(admin.URL); !ok {
				t.Error("traffic snapshot fetch failed")
			}
		}()
	}
	wg.Wait()
}

// TestThreatTrafficSnapshot_sharedCachePayloadNotMutated面 2：serve 不得
// 把 l4 键写进共享缓存载荷（并发 JSON 序列化迭代共享 map 即竞态）。
func TestThreatTrafficSnapshot_sharedCachePayloadNotMutated(t *testing.T) {
	resetThreatTrafficStateForTest(t)
	var l4Body atomic.Value
	admin := newL4TrafficAdmin(t, &l4Body)
	l4Body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":10,"denied_total":3}}}`)

	if _, ok := threatTrafficSnapshot(admin.URL); !ok {
		t.Fatal("traffic snapshot fetch failed")
	}
	if _, ok := threatTrafficSnapshot(admin.URL); !ok {
		t.Fatal("second snapshot fetch failed")
	}
	cached, ok := threatTrafficSnapshotCached(admin.URL)
	if !ok {
		t.Fatal("cached snapshot missing")
	}
	if _, polluted := cached["l4"]; polluted {
		t.Fatal("共享缓存载荷被写入 l4 键（并发序列化竞态面）")
	}
}

// TestThreatTrafficSnapshot_fetchFailureKeepsBaseline：抓取失败不推进
// 基线——恢复轮差分只含中断窗口，不重复累计。
func TestThreatTrafficSnapshot_fetchFailureKeepsBaseline(t *testing.T) {
	resetThreatTrafficStateForTest(t)
	var l4Body atomic.Value
	admin := newL4TrafficAdmin(t, &l4Body)

	// 轮 1：cur=100，首轮差分=100（全量，既有契约）。
	l4Body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":100,"denied_total":0}}}`)
	d1, ok := threatTrafficSnapshot(admin.URL)
	if !ok {
		t.Fatal("snapshot 1 failed")
	}
	if got := l4RulesAllowed(t, d1, "lb_tcp_1"); got != 100 {
		t.Fatalf("轮1 allowed delta = %d; want 100", got)
	}

	// 轮 2：抓取失败（空响应=解码失败）→ l4 键空、基线不动。
	l4Body.Store("")
	d2, ok := threatTrafficSnapshot(admin.URL)
	if !ok {
		t.Fatal("snapshot 2 failed")
	}
	if got := l4RulesAllowed(t, d2, "lb_tcp_1"); got != 0 {
		t.Fatalf("轮2（失败）allowed delta = %d; want 0", got)
	}

	// 轮 3：恢复 cur=150 → 差分应只含增量 50（失败前基线 100 续算）。
	l4Body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":150,"denied_total":0}}}`)
	d3, ok := threatTrafficSnapshot(admin.URL)
	if !ok {
		t.Fatal("snapshot 3 failed")
	}
	if got := l4RulesAllowed(t, d3, "lb_tcp_1"); got != 50 {
		t.Fatalf("轮3 allowed delta = %d; want 50（基线未被失败推进）", got)
	}
}

// l4RulesAllowed 从 traffic 响应 l4 键取指定规则的 allowed 差分。
func l4RulesAllowed(t *testing.T, data gin.H, cid string) uint64 {
	t.Helper()
	l4 := l4DeltaOf(t, data)
	rules, ok := l4["rules"].(map[string]map[string]uint64)
	if !ok {
		t.Fatalf("l4.rules 形态异常: %T", l4["rules"])
	}
	r, ok := rules[cid]
	if !ok {
		return 0
	}
	return r["allowed"]
}

var _ = httptest.NewServer // 保持导入对齐（newL4TrafficAdmin 同文件族）
