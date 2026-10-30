package handlers

// traffic 端点 L4 差分合并 RED 测试（契约 C3/C5）：拉取 caddy admin
// /lb/l4-conn-stats，按 admin URL 维护上次已消费原始计数并输出**差分值**；
// 计数器随 /load 重建归零时差分取重置后值（不出负数）；admin 不可达/l4 端点
// 缺失 → l4 键空对象（与 traffic-stats 同容错）。
import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

// resetL4TrafficDeltaStateForTest 清空差分状态（测试缝：产品文件不得声明
// test-only 入口，故驻留本测试文件；同包测试可直接访问未导出状态）。
func resetL4TrafficDeltaStateForTest() {
	l4TrafficDeltaMu.Lock()
	l4TrafficLastServe = map[string]l4TrafficRawSnapshot{}
	l4TrafficDeltaMu.Unlock()
}

// resetThreatTrafficStateForTest 复位 traffic 缓存/差分状态并关闭缓存 TTL。
func resetThreatTrafficStateForTest(t *testing.T) {
	t.Helper()
	withIsolatedGlobal(t)
	oldTTL := threatTrafficCacheTTL
	threatTrafficCacheTTL = 0 // 每次取数都绕过 1s 缓存（差分按次推进）
	t.Cleanup(func() { threatTrafficCacheTTL = oldTTL })
	threatTrafficCache = sync.Map{}
	resetL4TrafficDeltaStateForTest()
}

func newL4TrafficAdmin(t *testing.T, l4Body *atomic.Value) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/lb/traffic-stats", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"countries":{"China":{"attack":1,"normal":100}},"sample_n":1,"collecting":true}`))
	})
	mux.HandleFunc("/lb/l4-conn-stats", func(w http.ResponseWriter, r *http.Request) {
		if l4Body == nil || l4Body.Load() == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(l4Body.Load().(string)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func l4DeltaOf(t *testing.T, data gin.H) gin.H {
	t.Helper()
	raw, ok := data["l4"]
	if !ok {
		t.Fatalf("响应缺 l4 键: %v", data)
	}
	m, ok := raw.(gin.H)
	if !ok {
		t.Fatalf("l4 键形态异常: %T", raw)
	}
	return m
}

func TestThreatTrafficSnapshot_mergesL4Deltas(t *testing.T) {
	resetThreatTrafficStateForTest(t)
	var l4Body atomic.Value
	admin := newL4TrafficAdmin(t, &l4Body)

	// 首轮：全量计数即首轮差分。
	l4Body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":10,"denied_total":3,"countries":{"中国":4,"United States":2}}}}`)
	data, ok := threatTrafficSnapshot(admin.URL)
	if !ok {
		t.Fatal("traffic snapshot fetch failed")
	}
	l4 := l4DeltaOf(t, data)
	if sampled, _ := l4["sampled"].(bool); !sampled {
		t.Fatalf("sampled=%v, want true（countries 为采样口径）", l4["sampled"])
	}
	rules, ok := l4["rules"].(map[string]map[string]uint64)
	if !ok {
		t.Fatalf("l4.rules=%#v 形态异常", l4["rules"])
	}
	got := rules["lb_tcp_1"]
	if got["allowed"] != 10 || got["denied"] != 3 {
		t.Fatalf("首轮差分=%v, want allowed=10 denied=3", got)
	}
	countries, ok := l4["countries"].(map[string]uint64)
	if !ok {
		t.Fatalf("l4.countries=%#v 形态异常", l4["countries"])
	}
	if countries["中国"] != 4 || countries["美国"] != 2 {
		t.Fatalf("首轮国家差分=%v, want 中国=4 美国=2（中文名同 countries 口径）", countries)
	}

	// 次轮：增量差分（denied 不变 → 0；US 计数不变 → 0）。
	l4Body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":16,"denied_total":3,"countries":{"中国":8,"United States":2}}}}`)
	data, ok = threatTrafficSnapshot(admin.URL)
	if !ok {
		t.Fatal("second fetch failed")
	}
	l4 = l4DeltaOf(t, data)
	rules = l4["rules"].(map[string]map[string]uint64)
	got = rules["lb_tcp_1"]
	if got["allowed"] != 6 || got["denied"] != 0 {
		t.Fatalf("次轮差分=%v, want allowed=6 denied=0", got)
	}
	countries = l4["countries"].(map[string]uint64)
	if countries["中国"] != 4 {
		t.Fatalf("次轮国家差分=%v, want 中国=4", countries)
	}

	// 计数器重置（/load 归零形态：cur < prev）→ 差分取重置后值，不出负数。
	l4Body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":2,"denied_total":1,"countries":{"中国":1,"United States":0}}}}`)
	data, ok = threatTrafficSnapshot(admin.URL)
	if !ok {
		t.Fatal("third fetch failed")
	}
	l4 = l4DeltaOf(t, data)
	rules = l4["rules"].(map[string]map[string]uint64)
	got = rules["lb_tcp_1"]
	if got["allowed"] != 2 || got["denied"] != 1 {
		t.Fatalf("重置差分=%v, want allowed=2 denied=1", got)
	}
}

// l4 端点缺失/不可达（旧 Caddy 二进制形态）：traffic 主体照常返回，
// l4 键为空对象（静默跳过，与 traffic-stats 同容错）。
func TestThreatTrafficSnapshot_l4EndpointMissing_degradesQuietly(t *testing.T) {
	resetThreatTrafficStateForTest(t)
	admin := newL4TrafficAdmin(t, nil) // l4 恒 404
	data, ok := threatTrafficSnapshot(admin.URL)
	if !ok {
		t.Fatal("traffic 主体不得因 l4 缺失而失败")
	}
	l4 := l4DeltaOf(t, data)
	if rules, _ := l4["rules"].(map[string]map[string]uint64); len(rules) != 0 {
		t.Fatalf("l4.rules=%v, want 空", l4["rules"])
	}
	if countries, _ := l4["countries"].(map[string]uint64); len(countries) != 0 {
		t.Fatalf("l4.countries=%v, want 空", l4["countries"])
	}
}

// admin 整体不可达 → 既有降级形状不变（ok=false，无 l4 数据）。
func TestThreatTrafficSnapshot_adminUnreachable_unchangedDegrade(t *testing.T) {
	resetThreatTrafficStateForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("admin 不可达时不得发出请求")
	}))
	srv.Close()
	if _, ok := threatTrafficSnapshot(srv.URL); ok {
		t.Fatal("不可达 admin 应 ok=false")
	}
}
