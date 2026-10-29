package caddygeoip

// 流量计数/admin 端点钉测（大屏「无 accesslog 光流」数据源，Plan B）：
// 计数正确性（attack/normal 双桶+国名分桶）、抽样因子（×N 还原+回落）、
// 快照形状（JSON）、admin 注册一次语义。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetTrafficState(t *testing.T) {
	t.Helper()
	trafficMu.Lock()
	trafficCountries = map[string]*trafficEntry{}
	trafficMu.Unlock()
	trafficSecondState.Store(0)
	trafficSampleN.Store(1)
	trafficCountryDropped.Store(0)
	trafficEventSeq.Store(0)
	trafficLeasesMu.Lock()
	trafficLeases = map[string]trafficLease{}
	if trafficLeaseTimer != nil {
		trafficLeaseTimer.Stop()
		trafficLeaseTimer = nil
	}
	// 旧测试直接调用 trafficRecord，默认视为采集开启；租约测试会显式关闭。
	trafficCollectorEnabled.Store(true)
	trafficLeasesMu.Unlock()
}

func TestTrafficRecord_attackNormalBuckets(t *testing.T) {
	// Given: 同国攻击与正常流量并存；他国独立分桶
	resetTrafficState(t)

	trafficRecord("United States", true)
	trafficRecord("United States", true)
	trafficRecord("United States", false)
	trafficRecord("中国", false)

	e := trafficCountries["United States"]
	if e == nil || e.attack.Load() != 2 || e.normal.Load() != 1 {
		t.Fatalf("United States=%+v, want attack=2 normal=1", e)
	}
	cn := trafficCountries["中国"]
	if cn == nil || cn.attack.Load() != 0 || cn.normal.Load() != 1 {
		t.Fatalf("中国=%+v, want attack=0 normal=1", cn)
	}

	// 空国名（geoip 未解析）跳过
	trafficRecord("", true)
	if _, exists := trafficCountries[""]; exists {
		t.Fatalf("空国名不应产生条目")
	}
}

// 统计桶键与发射侧/校验侧同口径 TrimSpace——空白异形国名不得
// 建出与正式国名并存的脏桶（前端会显示两个「中国」）。
func TestTrafficRecord_trimsCountryKey(t *testing.T) {
	resetTrafficState(t)
	trafficRecord(" 中国 ", false)
	trafficRecord("\t中国", true)

	trafficMu.RLock()
	defer trafficMu.RUnlock()
	e := trafficCountries["中国"]
	if e == nil || e.normal.Load() != 1 || e.attack.Load() != 1 {
		t.Fatalf("trimmed bucket=%+v, want normal=1 attack=1", e)
	}
	if _, exists := trafficCountries[" 中国 "]; exists {
		t.Fatal("带空白的国名不得建桶（与发射侧/校验侧口径分裂）")
	}
	if got := len(trafficCountries); got != 1 {
		t.Fatalf("country buckets=%d, want 1（同一国家唯一桶）", got)
	}
}

// xdb 私网/保留段行的国家列为 "0"/"Reserved"，不是国家值——计数桶
// 与事件流都不得为其建键（聚合端点已过滤 ""/"0"/"Reserved"，两端口径统一）。
func TestTrafficRecord_rejectsNonCountryKeys(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSampleN.Store(1)
	for _, key := range []string{"", "0", "Reserved", " 0 ", "Reserved "} {
		trafficRecord(key, true)
		trafficRecord(key, false)
		trafficEventRecord(key, "")
	}
	trafficMu.RLock()
	count := len(trafficCountries)
	trafficMu.RUnlock()
	if count != 0 {
		t.Fatalf("non-country keys must not create buckets, got %d", count)
	}
	if events := len(trafficEvents); events != 0 {
		t.Fatalf("non-country keys must not create events, got %d", events)
	}

	// 回归形状：真实国家键照常计数与记录事件。
	trafficRecord("中国", false)
	trafficEventRecord("中国", "广东省")
	if e := trafficCountries["中国"]; e == nil || e.normal.Load() != 1 {
		t.Fatalf("real country bucket missing: %+v", e)
	}
	if len(trafficEvents) != 1 {
		t.Fatalf("real country event missing: %d", len(trafficEvents))
	}
}

// xdb 中文异体国名（「美国」）与英文规范名必须归一到同一桶——
// 分键各自计数时，app 聚合端点按翻译后中文名重建 map（后写覆盖先写）会丢掉
// 其中一桶的 attack/normal 计数。归一经 geoipnames.NormalizeCountry，与发射
// 侧 geoipLocFor 同表同函数；「中国」保留不折叠。
func TestTrafficRecord_normalizesOverseasAliases(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSampleN.Store(1)

	// 目标形状：中文异体与英文名进同一桶，事件流同口径。
	trafficRecord("美国", true)
	trafficRecord("United States", true)
	trafficRecord("United States", false)
	trafficEventRecord("美国", "")

	trafficMu.RLock()
	e := trafficCountries["United States"]
	_, aliasBucket := trafficCountries["美国"]
	buckets := len(trafficCountries)
	trafficMu.RUnlock()
	if e == nil || e.attack.Load() != 2 || e.normal.Load() != 1 {
		t.Fatalf("United States bucket=%+v, want attack=2 normal=1（异体合桶）", e)
	}
	if aliasBucket {
		t.Fatal("中文异体「美国」不得建独立桶")
	}
	if buckets != 1 {
		t.Fatalf("country buckets=%d, want 1（异体归一）", buckets)
	}
	if len(trafficEvents) != 1 || trafficEvents[0].Country != "United States" {
		t.Fatalf("event country=%+v, want normalized to United States", trafficEvents)
	}

	// 回归形状：「中国」保留（NormalizeCountry 对其返回空串，不得被吞）。
	trafficRecord("中国", false)
	trafficMu.RLock()
	cn := trafficCountries["中国"]
	trafficMu.RUnlock()
	if cn == nil || cn.normal.Load() != 1 {
		t.Fatalf("中国 bucket=%+v, want normal=1（保留不折叠）", cn)
	}
}

func TestTrafficRecord_countryCapacity(t *testing.T) {
	// 满员丢弃必须可观测（计数 + 节流告警）：否则大屏国家流量少计而零信号。
	oldInterval := crawlerSnapshotThrottle.interval
	crawlerSnapshotThrottle.interval = 0 // 不节流：断言每次丢弃都有告警
	t.Cleanup(func() { crawlerSnapshotThrottle.interval = oldInterval })
	logBase := crawlerSnapshotLogCallsForTest.Load()

	// Given: 国名桶达到硬上限，且其中一个已有桶随后继续命中。
	resetTrafficState(t)
	const limit = 512
	for i := range limit {
		trafficRecord(fmt.Sprintf("country-%03d", i), false)
	}
	trafficRecord("country-000", true)

	// When: 第 513 个新国名到达。
	trafficRecord("overflow", true)

	// Then: 新键被丢弃，已有键仍正常计数，map 永不越界。
	trafficMu.RLock()
	defer trafficMu.RUnlock()
	if got := len(trafficCountries); got != limit {
		t.Fatalf("country buckets=%d, want hard limit %d", got, limit)
	}
	if _, exists := trafficCountries["overflow"]; exists {
		t.Fatal("new country beyond the capacity must be dropped")
	}
	if got := trafficCountryDropped.Load(); got != 1 {
		t.Fatalf("dropped counter=%d, want 1（满员丢弃不得无声）", got)
	}
	if got := crawlerSnapshotLogCallsForTest.Load() - logBase; got != 1 {
		t.Fatalf("满员丢弃告警=%d 条, want 1（首报即记，不节流时逐次）", got)
	}
	// 已有国家在满员后继续精确计数（丢弃只作用于新键）。
	e := trafficCountries["country-000"]
	if e == nil || e.normal.Load() != 1 || e.attack.Load() != 1 {
		t.Fatalf("existing country at capacity=%+v, want attack=1 normal=1", e)
	}
}

func TestTrafficRecord_samplingFuse(t *testing.T) {
	// Given: 单秒请求计数越过保险丝 → 进入 1/8 抽样，计数 ×8 还原。
	// 冻结墙钟：4010 次记录若在真实时钟下跨秒，秒计数会从头累计、
	// 永远触不到越线点（慢 CI 秒边界假红）。
	resetTrafficState(t)
	const frozenSecond = 1_700_000_000
	oldNow := trafficNowUnix
	trafficNowUnix = func() int64 { return frozenSecond }
	t.Cleanup(func() { trafficNowUnix = oldNow })
	for range fuseQPSPerSecond + 10 {
		trafficRecord("德国", true)
	}
	if n := trafficSampleN.Load(); n != fuseSampleN {
		t.Fatalf("sample_n=%d, want %d（越线进抽样）", n, fuseSampleN)
	}
	// 抽样误差口径（注释披露）：估计量=真值±N（N=8）——整秒累计口径无偏，
	// 瞬时序列有量化截断（floor）
	got := trafficCountries["德国"].attack.Load()
	truth := uint64(fuseQPSPerSecond + 10)
	if got > truth || truth-got >= fuseSampleN {
		t.Fatalf("attack=%d, want %d±%d（抽样还原口径）", got, truth, fuseSampleN)
	}

	// 回落：显式模拟翻秒且上一秒计数 < fuseFallbackPerSecond → N=1（全量）
	trafficSecondState.Store((uint64(frozenSecond-1) << 32) | 500)
	trafficRecord("德国", true)
	if n := trafficSampleN.Load(); n != 1 {
		t.Fatalf("sample_n=%d, want 1（翻秒低计数回落全量）", n)
	}
}

// 翻秒丢计回归——秒戳与计数是打包原子态，跨秒瞬间的
// 并发计数不得被随后清零的上一秒计数吞掉。
func TestTrafficRecord_noLostHitsAcrossSecondRollover(t *testing.T) {
	resetTrafficState(t)
	// 强制「上一秒」态：下一次 record 触发翻秒，同时并发记录。
	trafficSecondState.Store((uint64(time.Now().Unix()-1) << 32) | 400)
	const goroutines = 8
	const perGoroutine = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				trafficRecord("翻秒国", false)
			}
		}()
	}
	wg.Wait()
	e := trafficCountries["翻秒国"]
	if e == nil {
		t.Fatal("missing country entry")
	}
	if got := e.normal.Load(); got != goroutines*perGoroutine {
		t.Fatalf("normal=%d, want %d（翻秒期间零丢计）", got, goroutines*perGoroutine)
	}
}

func TestTrafficRecord_samplingFuseConcurrent(t *testing.T) {
	// 回归形状：并发计数（atomic 语义，race 检测由 -race 覆盖）
	resetTrafficState(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				trafficRecord("并发国", j%4 == 0)
			}
		}()
	}
	wg.Wait()
	e := trafficCountries["并发国"]
	if e == nil || e.attack.Load()+e.normal.Load() != 800 {
		t.Fatalf("并发计数=%+v, want 合计 800", e)
	}
}

func TestTrafficSnapshotJSON_shape(t *testing.T) {
	// Given: 两国计数
	resetTrafficState(t)
	trafficRecord("United States", true)
	trafficRecord("United States", false)
	trafficRecord("中国", false)

	// When
	raw := trafficSnapshotJSON()

	// Then: JSON 形状 {"countries":{国:{attack,normal}},"sample_n":N}
	var payload struct {
		Countries map[string]struct {
			Attack uint64 `json:"attack"`
			Normal uint64 `json:"normal"`
		} `json:"countries"`
		SampleN uint32 `json:"sample_n"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	if payload.SampleN != 1 {
		t.Errorf("sample_n=%d, want 1", payload.SampleN)
	}
	if payload.Countries["United States"].Attack != 1 || payload.Countries["United States"].Normal != 1 {
		t.Errorf("United States=%+v", payload.Countries["United States"])
	}
	if payload.Countries["中国"].Normal != 1 {
		t.Errorf("中国=%+v", payload.Countries["中国"])
	}
	if !strings.Contains(string(raw), `"sample_n":`) {
		t.Errorf("缺 sample_n 字段: %s", raw)
	}
}

func TestTrafficAdminRoute_registerOnceAndServe(t *testing.T) {
	// trafficRouteRegistered/trafficSeq 是零生产读写的
	// 死变量（去重语义由 Caddy admin 模块生命周期保证），已删除。此处改钉
	// Routes() 的**形状契约**：恰一条 /lb/traffic-stats 路由——返回 0 条或
	// 2 条都必须失败。
	resetTrafficState(t)
	routes := (TrafficStatsAdmin{}).Routes()
	if len(routes) != 3 {
		t.Fatalf("Routes()=%d, want exactly 3", len(routes))
	}
	if routes[0].Pattern != "/lb/traffic-stats" || routes[1].Pattern != "/lb/traffic-collector" || routes[2].Pattern != "/lb/traffic-events" {
		t.Fatalf("route patterns=%q/%q/%q", routes[0].Pattern, routes[1].Pattern, routes[2].Pattern)
	}

	// serveTrafficStats 直出快照（HTTP 形状）
	rec := httptest.NewRecorder()
	serveTrafficStats(rec, httptest.NewRequest(http.MethodGet, "/lb/traffic-stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type=%q", ct)
	}
	if !strings.Contains(rec.Body.String(), `"countries"`) {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

// 国名键来自 GeoIP 解析结果（可能含非法 UTF-8/引号/控制字节）：快照序列化
// 必须始终产出合法 JSON——手写转义遇非法 UTF-8 会写出裸字节使整个端点失败。
func TestTrafficSnapshotJSON_toleratesInvalidUTF8CountryKey(t *testing.T) {
	resetTrafficState(t)
	rawName := "Bad\xff\"\\\x01Land"
	trafficRecord(rawName, true)

	raw := trafficSnapshotJSON()

	if !json.Valid(raw) {
		t.Fatalf("snapshot is not valid JSON: %q", raw)
	}
	var payload struct {
		Countries map[string]struct {
			Attack uint64 `json:"attack"`
			Normal uint64 `json:"normal"`
		} `json:"countries"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode snapshot: %v (%q)", err, raw)
	}
	want := "Bad\uFFFD\"\\\x01Land"
	entry, ok := payload.Countries[want]
	if !ok {
		t.Fatalf("invalid UTF-8 key not normalized to replacement char: %v", payload.Countries)
	}
	if entry.Attack != 1 || entry.Normal != 0 {
		t.Fatalf("entry=%+v, want attack=1 normal=0", entry)
	}
}

// 快照形状契约：consumers（internal/handlers 的 trafficSnapshot）只解码
// countries/sample_n/collecting；admin 可达性由 app 侧 available 合成，插件
// 不发射 enabled（开关真源是租约端点）。collecting=采集租约当前是否有效——
// 无租约时累计计数冻结，缺该字段会让「累计不变」被误读为「无流量」。
func TestTrafficSnapshotJSON_omitsUnconsumedEnabledField(t *testing.T) {
	resetTrafficState(t)
	trafficRecord("China", false)

	raw := string(trafficSnapshotJSON())
	if strings.Contains(raw, `"enabled"`) {
		t.Fatalf("traffic snapshot must not emit the unconsumed enabled field: %s", raw)
	}
	if !strings.Contains(raw, `"countries"`) || !strings.Contains(raw, `"sample_n"`) || !strings.Contains(raw, `"collecting"`) {
		t.Fatalf("snapshot lost its contract fields: %s", raw)
	}
}

// 采集租约状态是快照的一等字段：无租约期间计数冻结，快照必须如实披露
// collecting=false（否则「累计不变」与「无流量」不可区分）。
func TestTrafficSnapshotJSON_collectorStateFollowsLease(t *testing.T) {
	resetTrafficState(t)
	// Given：无租约（采集关闭）
	trafficCollectorEnabled.Store(false)

	readCollecting := func(t *testing.T) bool {
		t.Helper()
		var payload struct {
			Collecting bool `json:"collecting"`
		}
		if err := json.Unmarshal(trafficSnapshotJSON(), &payload); err != nil {
			t.Fatalf("decode snapshot: %v", err)
		}
		return payload.Collecting
	}
	if readCollecting(t) {
		t.Fatal("无租约时 collecting 必须为 false")
	}

	// When：申请租约
	if err := acquireTrafficLease("snapshot-lease", time.Second, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { releaseTrafficLease("snapshot-lease") })
	// Then：collecting=true
	if !readCollecting(t) {
		t.Fatal("持有租约时 collecting 必须为 true")
	}

	// When：释放租约
	releaseTrafficLease("snapshot-lease")
	// Then：回落 false
	if readCollecting(t) {
		t.Fatal("释放租约后 collecting 必须回落 false")
	}
}
