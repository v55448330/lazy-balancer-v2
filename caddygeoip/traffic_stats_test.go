package caddygeoip

// 流量计数/admin 端点钉测（大屏「无 accesslog 光流」数据源，Plan B）：
// 计数正确性（attack/normal 双桶+国名分桶）、抽样因子（×N 还原+回落）、
// 快照形状（JSON）、admin 注册一次语义。

import (
	"encoding/json"
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
	trafficSeq.Store(0)
	trafficSecond.Store(0)
	trafficSecondHits.Store(0)
	trafficSampleN.Store(1)
	trafficRouteRegistered.Store(false)
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

func TestTrafficRecord_samplingFuse(t *testing.T) {
	// Given: 单秒请求计数越过保险丝 → 进入 1/8 抽样，计数 ×8 还原
	resetTrafficState(t)
	for i := 0; i < fuseQPSPerSecond+10; i++ {
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
	trafficSecond.Store(time.Now().Unix() - 1)
	trafficSecondHits.Store(500)
	trafficRecord("德国", true)
	if n := trafficSampleN.Load(); n != 1 {
		t.Fatalf("sample_n=%d, want 1（翻秒低计数回落全量）", n)
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
	// Given: admin 路由进程级注册一次（reload 期新旧实例并存——同路径二次
	// 注册会 panic；路由读全局计数，实例无关）
	resetTrafficState(t)
	old := trafficRouteRegistered.Load()
	trafficRouteRegistered.Store(false)
	t.Cleanup(func() { trafficRouteRegistered.Store(old) })

	if !trafficRouteRegistered.CompareAndSwap(false, true) {
		t.Fatal("首次注册 CAS 失败")
	}
	if trafficRouteRegistered.CompareAndSwap(false, true) {
		t.Fatal("二次注册未被去重——reload 双实例并存会 panic")
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
