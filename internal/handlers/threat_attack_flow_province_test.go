package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 攻击光流的 country/province 必须取自结构化单源（enrichIPLocationParts），
// 不得二次拆展示串：ISP-only 行按 regionLocationParts 真实产物为
// 「展示串=中国·阿里、province 空」，拆串会把 ISP 当省名（同文件
// enrichIPLocationParts 注释已把该形态定为回归）。
//
// 夹具直接写归属地缓存（一次查询同时产出展示与结构化两视图，见
// loadEnrichLocation），避免依赖二进制 xdb 夹具；两视图与
// regionLocationParts 的真实产物逐字一致。
func TestThreatScreenAttackFlowUsesStructuredProvince(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	if err := services.AcquireThreatScreenAttackFlowLease("flow-province-test", time.Minute, 1); err != nil {
		t.Fatalf("lease: %v", err)
	}

	const (
		ispOnlyIP  = "8.8.4.4" // xdb ISP-only 段：中国|0|0|阿里|CN
		provinceIP = "1.2.3.4" // xdb 完整段：中国|广东省|深圳市|电信|CN
	)
	generation := services.GeoIPDataGeneration()
	seed := func(ip, location, country, province string) {
		enrichLocationCache.Lock()
		enrichLocationCache.entries[ip] = enrichLocationCacheEntry{
			location: location, country: country, province: province, generation: generation,
		}
		enrichLocationCache.Unlock()
	}
	seed(ispOnlyIP, "中国·阿里", "中国", "")
	seed(provinceIP, "中国·广东·深圳·电信", "中国", "广东")
	t.Cleanup(func() {
		enrichLocationCache.Lock()
		delete(enrichLocationCache.entries, ispOnlyIP)
		delete(enrichLocationCache.entries, provinceIP)
		enrichLocationCache.Unlock()
	})

	ispSeq := services.ThreatScreenAttackFlowAppendForTest(ispOnlyIP, "blocked", "942100")
	provinceSeq := services.ThreatScreenAttackFlowAppendForTest(provinceIP, "blocked", "942100")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/overview/threat-screen/attack-flow", (&Handlers{}).GetThreatScreenAttackFlow)
	recorder := getRequest(t, router, "/security/overview/threat-screen/attack-flow")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Events []struct {
				Seq      uint64 `json:"seq"`
				Country  string `json:"country"`
				Province string `json:"province"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	bySeq := make(map[uint64]string, len(payload.Data.Events))
	for _, event := range payload.Data.Events {
		bySeq[event.Seq] = event.Province
	}
	if got, ok := bySeq[ispSeq]; !ok {
		t.Fatalf("ISP-only 事件（seq=%d）未出现在光流：%s", ispSeq, recorder.Body.String())
	} else if got != "" {
		t.Fatalf("ISP-only 归属地 province=%q, want 空（阿里是 ISP 不是省，拆展示串回归）", got)
	}
	if got := bySeq[provinceSeq]; got != "广东" {
		t.Fatalf("完整归属地 province=%q, want 广东（结构化单源未被消费）", got)
	}
}
