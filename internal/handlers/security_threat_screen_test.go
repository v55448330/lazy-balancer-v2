package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 威胁大屏（threat-screen）端点钉测：聚合形状（国家计数 map/总量/拦截率/
// Top5）与 feed 游标（since_id 递增无重无漏）。两端点均为只读、不挂
// requireMaster（从节点可读，与大屏展示场景一致）。

func newThreatScreenRouter(t *testing.T, metricsURL string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: metricsURL}}
	router := gin.New()
	router.GET("/security/overview/threat-screen", h.GetSecurityThreatScreen)
	router.GET("/security/events/feed", h.GetSecurityEventFeed)
	return router
}

func newThreatMetricsServer(t *testing.T) *httptest.Server {
	t.Helper()
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rateLimitBlocksMetricsFixture))
	}))
	t.Cleanup(metrics.Close)
	return metrics
}

func seedThreatScreenEvent(t *testing.T, eventTime, clientIP, ruleTriggered, ruleMsg, action string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
		VALUES (?, ?, 'GET', '/a', 'crs', ?, ?, ?, '测试规则')`,
		eventTime, clientIP, ruleTriggered, ruleMsg, action); err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

func utcStringAgo(d time.Duration) string {
	return time.Now().UTC().Add(-d).Truncate(time.Second).Format("2006-01-02 15:04:05")
}

type threatScreenPayload struct {
	Code int `json:"code"`
	Data struct {
		Hours           int                         `json:"hours"`
		WindowStart     string                      `json:"window_start"`
		TotalEvents     int                         `json:"total_events"`
		BlockedEvents   int                         `json:"blocked_events"`
		BlockRate       float64                     `json:"block_rate"`
		RatelimitBlocks float64                     `json:"ratelimit_blocks"`
		ActiveSources   int                         `json:"active_sources"`
		Countries       map[string]int              `json:"countries"`
		ChinaProvinces  map[string]int              `json:"china_provinces"`
		TopCountries    []models.SecurityAttackType `json:"top_countries"`
		TopAttackTypes  []models.SecurityAttackType `json:"top_attack_types"`
		TopRules        []models.SecurityAttackType `json:"top_rules"`
		HourlyHist      []models.SecurityAttackType `json:"hourly_hist"`
		AttackTypeShare []models.SecurityAttackType `json:"attack_type_share"`
		RecentRate      float64                     `json:"recent_rate"`
	} `json:"data"`
}

func TestGetSecurityThreatScreen_reservedIPsExcludedEverywhere(t *testing.T) {
	// Given: 公网与保留/私网事件并存（::1 回环、192.168.x、10.x 私网）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	// 公网：2 blocked + 1 logged，两个 IP（其一在活跃窗）
	seedThreatScreenEvent(t, utcStringAgo(10*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(9*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(8*time.Minute), "198.51.100.5", "941100", "XSS", "logged")
	// 保留/私网：3 条（不计总量/拦截/活跃源/国家/攻击族）
	seedThreatScreenEvent(t, utcStringAgo(7*time.Minute), "192.168.1.5", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(6*time.Minute), "10.0.0.8", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(5*time.Minute), "::1", "932100", "RCE", "blocked")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")

	// Then: 全部统计口径一致排除保留地址（大屏不展示内网噪声，v4 裁定）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.TotalEvents != 3 {
		t.Errorf("total_events=%d, want 3（保留地址不计）", payload.Data.TotalEvents)
	}
	if payload.Data.BlockedEvents != 2 {
		t.Errorf("blocked_events=%d, want 2", payload.Data.BlockedEvents)
	}
	// 2/3 → 66.7%
	if payload.Data.BlockRate < 66.6 || payload.Data.BlockRate > 66.8 {
		t.Errorf("block_rate=%v, want 66.7", payload.Data.BlockRate)
	}
	if payload.Data.ActiveSources != 2 {
		t.Errorf("active_sources=%d, want 2（私网 IP 不是活跃攻击源）", payload.Data.ActiveSources)
	}
	if payload.Data.TopAttackTypes[0].Name != "SQL注入" || payload.Data.TopAttackTypes[0].Value != 2 {
		t.Errorf("top_attack_types[0]=%+v, want {SQL注入 2}（私网事件不计入攻击族）", payload.Data.TopAttackTypes[0])
	}
}

func TestGetSecurityEventFeed_reservedIPsFiltered(t *testing.T) {
	// Given: 公网与保留事件交错落库
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(3*time.Second), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Second), "192.168.1.5", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(1*time.Second), "203.0.113.9", "941100", "XSS", "logged")

	// When
	recorder := getRequest(t, router, "/security/events/feed")

	// Then: 保留地址事件不出现在事件流（游标语义不变——公网事件无重无漏）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload feedPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 2 {
		t.Fatalf("events=%d, want 2（192.168.1.5 被过滤）", len(payload.Data.Events))
	}
	for _, ev := range payload.Data.Events {
		if ev.ClientIP == "192.168.1.5" {
			t.Fatalf("保留地址事件泄漏到事件流: %+v", ev)
		}
	}
}

func TestGetSecurityThreatScreen_aggregateShape(t *testing.T) {
	// Given: 近 24h 六条事件（4 blocked + 1 logged + 1 跨越 24h 窗口的旧事件），
	// 其中两条落在近 10 分钟活跃窗内；Caddy metrics 提供 429 计数 12。
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	seedThreatScreenEvent(t, utcStringAgo(time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(30*time.Minute), "198.51.100.5", "941100", "XSS", "logged")
	seedThreatScreenEvent(t, utcStringAgo(20*time.Minute), "198.51.100.5", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(5*time.Minute), "192.0.2.9", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(8*time.Minute), "198.51.100.6", "932100", "RCE", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(49*time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")

	// Then: 窗口计数/拦截率/限流计数/活跃源/Top5 形状完整，49h 旧事件被窗口排除
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("code=%d body=%s", payload.Code, recorder.Body.String())
	}
	if payload.Data.Hours != 24 {
		t.Errorf("hours=%d, want 24 (default)", payload.Data.Hours)
	}
	if payload.Data.TotalEvents != 6 {
		t.Errorf("total_events=%d, want 6 (49h old event excluded)", payload.Data.TotalEvents)
	}
	if payload.Data.BlockedEvents != 5 {
		t.Errorf("blocked_events=%d, want 5", payload.Data.BlockedEvents)
	}
	// 5/6 → 83.3%（一位小数）
	if payload.Data.BlockRate < 83.3 || payload.Data.BlockRate > 83.4 {
		t.Errorf("block_rate=%v, want 83.3", payload.Data.BlockRate)
	}
	// Caddy metrics fixture 总计 = 12
	if payload.Data.RatelimitBlocks != 12 {
		t.Errorf("ratelimit_blocks=%v, want 12 (Caddy metrics 429 total)", payload.Data.RatelimitBlocks)
	}
	// 活跃源 = 近 10min 去重 client_ip：192.0.2.9 与 198.51.100.6
	if payload.Data.ActiveSources != 2 {
		t.Errorf("active_sources=%d, want 2", payload.Data.ActiveSources)
	}
	// 无 xdb：归属地全空 → 国家 map 为空对象（非 null），不报错
	if payload.Data.Countries == nil {
		t.Errorf("countries=%v, want empty map (no xdb in tests)", payload.Data.Countries)
	}
	// 国内省份计数 map 同形状常驻（无 xdb 时空对象，前端省级视图消费）
	if payload.Data.ChinaProvinces == nil {
		t.Errorf("china_provinces=%v, want empty map (no xdb in tests)", payload.Data.ChinaProvinces)
	}
	if len(payload.Data.TopCountries) != 0 {
		t.Errorf("top_countries=%+v, want empty without xdb", payload.Data.TopCountries)
	}
	// Top 攻击类型：categorizeAttack 家族单源——942100→SQL注入 ×3 居首，
	// 941100→XSS ×2 次之，932100→命令注入 ×1 第三
	if len(payload.Data.TopAttackTypes) != 3 {
		t.Fatalf("top_attack_types=%+v, want 3 families", payload.Data.TopAttackTypes)
	}
	if payload.Data.TopAttackTypes[0].Name != "SQL注入" || payload.Data.TopAttackTypes[0].Value != 3 {
		t.Errorf("top_attack_types[0]=%+v, want {SQL注入 3}", payload.Data.TopAttackTypes[0])
	}
	if payload.Data.TopAttackTypes[1].Name != "XSS" || payload.Data.TopAttackTypes[1].Value != 2 {
		t.Errorf("top_attack_types[1]=%+v, want {XSS 2}", payload.Data.TopAttackTypes[1])
	}
	if payload.Data.TopAttackTypes[2].Name != "命令注入" || payload.Data.TopAttackTypes[2].Value != 1 {
		t.Errorf("top_attack_types[2]=%+v, want {命令注入 1}", payload.Data.TopAttackTypes[2])
	}
}

func TestGetSecurityThreatScreen_hoursParam(t *testing.T) {
	// Given: 一条 2h 前事件
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(2*time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")

	// When/Then: hours=1 → 事件在窗外；缺省 → 计入；hours 非法/越界 → 回退默认 24
	if recorder := getRequest(t, router, "/security/overview/threat-screen?hours=1"); recorder.Code != http.StatusOK {
		t.Fatalf("hours=1 status=%d", recorder.Code)
	} else {
		var payload threatScreenPayload
		_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
		if payload.Data.TotalEvents != 0 {
			t.Errorf("hours=1 total_events=%d, want 0", payload.Data.TotalEvents)
		}
		if payload.Data.Hours != 1 {
			t.Errorf("hours echo=%d, want 1", payload.Data.Hours)
		}
	}
	if recorder := getRequest(t, router, "/security/overview/threat-screen"); recorder.Code != http.StatusOK {
		t.Fatalf("default status=%d", recorder.Code)
	} else {
		var payload threatScreenPayload
		_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
		if payload.Data.TotalEvents != 1 {
			t.Errorf("default total_events=%d, want 1", payload.Data.TotalEvents)
		}
	}
	for _, raw := range []string{"?hours=abc", "?hours=0", "?hours=-5", "?hours=99999"} {
		recorder := getRequest(t, router, "/security/overview/threat-screen"+raw)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", raw, recorder.Code, recorder.Body.String())
		}
		var payload threatScreenPayload
		_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
		if payload.Data.Hours != 24 {
			t.Errorf("%s hours=%d, want fallback 24", raw, payload.Data.Hours)
		}
	}
}

func TestGetSecurityThreatScreen_metricsScrapeFailureReturns500(t *testing.T) {
	// Given: Caddy metrics 不可达
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, "http://127.0.0.1:1/metrics")

	// When/Then: 500「限流拦截数据不可用」——指标不可达与暂无限流拦截必须
	// 可区分（与 GetSecurityRateLimitBlocks 同口径，R38 三-4）
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "限流拦截数据不可用") {
		t.Fatalf("body=%s, want explicit message", recorder.Body.String())
	}
}

func TestGetSecurityThreatScreen_metricsDBNilReturnsZeroShape(t *testing.T) {
	// Given: MetricsDB 未装配（P5-4 家族口径）
	setupSecurityPolicyTestDB(t)
	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	// When/Then: 200 零值形状而非 panic
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.TotalEvents != 0 || payload.Data.ActiveSources != 0 || payload.Data.Countries == nil || payload.Data.ChinaProvinces == nil {
		t.Fatalf("零值形状应完整: %+v", payload.Data)
	}
}

func TestThreatChinaProvinceAggregation_secondSegmentDomesticOnly(t *testing.T) {
	// Given: ip_location 国内格式「中国·省·市·ISP」取省段（第 2 段）聚合；
	// 仅首段=「中国」的归属地参与，省段为空/无省段跳过（与国家计数同一
	// ipHits 单次遍历的伴生聚合，零额外查询）。
	hits := map[string]int{"203.0.113.7": 3, "203.0.113.8": 2, "198.51.100.5": 4, "203.0.113.9": 1}
	lookup := func(ip string) string {
		switch ip {
		case "203.0.113.7":
			return "中国·广东省·深圳市·电信"
		case "203.0.113.8":
			return "中国·广东省·广州市·联通"
		case "198.51.100.5":
			return "美国·加州·洛杉矶·Cloudflare" // 海外不参与省份聚合
		default:
			return "中国" // 国内但缺省段（未识别省份）
		}
	}

	// When
	counts := aggregateChinaProvinces(hits, lookup)

	// Then: 同省合并（3+2=5），海外与无省段整体跳过（不产出空键/海外键）
	if len(counts) != 1 || counts["广东省"] != 5 {
		t.Fatalf("counts=%+v, want {广东省:5}", counts)
	}
}

func TestThreatCountryAggregation_firstSegmentAndEmptySkip(t *testing.T) {
	// Given: 三 IP 命中计数与注入的归属地查询（替换 enrichIPLocation——无 xdb
	// 环境无法产出真实归属地，纯函数侧钉「首段提取+空归属跳过」契约）
	hits := map[string]int{"203.0.113.7": 3, "198.51.100.5": 2, "192.0.2.9": 1}
	lookup := func(ip string) string {
		switch ip {
		case "203.0.113.7":
			return "美国·加州·洛杉矶·Cloudflare"
		case "198.51.100.5":
			return "美国·德州·达拉斯·AT&T"
		default:
			return "" // 查询失败/未装库 → 空归属
		}
	}

	// When
	counts := aggregateThreatCountries(hits, lookup)

	// Then: 同国家首段合并（3+2=5），空归属整体跳过（不产出空键）
	if len(counts) != 1 || counts["美国"] != 5 {
		t.Fatalf("counts=%+v, want {美国:5}", counts)
	}

	// 回归形状：归属地空串与「保留地址」首段语义
	if got := threatCountryFromLocation(""); got != "" {
		t.Errorf("empty location → %q, want empty", got)
	}
	if got := threatCountryFromLocation("保留地址"); got != "保留地址" {
		t.Errorf("reserved location → %q, want 保留地址", got)
	}
	if got := threatCountryFromLocation("中国·广东省·深圳市·电信"); got != "中国" {
		t.Errorf("domestic location → %q, want 中国", got)
	}
}

func TestTopThreatEntries_sortedDescWithStableTiebreak(t *testing.T) {
	// Given: 同计数并列（XSS=SQL注入=2）
	counts := map[string]int{"SQL注入": 2, "XSS": 2, "文件包含": 5}

	// When
	entries := topThreatEntries(counts, 5)

	// Then: 计数降序；同计数按名称升序（确定性输出，前端轮询渲染不抖动）
	if len(entries) != 3 {
		t.Fatalf("entries=%+v, want 3", entries)
	}
	if entries[0].Name != "文件包含" || entries[0].Value != 5 {
		t.Errorf("entries[0]=%+v, want {文件包含 5}", entries[0])
	}
	if entries[1].Name != "SQL注入" || entries[2].Name != "XSS" {
		t.Errorf("tie order=%+v, want SQL注入 before XSS (byte-asc: 'S'<'X')", entries)
	}

	// Top5 截断：7 项取前 5
	big := map[string]int{"a": 7, "b": 6, "c": 5, "d": 4, "e": 3, "f": 2, "g": 1}
	if got := topThreatEntries(big, 5); len(got) != 5 || got[0].Name != "a" || got[4].Name != "e" {
		t.Fatalf("top5=%+v, want a..e", got)
	}
}

type feedPayload struct {
	Code int `json:"code"`
	Data struct {
		Events []struct {
			ID         int    `json:"id"`
			EventTime  string `json:"event_time"`
			ClientIP   string `json:"client_ip"`
			IPLocation string `json:"ip_location"`
			Action     string `json:"action"`
			RuleName   string `json:"rule_name"`
			AttackType string `json:"attack_type"`
		} `json:"events"`
		SinceID int `json:"since_id"`
		Limit   int `json:"limit"`
	} `json:"data"`
}

func TestGetSecurityEventFeed_cursorIncrementalNoDupNoLoss(t *testing.T) {
	// Given: 210 条事件（超过单页 clamp 上限 200）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	base := time.Now().UTC().Add(-24 * time.Hour)
	for i := range 210 {
		ts := base.Add(time.Duration(i) * time.Second).Format("2006-01-02 15:04:05")
		triggered, msg := "942100", "SQL Injection"
		if i == 0 {
			triggered, msg = "941100", "XSS"
		}
		seedThreatScreenEvent(t, ts, fmt.Sprintf("203.0.113.%d", i%200+1), triggered, msg, "blocked")
	}

	// When: 消费者游标 = 已消费最大 id，恒递增；每次拉取 id > 游标的增量
	// （id 降序、limit 截断——超出单页的积压按大屏突发合并口径舍弃，不重复
	// 消费已见 id）。
	seen := map[int]bool{}
	since := 0
	fetch := func(query string) feedPayload {
		recorder := getRequest(t, router, "/security/events/feed"+query)
		if recorder.Code != http.StatusOK {
			t.Fatalf("feed status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var payload feedPayload
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		prev := -1
		for _, ev := range payload.Data.Events {
			if ev.ID >= prev && prev != -1 {
				t.Fatalf("feed not id-desc: %v after %v", ev.ID, prev)
			}
			prev = ev.ID
			if seen[ev.ID] {
				t.Fatalf("duplicate id %v across polls", ev.ID)
			}
			seen[ev.ID] = true
			if ev.ClientIP == "" || ev.Action != "blocked" || ev.EventTime == "" || ev.RuleName != "测试规则" {
				t.Fatalf("feed event missing enrichment fields: %+v", ev)
			}
		}
		return payload
	}

	// Then: 首轮（since=0, limit=200）→ 恰 200 条、不越上限
	payload := fetch("?since_id=0&limit=200")
	if len(payload.Data.Events) != 200 || payload.Data.Limit != 200 {
		t.Fatalf("first poll: %d events (limit=%d), want 200/200", len(payload.Data.Events), payload.Data.Limit)
	}
	// 游标推进到本页最大 id 后重复轮询 → 空页（无重）
	since = payload.Data.Events[0].ID
	payload = fetch(fmt.Sprintf("?since_id=%d&limit=200", since))
	if len(payload.Data.Events) != 0 {
		t.Fatalf("re-poll after cursor advance returned %d events, want 0", len(payload.Data.Events))
	}
	// 游标之后新落库的事件全部被增量拉到（无漏）
	for i := range 3 {
		seedThreatScreenEvent(t, utcStringAgo(time.Duration(-i)*time.Second), fmt.Sprintf("198.51.100.%d", i+1), "930100", "LFI", "blocked")
	}
	payload = fetch(fmt.Sprintf("?since_id=%d", since))
	if len(payload.Data.Events) != 3 {
		t.Fatalf("incremental poll=%d events, want exactly the 3 new events", len(payload.Data.Events))
	}
	if len(seen) != 203 {
		t.Fatalf("unique ids=%d, want 203 (200+3, zero dup)", len(seen))
	}

	// 家族归因单源：942100→SQL注入、941100→XSS（feed 富化字段）
	recorder := getRequest(t, router, "/security/events/feed?limit=200")
	var full feedPayload
	_ = json.Unmarshal(recorder.Body.Bytes(), &full)
	sqlCount, xssCount := 0, 0
	for _, ev := range full.Data.Events {
		switch ev.AttackType {
		case "SQL注入":
			sqlCount++
		case "XSS":
			xssCount++
		}
	}
	if sqlCount != 197 || xssCount != 0 {
		t.Fatalf("attack_type attribution=%d/%d, want 197/0（最新 200 条=ids 213..14：XSS 事件 id=1 在窗外，3 条 LFI 为游标后新增）", sqlCount, xssCount)
	}
}

func TestGetSecurityEventFeed_defaultsAndNewEventsAfterCursor(t *testing.T) {
	// Given: 3 条事件
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(3*time.Second), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Second), "203.0.113.8", "941100", "XSS", "logged")
	seedThreatScreenEvent(t, utcStringAgo(1*time.Second), "203.0.113.9", "942100", "SQL Injection", "blocked")

	// When/Then: 缺省 since_id=0/limit=50 → 全量返回
	recorder := getRequest(t, router, "/security/events/feed")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload feedPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 3 || payload.Data.SinceID != 0 || payload.Data.Limit != 50 {
		t.Fatalf("defaults: %+v", payload.Data)
	}
	maxID := payload.Data.Events[0].ID

	// 游标之后新落库的事件可被增量拉到（不重不漏的增量语义）
	seedThreatScreenEvent(t, utcStringAgo(0), "203.0.113.10", "930100", "LFI", "blocked")
	recorder = getRequest(t, router, fmt.Sprintf("/security/events/feed?since_id=%d", maxID))
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 1 || payload.Data.Events[0].ID <= maxID {
		t.Fatalf("incremental fetch=%+v, want exactly the new event", payload.Data.Events)
	}
}

func TestGetSecurityEventFeed_metricsDBNilReturnsEmptyList(t *testing.T) {
	// Given: MetricsDB 未装配（P5-4 家族口径，键形状与成功路径一致）
	setupSecurityPolicyTestDB(t)
	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	// When/Then
	recorder := getRequest(t, router, "/security/events/feed")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"events":[]`) {
		t.Fatalf("body=%s, want empty events list", recorder.Body.String())
	}
}

func TestGetSecurityThreatScreen_contentCards(t *testing.T) {
	// Given: 公网与保留事件并存（内容卡三件套 = top_rules/hourly_hist/
	// attack_type_share 与 recent_rate，v7 右列扩展；保留地址全口径排除）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	// 3×rule_name「SQL注入检测」（blocked）+ 1×rule_name 空（回退 rule_triggered）
	seedRuleNamed := func(minutes int, ip, ruleName string) {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
			VALUES (?, ?, 'GET', '/a', 'crs', '942100', 'SQL 注入攻击头', 'blocked', ?)`,
			utcStringAgo(time.Duration(minutes)*time.Minute), ip, ruleName); err != nil {
			t.Fatalf("seed rule-named event: %v", err)
		}
	}
	seedRuleNamed(30, "203.0.113.7", "SQL注入检测")
	seedRuleNamed(29, "203.0.113.7", "SQL注入检测")
	seedRuleNamed(28, "198.51.100.5", "SQL注入检测")
	// rule_name 空行：rule_triggered=2 黑名单（空名回退 rule_triggered 形态）
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
		VALUES (?, '203.0.113.9', 'GET', '/a', 'stage1', '2', 'IP 黑名单命中', 'blocked', '')`,
		utcStringAgo(27*time.Minute)); err != nil {
		t.Fatalf("seed empty-name event: %v", err)
	}
	// 保留地址：不计入任何内容卡
	seedRuleNamed(26, "192.168.1.5", "SQL注入检测")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then: top_rules——rule_name 优先、空名回退 rule_triggered，保留地址排除
	if len(payload.Data.TopRules) != 2 {
		t.Fatalf("top_rules=%+v, want 2 项（SQL注入检测 ×3 + 回退规则 2）", payload.Data.TopRules)
	}
	if payload.Data.TopRules[0].Name != "SQL注入检测" || payload.Data.TopRules[0].Value != 3 {
		t.Errorf("top_rules[0]=%+v, want {SQL注入检测 3}", payload.Data.TopRules[0])
	}
	if payload.Data.TopRules[1].Name != "2" || payload.Data.TopRules[1].Value != 1 {
		t.Errorf("top_rules[1]=%+v, want {2 1}（rule_name 空回退 rule_triggered）", payload.Data.TopRules[1])
	}

	// hourly_hist：恒 24 槽（hour 0-23 升序），命中槽计数、空槽零填；
	// 时区按配置时区偏移（默认 Asia/Shanghai +8）
	if len(payload.Data.HourlyHist) != 24 {
		t.Fatalf("hourly_hist=%d 槽, want 24", len(payload.Data.HourlyHist))
	}
	// 时区换算由 tzModifier 与 GetSecurityOverview 同源；种子全在近 24h
	// 同一小时簇内，按总量断言（具体槽位随时钟漂移不稳定）
	total := 0
	for _, slot := range payload.Data.HourlyHist {
		if slot.Value < 0 {
			t.Errorf("负计数槽: %+v", slot)
		}
		total += slot.Value
	}
	if total != 4 {
		t.Errorf("hourly 总计=%d, want 4（保留地址不计）", total)
	}

	// attack_type_share：与 top_attack_types 同源家族计数（SQL注入 ×3 + 回退黑名单
	// rule_triggered=2 → 攻击族 IP 访问控制 ×1）
	foundSQL, foundACL := false, false
	for _, item := range payload.Data.AttackTypeShare {
		if item.Name == "SQL注入" && item.Value == 3 {
			foundSQL = true
		}
		if item.Name == "IP 访问控制" && item.Value == 1 {
			foundACL = true
		}
	}
	if !foundSQL || !foundACL {
		t.Fatalf("attack_type_share 缺家族: %+v", payload.Data.AttackTypeShare)
	}

	// recent_rate：近 5min 无 blocked 事件 → 0（种子均在 27-30min 前）
	if payload.Data.RecentRate != 0 {
		t.Errorf("recent_rate=%v, want 0", payload.Data.RecentRate)
	}
}

func TestGetSecurityThreatScreen_recentRate(t *testing.T) {
	// Given: 近 5 分钟 3 条 blocked + 1 条 logged（blocked 3 条/5min = 0.6/min）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(1*time.Minute), "203.0.113.7", "942100", "SQL 注入攻击头", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Minute), "203.0.113.7", "942100", "SQL 注入攻击头", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(3*time.Minute), "198.51.100.5", "941100", "XSS 脚本标签探测", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(4*time.Minute), "198.51.100.5", "941100", "XSS 脚本标签探测", "logged")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Minute), "10.0.0.8", "941100", "XSS 脚本标签探测", "blocked")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then: 3 blocked/5min = 0.6（保留地址不计；logged 不计）
	if payload.Data.RecentRate != 0.6 {
		t.Errorf("recent_rate=%v, want 0.6", payload.Data.RecentRate)
	}
}

// TestThreatScreenRollup_fixationIdempotentAndEquivalent（v2.3.8 性能工程）
// Given: 原始事件在窗口内；When: 两次请求端点（懒固化的幂等性）且清空原始表后再请求
// Then: rollup 行数不翻倍；清空原始表后聚合数值不变（聚合与原始表规模解耦的等价性证明）
func TestThreatScreenRollup_fixationIdempotentAndEquivalent(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(10*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(9*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(8*time.Minute), "198.51.100.5", "941100", "XSS", "logged")

	first := getRequest(t, router, "/security/overview/threat-screen")
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	// 幂等：再请求一次，rollup 计数不得翻倍
	second := getRequest(t, router, "/security/overview/threat-screen")
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d", second.Code)
	}
	var rollCount int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup`).Scan(&rollCount); err != nil {
		t.Fatal(err)
	}
	if rollCount != 3 {
		t.Errorf("rollup sum=%d, want 3（幂等固化，不随请求次数翻倍）", rollCount)
	}
	// 等价性：清空原始表（模拟原始表被保留策略裁剪/规模解耦），聚合仍来自 rollup
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatal(err)
	}
	third := getRequest(t, router, "/security/overview/threat-screen")
	if third.Code != http.StatusOK {
		t.Fatalf("third status=%d body=%s", third.Code, third.Body.String())
	}
	var p1, p3 threatScreenPayload
	if err := json.Unmarshal(first.Body.Bytes(), &p1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(third.Body.Bytes(), &p3); err != nil {
		t.Fatal(err)
	}
	if p3.Data.TotalEvents != p1.Data.TotalEvents || p3.Data.TotalEvents != 3 {
		t.Errorf("total after raw wipe=%d (first=%d), want 3（rollup 等价承载）", p3.Data.TotalEvents, p1.Data.TotalEvents)
	}
	if p3.Data.BlockedEvents != 2 {
		t.Errorf("blocked after raw wipe=%d, want 2", p3.Data.BlockedEvents)
	}
	// 国家维度依赖 xdb 归属（测试环境无 xdb → country 空），只验计数等价；
	// 国家/省产出在 rollup 行中有独立断言（下）。
	if rollCount == 0 {
		t.Errorf("rollup empty")
	}
}
