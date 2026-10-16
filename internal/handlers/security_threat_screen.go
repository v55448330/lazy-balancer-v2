package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 威胁大屏（ThreatScreen）数据端点——只读聚合，复用安全总览查询核心
// （security_events 单表 + categorizeAttack 家族单源 + enrichIPLocation 归属
// 地单源），从节点可读（不挂 requireMaster）。

// threatScreenMaxHours hours 参数上限（30 天）——超出回退默认 24h，与非法
// 值同口径（大屏固定 24h 消费，参数仅为后续扩展保留）。
const threatScreenMaxHours = 24 * 30

// threatActiveSourceWindow 活跃攻击源窗口（设计定稿）：近 10 分钟去重 client_ip。
const threatActiveSourceWindow = 10 * time.Minute

// threatCountryFromLocation 从 ip_location 文本（「国家·省州·城市·ISP」，
// formatIP2RegionLocation 产物）提取国家首段。分隔符「·」为多字节 UTF-8，
// 必须 strings.Index 按子串定位（按字节扫描会切进分隔符中间产出脏首段）。
// 空归属返回 ""（上游跳过）。
func threatCountryFromLocation(location string) string {
	if idx := strings.Index(location, "·"); idx >= 0 {
		return location[:idx]
	}
	return location
}

// aggregateThreatCountries 把「IP → 命中数」聚合为「国家 → 命中数」：归属地
// 经 lookup 逐 IP 富化（调用方传 enrichIPLocation——BufferCache 已按 IP 去重
// 查询，xb 缺失返回 "" 的 IP 整体跳过，不产出空键）。
func aggregateThreatCountries(hits map[string]int, lookup func(string) string) map[string]int {
	countries := make(map[string]int, len(hits))
	for ip, count := range hits {
		country := threatCountryFromLocation(lookup(ip))
		if country == "" {
			continue
		}
		countries[country] += count
	}
	return countries
}

// aggregateChinaProvinces 国内省份聚合（v3 大屏省级下钻数据源）：仅首段=
// 「中国」的归属地参与，取省段（第 2 段，formatIP2RegionLocation 国内分支
// 已归一为 ip2RegionShortenName 形态）；省段为空跳过（不产出空键），海外
// 事件整体不参与。与国家计数共享同一 ipHits（单次遍历伴生聚合，零额外查询）。
func aggregateChinaProvinces(hits map[string]int, lookup func(string) string) map[string]int {
	provinces := make(map[string]int, len(hits)/2+1)
	for ip, count := range hits {
		parts := strings.SplitN(lookup(ip), "·", 3)
		if len(parts) < 2 || parts[0] != "中国" || parts[1] == "" {
			continue
		}
		provinces[parts[1]] += count
	}
	return provinces
}

// topThreatEntries 计数 map → 前 n 条（值降序；同值按名称升序——确定性输出，
// 大屏 30s 轮询重渲染名次不抖动）。
func topThreatEntries(counts map[string]int, n int) []models.SecurityAttackType {
	entries := make([]models.SecurityAttackType, 0, len(counts))
	for name, value := range counts {
		entries = append(entries, models.SecurityAttackType{Name: name, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Value != entries[j].Value {
			return entries[i].Value > entries[j].Value
		}
		return entries[i].Name < entries[j].Name
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// ipSource 公网 IP 回显源（v5 多源回退链，用户指定国内可达优先）：
// 任一源成功（首个合法 IPv4/IPv6）即用；每源独立 3.5s 超时、整体 10s 上限；
// 源名随响应/审计披露便于排障。GitHub 加速代理仅支持 GitHub 路径
// （crshttp.go 契约），不适用本类回显服务，直连。
type ipSource struct {
	name      string
	url       string
	multiLine bool // 文本含附加信息（需正则提取 IP），false=整行即 IP
}

var publicIPSources = []ipSource{
	{name: "myip.ipip.net", url: "https://myip.ipip.net", multiLine: true},
	{name: "cip.cc", url: "https://cip.cc", multiLine: true},
	{name: "ipv4.icanhazip.com", url: "https://ipv4.icanhazip.com"},
	{name: "api.ipify.org", url: "https://api.ipify.org"},
}

var ipExtractPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// fetchPublicIP 出站获取本机公网 IP：多源按序回退（整体 10s 上限），返回
// (IP, 源名)。显式按钮触发、无后台轮询。测试经包级缝注入。
var fetchPublicIP = func() (ip string, source string, err error) {
	client := &http.Client{Timeout: 3500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for _, src := range publicIPSources {
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("整体超时")
			}
			break
		}
		ip, err := fetchIPFromSource(client, src)
		if err == nil {
			return ip, src.name, nil
		}
		lastErr = err
		services.Logf("warn", "threat-screen site detect: source %s failed: %v", src.name, err)
	}
	return "", "", lastErr
}

func fetchIPFromSource(client *http.Client, source ipSource) (string, error) {
	resp, err := client.Get(source.url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("响应 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(body))
	var ip string
	if source.multiLine {
		if m := ipExtractPattern.FindString(text); m != "" {
			ip = m
		}
	} else {
		ip = text
	}
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("未解析到合法 IP")
	}
	return ip, nil
}

// locateSiteCoords 公网 IP → 归属地文本 → 经纬度（本地 xdb + 质心表派生表）：
// 国内取省短名质心、海外取国家质心；无法定位 ok=false（调用方走手动填写指引）。
var locateSiteCoords = func(ip string) (lat, lon float64, location string, ok bool) {
	location = enrichIPLocation(ip)
	if location == "" {
		return 0, 0, "", false
	}
	parts := strings.SplitN(location, "·", 3)
	if len(parts) == 0 || parts[0] == "" {
		return 0, 0, "", false
	}
	if parts[0] == "中国" {
		if len(parts) < 2 {
			return 0, 0, "", false
		}
		if c, found := threatScreenProvinceCentroids[parts[1]]; found {
			return c[1], c[0], location, true
		}
		return 0, 0, "", false
	}
	if c, found := threatScreenCountryCentroids[parts[0]]; found {
		return c[1], c[0], location, true
	}
	return 0, 0, "", false
}

// threatRollupMu 懒固化互斥（每分钟一次 DELETE+INSERT，幂等）。
var threatRollupMu sync.Mutex

// ensureThreatRollup 按需固化 rollup 到 now-1 分钟（幂等、自愈）：
// 每分钟把原始表按 (国家,省,族,规则,动作) 聚合写入 security_event_rollup。
// 归属地/攻击族在固化时算一次（enrichIPLocation/categorizeAttack 单源），
// 之后大屏全部聚合只扫 rollup（PK 前缀 minute），与原始表规模解耦。
// 追溯上限 24h（更早的洞不补——原始表可能已被保留策略清掉）。
func ensureThreatRollup() error {
	threatRollupMu.Lock()
	defer threatRollupMu.Unlock()
	if db.MetricsDB == nil {
		return errors.New("metrics db unavailable")
	}
	now := time.Now().UTC()
	lastComplete := now.Add(-time.Minute).Truncate(time.Minute)
	currentMinute := now.Truncate(time.Minute)
	var maxMinute string
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(MAX(minute), '') FROM security_event_rollup`).Scan(&maxMinute); err != nil {
		return err
	}
	var from time.Time
	if maxMinute == "" {
		from = lastComplete.Add(-24 * time.Hour)
	} else {
		parsed, err := time.ParseInLocation("2006-01-02 15:04", maxMinute, time.UTC)
		if err != nil {
			return err
		}
		from = parsed.Add(time.Minute)
	}
	// 增量回填（完整分钟，幂等）+ 当前不完整分钟恒重固化（recent_rate 等
	// 「最近 N 分钟」口径需要覆盖当前分钟；单分钟聚合有界，成本可忽略）
	ranges := make([]time.Time, 0, 64)
	for m := from; !m.After(lastComplete); m = m.Add(time.Minute) {
		ranges = append(ranges, m)
	}
	if len(ranges) == 0 || ranges[len(ranges)-1] != currentMinute {
		ranges = append(ranges, currentMinute)
	}
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		return err
	}
	for _, m := range ranges {
		if err := threatFixMinute(tx, m); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// threatFixMinute 单分钟固化：DELETE+INSERT 幂等；保留/私网 IP 排除；归属
// 地/攻击族在此算一次（enrichIPLocation/categorizeAttack 单源）。
func threatFixMinute(tx *sql.Tx, m time.Time) error {
	next := m.Add(time.Minute)
	if _, err := tx.Exec(`DELETE FROM security_event_rollup WHERE minute = ?`, m.Format("2006-01-02 15:04")); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT client_ip, COALESCE(NULLIF(rule_name,''), COALESCE(rule_triggered,'')), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), action, COUNT(*)
		FROM security_events
		WHERE event_time >= ? AND event_time < ?
		GROUP BY client_ip, 2, rule_triggered, rule_msg, action`, m.Format("2006-01-02 15:04:05"), next.Format("2006-01-02 15:04:05"))
	if err != nil {
		return err
	}
	type key struct{ country, province, family, rule, action string }
	agg := map[key]int{}
	for rows.Next() {
		var ip, ruleName, ruleTriggered, ruleMsg, action string
		var count int
		if err := rows.Scan(&ip, &ruleName, &ruleTriggered, &ruleMsg, &action, &count); err != nil {
			rows.Close()
			return err
		}
		if isReservedIP(ip) {
			continue
		}
		country, province := threatLocationParts(enrichIPLocation(ip))
		k := key{country, province, categorizeAttack(ruleTriggered, ruleMsg), ruleName, action}
		agg[k] += count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	minuteStr := m.Format("2006-01-02 15:04")
	stmt, err := tx.Prepare(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	for k, count := range agg {
		if _, err := stmt.Exec(minuteStr, k.country, k.province, k.family, k.rule, k.action, count); err != nil {
			stmt.Close()
			return err
		}
	}
	return stmt.Close()
}

// threatLocationParts 归属地字符串 → (国家, 省简称)；中国省供省级聚合。
func threatLocationParts(location string) (string, string) {
	parts := strings.SplitN(location, "·", 3)
	country := ""
	province := ""
	if len(parts) > 0 {
		country = strings.TrimSpace(parts[0])
	}
	if country == "中国" && len(parts) > 1 {
		province = strings.TrimSpace(parts[1])
	}
	return country, province
}

// GetThreatScreenTraffic GET /security/overview/threat-screen/traffic
// 大屏实时流量代理（Plan B）：读 Caddy admin 自定义端点 /lb/traffic-stats
// （caddygeoip per-country 原子计数器，attack/normal 双桶累计），国名翻译
// 中文（geoipnames 单源）+ Reserved/空键过滤；admin 不可达 200 空数据降级
// （available=false）——大屏 1-2s 轮询容忍瞬时不可达，不 500。超时 2s。
func (h *Handlers) GetThreatScreenTraffic(c *gin.Context) {
	type trafficCountry struct {
		Attack uint64 `json:"attack"`
		Normal uint64 `json:"normal"`
	}
	type trafficSnapshot struct {
		Countries map[string]trafficCountry `json:"countries"`
		SampleN   uint32                    `json:"sample_n"`
	}
	empty := gin.H{"countries": map[string]trafficCountry{}, "available": false, "sample_n": 1}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/lb/traffic-stats")
	if err != nil {
		services.Logf("warn", "threat-screen traffic: admin fetch failed: %v", err)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		services.Logf("warn", "threat-screen traffic: admin status %d", resp.StatusCode)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty})
		return
	}
	var snap trafficSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snap); err != nil {
		services.Logf("warn", "threat-screen traffic: decode failed: %v", err)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty})
		return
	}
	out := make(map[string]trafficCountry, len(snap.Countries))
	for country, entry := range snap.Countries {
		if country == "" || country == "Reserved" {
			continue
		}
		name := geoipnames.CountryChinese(country)
		if name == country && country != "中国" {
			// 未收录英文名原样保留（前端质心表 miss 走兜底位）
			name = country
		}
		out[name] = entry
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"countries": out,
		"available": true,
		"sample_n":  snap.SampleN,
	}})
}

// DetectThreatScreenSite POST /security/overview/threat-screen/site-detect
// 大屏本站坐标自动检测：公网 IP → 本地归属地 → 经纬度。定位失败 422 并指引
// 手动填写（保留既有写侧校验路径）；出站失败 502 友好文案。
func (h *Handlers) DetectThreatScreenSite(c *gin.Context) {
	ip, source, err := fetchPublicIP()
	if err != nil {
		services.Logf("warn", "threat-screen site detect: fetch public ip failed: %v", err)
		recordAudit(c, "检测失败", "大屏坐标", services.FormatAuditDetail("公网 IP 获取失败", services.AuditResultPart("failure")))
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: "公网 IP 获取失败（离线或超时），请检查网络后重试"})
		return
	}
	lat, lon, location, ok := locateSiteCoords(ip)
	if !ok {
		services.Logf("warn", "threat-screen site detect: ip %s (via %s) location unresolvable", ip, source)
		recordAudit(c, "检测失败", "大屏坐标", services.FormatAuditDetail("归属地无法定位: "+ip+"（源 "+source+"）", services.AuditResultPart("failure")))
		c.JSON(http.StatusUnprocessableEntity, models.APIResponse{Code: 422, Message: "归属地无法定位（GeoIP 库缺失或网段未知），请手动填写坐标"})
		return
	}
	recordAudit(c, "自动检测", "大屏坐标", services.FormatAuditDetail(location+" ("+ip+"，源 "+source+")"))
	// APIResponse 包装（全站契约）：前端 request 封装按 data 字段取值，
	// 裸 JSON 会被消费方判「响应缺失」误走失败分支（v5 实测修复）。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ip": ip, "location": location, "lat": lat, "lon": lon, "source": source}})
}

// GetSecurityThreatScreen GET /security/overview/threat-screen?hours=24
// 返回大屏聚合：窗口总量/拦截率/限流拦截数（Caddy metrics 429，重载口径）/
// 活跃攻击源（近 10min 去重）/ 国家计数 map（ip_location 首段，空归属跳过）/
// Top5 攻击国家与攻击类型。任一安全库查询失败显式 500（R35 D2：全零大屏与
// 「无攻击」不可区分）；Caddy metrics 抓取失败 500「限流拦截数据不可用」
// （与 GetSecurityRateLimitBlocks 同口径）。
func (h *Handlers) GetSecurityThreatScreen(c *gin.Context) {
	hours := 24
	if raw := c.Query("hours"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= threatScreenMaxHours {
			hours = n
		}
	}
	zero := func() gin.H {
		return gin.H{
			"hours":            hours,
			"window_start":     "",
			"total_events":     0,
			"blocked_events":   0,
			"block_rate":       0.0,
			"ratelimit_blocks": 0.0,
			"active_sources":   0,
			"countries":        map[string]int{},
			"china_provinces":  map[string]int{},
			"top_countries":    []models.SecurityAttackType{},
			"top_attack_types": []models.SecurityAttackType{},
		}
	}
	if db.MetricsDB == nil {
		// MetricsDB 未装配：零值面板 200 而非 panic（P5-4 家族口径）
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: zero()})
		return
	}

	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Second).Format("2006-01-02 15:04:05")
	activeSince := time.Now().UTC().Add(-threatActiveSourceWindow).Truncate(time.Second).Format("2006-01-02 15:04:05")

	// 任一查询失败显式报错（R35 D2 单错误收敛，trackErr 同 GetSecurityOverview）
	var firstErr error
	trackErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// v2.3.8 rollup 路径：懒固化后单次扫描 rollup 产出全部维度（总量/拦截/
	// 国家/省/攻击族/规则/小时——原 5 条原始表窗口扫描合并为 1 条 rollup 扫
	// 描，与原始表规模解耦）。保留/私网已在固化时排除（口径不变）。
	if err := ensureThreatRollup(); err != nil {
		trackErr(err)
	}
	var total, blocked int
	countries := map[string]int{}
	chinaProvinces := map[string]int{}
	familyCounts := map[string]int{}
	ruleCounts := map[string]int{}
	sinceMinute := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Minute).Format("2006-01-02 15:04")
	loc := services.CurrentLocation()
	_, offset := time.Now().In(loc).Zone()
	hourly := make([]models.SecurityAttackType, 24)
	for i := range hourly {
		hourly[i] = models.SecurityAttackType{Name: strconv.Itoa(i), Value: 0}
	}
	if rollRows, err := db.MetricsDB.Query(`SELECT minute, country, province, family, rule, action, count FROM security_event_rollup WHERE minute >= ?`, sinceMinute); err != nil {
		trackErr(err)
	} else {
		for rollRows.Next() {
			var minute, country, province, family, rule, action string
			var count int
			trackErr(rollRows.Scan(&minute, &country, &province, &family, &rule, &action, &count))
			total += count
			if action == "blocked" {
				blocked += count
			}
			if country != "" {
				countries[country] += count
			}
			if province != "" {
				chinaProvinces[province] += count
			}
			familyCounts[family] += count
			if rule != "" {
				ruleCounts[rule] += count
			}
			// 小时直方：rollup 分钟串为 UTC，按配置时区偏移取小时
			mt, err := time.ParseInLocation("2006-01-02 15:04", minute, time.UTC)
			if err == nil {
				h := mt.Add(time.Duration(offset) * time.Second).Hour()
				if h >= 0 && h < 24 {
					hourly[h].Value += count
				}
			}
		}
		trackErr(rollRows.Err())
		rollRows.Close()
	}
	// 活跃攻击源：近 10min 去重 client_ip，保留/私网排除（与总量同口径）
	activeSources := 0
	if activeRows, err := db.MetricsDB.Query(`SELECT client_ip FROM security_events WHERE event_time >= ? GROUP BY client_ip`, activeSince); err != nil {
		trackErr(err)
	} else {
		for activeRows.Next() {
			var ip string
			trackErr(activeRows.Scan(&ip))
			if !isReservedIP(ip) {
				activeSources++
			}
		}
		trackErr(activeRows.Err())
		activeRows.Close()
	}
	if firstErr != nil {
		services.Logf("error", "threat-screen query failed: %v", firstErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁大屏数据查询失败"})
		return
	}

	// 限流拦截：Caddy /metrics 429 总计（与 GetSecurityRateLimitBlocks 同源；
	// 抓取失败 500——「指标不可达」与「暂无限流拦截」必须可区分）
	blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
	if err != nil {
		services.Logf("error", "threat-screen scrape rate-limit blocks failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "限流拦截数据不可用"})
		return
	}
	var ratelimit float64
	for _, block := range blocks {
		ratelimit += block.Count
	}

	blockRate := 0.0
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
		// 一位小数（百分比展示口径）
		blockRate = float64(int(blockRate*10+0.5)) / 10
	}
	// recent_rate：近 5 分钟 blocked/min（rollup 单前缀扫描；logged 不计）
	since5Minute := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Minute).Format("2006-01-02 15:04")
	blocked5 := 0
	trackErr(db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute >= ? AND action='blocked'`, since5Minute).Scan(&blocked5))
	recentRate := float64(int(float64(blocked5)/5.0*10+0.5)) / 10
	services.Logf("debug", "ZZ rate: since5=%s blocked5=%d recentRate=%v", since5Minute, blocked5, recentRate)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"hours":            hours,
		"window_start":     since,
		"total_events":     total,
		"blocked_events":   blocked,
		"block_rate":       blockRate,
		"ratelimit_blocks": ratelimit,
		"active_sources":   activeSources,
		"countries":        countries,
		"china_provinces":  chinaProvinces,
		"top_countries":    topThreatEntries(countries, 5),
		"top_attack_types": topThreatEntries(familyCounts, 5),
		"top_rules":        topThreatEntries(ruleCounts, 6),
		"hourly_hist":      hourly,
		"attack_type_share": func() []models.SecurityAttackType {
			share := topThreatEntries(familyCounts, len(familyCounts))
			if share == nil {
				return []models.SecurityAttackType{}
			}
			return share
		}(),
		"recent_rate": recentRate,
	}})
}

// GetSecurityEventFeed GET /security/events/feed?since_id=N&limit=50
// 大屏增量事件流：id 降序、WHERE id > since_id 游标翻页（无重无漏），含归属
// 地/攻击族富化（enrichIPLocation + categorizeAttack 单源）。limit 缺省 50、
// 上限 200。
func (h *Handlers) GetSecurityEventFeed(c *gin.Context) {
	const (
		defaultLimit = 50
		maxLimit     = 200
	)
	sinceID := int64(0)
	if raw := c.Query("since_id"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			sinceID = n
		}
	}
	limit := defaultLimit
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	empty := func() gin.H {
		return gin.H{"events": []models.SecurityEventFeedItem{}, "since_id": sinceID, "limit": limit}
	}
	if db.MetricsDB == nil {
		// MetricsDB 未装配：空列表 200 而非 panic（P5-4 家族口径，键与成功路径同形状）
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty()})
		return
	}
	rows, err := db.MetricsDB.Query(`SELECT id, event_time, client_ip, action, COALESCE(rule_name,''), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COALESCE(event_type,''), COALESCE(duration_us,0), COALESCE(anomaly_score,0)
		FROM security_events WHERE id > ? ORDER BY id DESC LIMIT ?`, sinceID, limit)
	if err != nil {
		services.Logf("error", "security event feed: query failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}
	defer rows.Close()
	events := make([]models.SecurityEventFeedItem, 0, limit)
	for rows.Next() {
		var e models.SecurityEventFeedItem
		var ruleTriggered, ruleMsg string
		// Scan 失败必须中止（R35 D3：部分零值行不得当真实事件返回）
		if err := rows.Scan(&e.ID, &e.EventTime, &e.ClientIP, &e.Action, &e.RuleName, &ruleTriggered, &ruleMsg, &e.EventType, &e.DurationUs, &e.AnomalyScore); err != nil {
			services.Logf("error", "security event feed: scan failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
			return
		}
		e.IPLocation = enrichIPLocation(e.ClientIP)
		// 保留/私网 IP 不进大屏事件流（v4 裁定，与聚合口径一致）；游标语义
		// 不受影响——since_id 恒为已消费最大 id，被过滤行只是跳过。
		if isReservedIP(e.ClientIP) {
			continue
		}
		e.AttackType = categorizeAttack(ruleTriggered, ruleMsg)
		e.RuleTrigged = ruleTriggered
		e.TriggerType = triggerTypeForRule(ruleTriggered)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		services.Logf("error", "security event feed: rows iteration failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": events, "since_id": sinceID, "limit": limit}})
}

// triggerTypeForRule 触发类型显示映射（v2.3.8 单源）：阶段 id → 业务语义类型。
// 爬虫事件独立于地域拦截（豁免/伪装不再落「IP 访问控制」桶，消除歧义）；
// WAF 拆 CRS/自定义（10000-899999=自定义规则库、1000000+=合成自定义）；
// 429→限流、GeoIP 老 id:8 兼容。
func triggerTypeForRule(ruleTriggered string) string {
	n, err := strconv.Atoi(ruleTriggered)
	if err == nil {
		switch {
		case n >= 810000 && n < 850000, n >= 850000 && n < 900000:
			return "爬虫Bot"
		case n >= 800000 && n < 810000:
			return "地域拦截"
		case n >= 1000000:
			return "WAF·自定义"
		case n >= 10000 && n < 900000:
			return "WAF·自定义"
		case n >= 900000:
			return "WAF·CRS"
		}
	}
	switch ruleTriggered {
	case "429":
		return "限流"
	case "2", "4", "7":
		return "IP 访问控制"
	case "8":
		return "地域拦截"
	case "12":
		return "信任名单"
	case "14":
		return "威胁情报库"
	case "11":
		return "请求体异常"
	default:
		return "其他"
	}
}
