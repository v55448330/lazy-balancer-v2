package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"
)

// 连接详情端点（三源恒可用，2026-11-12：lb_reqmon 内存快照/连接过滤/聚合指标，
// 不读取访问日志、零磁盘 I/O）：
//   - 连接视图：netstat -tan 经「Caddy 流量判别」过滤——监听端口
//     （lb_rules.listen_port，客户端侧）+ 上游 host:port（upstreams 表，
//     反代侧），只显示真正经过 Caddy 反代的连接，不再展示系统全量 socket。
//   - 聚合指标：Caddy admin Prometheus（复用 caddyMetricsSnapshot 与
//     parseHostMetrics 单源），按域名请求总数/在途，弹框顶部聚合条。
//
// 四分类=连接态口径：established=活跃；time_wait=待关闭；closed=已关闭。
const connectionsListTTL = 1500 * time.Millisecond
const connectionsListMaxRows = 500
const connectionsReqWindow = time.Hour
const connectionsActiveWindow = time.Minute
const connectionsClosingWindow = 10 * time.Minute

type connectionEntry struct {
	Proto    string `json:"proto"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
	Category string `json:"category"` // established | time_wait | closed | listen(排除)
	Country  string `json:"country"`  // 远端归属地（enrichIPLocation）
}

// requestEntry 反代请求明细行（来自 lb_reqmon 内存环形快照）。
// domainStat 聚合指标行（Caddy Prometheus per-host）。
type domainStat struct {
	Host      string `json:"host"`
	Requests  int64  `json:"requests"`
	InFlight  int64  `json:"in_flight"`
	Status5xx int64  `json:"status_5xx"`
}

// requestEntry 逐请求观测行（lb_reqmon 内存快照投影）。
type requestEntry struct {
	Ts         int64   `json:"ts"`       // unix 毫秒
	Category   string  `json:"category"` // active | closing | closed（窗口映射）
	ClientIP   string  `json:"client_ip"`
	Country    string  `json:"country"`
	Method     string  `json:"method"`
	Proto      string  `json:"proto"`     // HTTP/1.1 | HTTP/2.0 | HTTP/3
	Scheme     string  `json:"scheme"`    // https | http
	RuleName   string  `json:"rule_name"` // 规则名（X-LB-Rule-ID→lb_rules.name 映射，空=caddy_id）
	UA         string  `json:"ua"`        // User-Agent（展示侧简化）
	Host       string  `json:"host"`
	URI        string  `json:"uri"`
	Status     int     `json:"status"`
	DurationMs float64 `json:"duration_ms"`
	Size       int64   `json:"size"`     // 响应字节
	ReqSize    int64   `json:"req_size"` // 请求字节（-1=流式）
}

type connectionsListPayload struct {
	Counts      map[string]int64  `json:"counts"`      // 四分类计数（请求视图=窗口；连接视图=连接态）
	ConnCounts  map[string]int64  `json:"conn_counts"` // 连接态计数（established/time_wait/closed）
	Requests    []requestEntry    `json:"requests"`    // lb_reqmon 快照（最新优先，500 行截断）
	Connections []connectionEntry `json:"connections"` // 恒有值（Caddy 流量过滤后）
	Domains     []domainStat      `json:"domains"`     // 聚合指标（采集失败时为空）
	ReqMon      bool              `json:"req_mon"`     // lb_reqmon 端点是否可用
	Truncated   bool              `json:"truncated"`
	GeneratedAt string            `json:"generated_at"`
}

// reqMonSnapshot lbreqmon admin 端点响应（契约与插件锁定）。
type reqMonSnapshot struct {
	Capacity int `json:"capacity"`
	Entries  []struct {
		Ts         int64   `json:"ts"`
		ClientIP   string  `json:"client_ip"`
		Method     string  `json:"method"`
		Proto      string  `json:"proto"`
		Scheme     string  `json:"scheme"`
		RuleID     string  `json:"rule_id"`
		UA         string  `json:"ua"`
		Host       string  `json:"host"`
		URI        string  `json:"uri"`
		Status     int     `json:"status"`
		DurationMs float64 `json:"duration_ms"`
		Size       int64   `json:"size"`
		ReqSize    int64   `json:"req_size"`
	} `json:"entries"`
}

// reqMonUnavailableUntil 端点缺失/不可达的负缓存（旧 Caddy 无端点=静默跳过，
// 与 l4-conn-stats 同容错口径）。
var (
	reqMonClient        = &http.Client{Timeout: 2 * time.Second}
	reqMonMu            sync.Mutex
	reqMonUnavailableAt time.Time
)

// fetchReqMonSnapshot 拉取 lb_reqmon 内存快照 → 请求明细（窗口分类+500 行
// 截断，最新优先）。失败返回 nil, false（负缓存 30s 吸收弹框 2s 轮询）。
func fetchReqMonSnapshot(adminURL string, now time.Time) ([]requestEntry, bool) {
	reqMonMu.Lock()
	unavailable := now.Before(reqMonUnavailableAt)
	reqMonMu.Unlock()
	if unavailable || adminURL == "" {
		return nil, false
	}
	resp, err := reqMonClient.Get(strings.TrimSuffix(adminURL, "/") + "/lb/reqmon/snapshot?limit=" + strconv.Itoa(connectionsListMaxRows))
	if err != nil {
		reqMonMarkUnavailable(now)
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		reqMonMarkUnavailable(now)
		return nil, false
	}
	var snap reqMonSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&snap); err != nil {
		reqMonMarkUnavailable(now)
		return nil, false
	}
	out := make([]requestEntry, 0, len(snap.Entries))
	for _, e := range snap.Entries {
		age := now.Sub(time.UnixMilli(e.Ts))
		if age < 0 || age > connectionsReqWindow {
			continue // 插件为环形覆盖（50k 上限），超窗不展示
		}
		category := "closed"
		switch {
		case age <= connectionsActiveWindow:
			category = "active"
		case age <= connectionsClosingWindow:
			category = "closing"
		}
		out = append(out, requestEntry{
			Ts: e.Ts, Category: category, ClientIP: e.ClientIP, Method: e.Method,
			Proto: e.Proto, Scheme: e.Scheme, RuleName: e.RuleID, UA: e.UA,
			Host: e.Host, URI: e.URI, Status: e.Status, DurationMs: e.DurationMs,
			Size: e.Size, ReqSize: e.ReqSize,
		})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Ts > out[b].Ts })
	if len(out) > connectionsListMaxRows {
		out = out[:connectionsListMaxRows]
	}
	return out, true
}

func reqMonMarkUnavailable(now time.Time) {
	reqMonMu.Lock()
	reqMonUnavailableAt = now.Add(30 * time.Second)
	reqMonMu.Unlock()
}

// ruleNameMap 规则 ID→显示名单源（lb_rules.name，回退 caddy_id；弹框刷新
// 一次一查，2s 轮询被 TTL 缓存吸收，无逐行放大）。
func ruleNameMap() map[string]string {
	m := map[string]string{}
	if db.DB == nil {
		return m
	}
	rows, err := db.DB.Query(`SELECT caddy_id, name FROM lb_rules`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil {
			m[id] = name
		}
	}
	return m
}

// joinRequestMetadata 请求明细叠加归属地（client_ip 去重批量）+ 规则名映射
// （X-LB-Rule-ID → lb_rules.name；2026-11-12 用户裁定：去 WAF 列，增反代数据）。
func joinRequestMetadata(entries []requestEntry) {
	ipsSet := map[string]struct{}{}
	for i := range entries {
		if entries[i].ClientIP != "" {
			ipsSet[entries[i].ClientIP] = struct{}{}
		}
	}
	ips := make([]string, 0, len(ipsSet))
	for ip := range ipsSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	names := ruleNameMap()
	for i := range entries {
		entries[i].Country = enrichIPLocation(entries[i].ClientIP)
		if id := entries[i].RuleName; id != "" {
			if n, ok := names[id]; ok && n != "" {
				entries[i].RuleName = n
			}
		}
	}
}

var (
	connectionsListMu       sync.Mutex
	connectionsListCache    connectionsListPayload
	connectionsListExpireAt time.Time
	connectionsListNegUntil time.Time
	connectionsListNegErr   error
	connectionsListGroup    singleflight.Group

	// upstreamResolveCache 上游域名→IP 解析缓存（反代侧判别：netstat 远端
	// 是 IP 而上游配置可能是域名；60s TTL 防 2s 轮询逐次 DNS）。
	upstreamResolveMu    sync.Mutex
	upstreamResolveCache map[string]upstreamResolveEntry
)

type upstreamResolveEntry struct {
	ips       map[string]struct{}
	expiresAt time.Time
}

// parseNetstatEntries netstat -tan 输出 → 连接明细（排除 LISTEN 行）。
// 分类映射：ESTABLISHED=established；TIME_WAIT=time_wait；
// CLOSE_WAIT/LAST_ACK/FIN_WAIT1/FIN_WAIT2/CLOSING=closed（终结态合计族）。
func parseNetstatEntries(output string) []connectionEntry {
	entries := []connectionEntry{}
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		if i == 0 && fields[0] == "Proto" {
			continue
		}
		state := strings.ReplaceAll(fields[5], "-", "_")
		category := ""
		switch state {
		case "ESTABLISHED":
			category = "established"
		case "TIME_WAIT":
			category = "time_wait"
		case "CLOSE_WAIT", "LAST_ACK", "FIN_WAIT1", "FIN_WAIT2", "CLOSING", "CLOSE":
			category = "closed"
		default:
			continue // LISTEN 等非连接行排除
		}
		entries = append(entries, connectionEntry{
			Proto:    fields[0],
			Local:    fields[3],
			Remote:   fields[4],
			State:    state,
			Category: category,
		})
	}
	return entries
}

// splitHostPortAddr "host:port"/"[v6]:port"/"::1:port 形态拆解（netstat 混合
// 输出容忍：IPv6 无括号形态按最后一个冒号切）。
func splitHostPortAddr(addr string) (string, int) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, 0
	}
	host := strings.Trim(strings.TrimSpace(addr[:idx]), "[]")
	port, _ := strconv.Atoi(addr[idx+1:])
	return host, port
}

// loadCaddyEndpoints Caddy 流量判别数据单源：监听端口（客户端侧）+ 上游
// host:port 集合（反代侧，含域名一次性解析缓存）。
func loadCaddyEndpoints() (map[int]struct{}, map[string]struct{}) {
	ports := map[int]struct{}{}
	upstreams := map[string]struct{}{}
	if db.DB == nil {
		return ports, upstreams
	}
	if rows, err := db.DB.Query(`SELECT listen_port FROM lb_rules`); err == nil {
		for rows.Next() {
			var p int
			if rows.Scan(&p) == nil && p > 0 {
				ports[p] = struct{}{}
			}
		}
		rows.Close()
	}
	type up struct {
		host string
		port int
	}
	var ups []up
	if rows, err := db.DB.Query(`SELECT u.host, u.port FROM upstreams u JOIN lb_rules r ON r.caddy_id = u.rule_id WHERE ` + services.UpstreamEnabledSQLPredicate + ` AND r.enabled = 1`); err == nil {
		for rows.Next() {
			var h string
			var p int
			if rows.Scan(&h, &p) == nil {
				ups = append(ups, up{h, p})
			}
		}
		rows.Close()
	}
	now := time.Now()
	upstreamResolveMu.Lock()
	if upstreamResolveCache == nil {
		upstreamResolveCache = map[string]upstreamResolveEntry{}
	}
	upstreamResolveMu.Unlock()
	for _, u := range ups {
		key := strings.ToLower(strings.TrimSpace(u.host))
		upstreamResolveMu.Lock()
		cached, ok := upstreamResolveCache[key]
		upstreamResolveMu.Unlock()
		if !ok || now.After(cached.expiresAt) {
			ips := map[string]struct{}{}
			if net.ParseIP(key) != nil {
				ips[key] = struct{}{}
			} else if resolved, err := net.LookupIP(key); err == nil {
				for _, ip := range resolved {
					ips[ip.String()] = struct{}{}
				}
			}
			cached = upstreamResolveEntry{ips: ips, expiresAt: now.Add(time.Minute)}
			upstreamResolveMu.Lock()
			upstreamResolveCache[key] = cached
			upstreamResolveMu.Unlock()
		}
		for ip := range cached.ips {
			upstreams[ip+":"+strconv.Itoa(u.port)] = struct{}{}
		}
		upstreams[key+":"+strconv.Itoa(u.port)] = struct{}{}
	}
	return ports, upstreams
}

// filterCaddyConnections 只保留 Caddy 相关连接：客户端侧（本地端口=规则监听
// 端口）或反代侧（远端=上游 host:port）。
func filterCaddyConnections(entries []connectionEntry, ports map[int]struct{}, upstreams map[string]struct{}) []connectionEntry {
	out := make([]connectionEntry, 0, len(entries))
	for _, e := range entries {
		_, localPort := splitHostPortAddr(e.Local)
		remoteHost, remotePort := splitHostPortAddr(e.Remote)
		if _, ok := ports[localPort]; ok {
			out = append(out, e)
			continue
		}
		if _, ok := upstreams[strings.ToLower(remoteHost)+":"+strconv.Itoa(remotePort)]; ok {
			out = append(out, e)
		}
	}
	return out
}

// joinConnectionsMetadata 归属地+安全事件批量叠加（去重远端 IP 一次查询，
// 防逐连接放大；单 IP 查询走 idx_security_events_ip_time 复合索引）。
func joinConnectionsMetadata(entries []connectionEntry) {
	remoteIPs := map[string]struct{}{}
	for i := range entries {
		ip := entries[i].Remote
		if idx := strings.LastIndex(ip, ":"); idx >= 0 && strings.Count(ip, ":") <= 1 {
			ip = ip[:idx] // IPv4 host:port
		}
		if ip != "" && ip != "*" {
			remoteIPs[ip] = struct{}{}
			entries[i].Remote = ip
		} else {
			entries[i].Remote = strings.TrimPrefix(entries[i].Remote, "*:")
		}
	}
	ips := make([]string, 0, len(remoteIPs))
	for ip := range remoteIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for i := range entries {
		entries[i].Country = enrichIPLocation(entries[i].Remote)
	}
}

// collectDomainStats 聚合指标（best-effort：采集失败返回空，不阻塞端点）。
func (h *Handlers) collectDomainStats() []domainStat {
	body, err := h.caddyMetricsSnapshot(context.Background(), false)
	if err != nil || len(body) == 0 {
		return []domainStat{}
	}
	hosts, err := parseHostMetrics(string(body))
	if err != nil {
		return []domainStat{}
	}
	out := make([]domainStat, 0, len(hosts))
	for _, m := range hosts {
		out = append(out, domainStat{Host: m.Host, Requests: m.RequestsTotal, InFlight: m.RequestsInFlight, Status5xx: m.Status5xx})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Requests > out[b].Requests })
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// getConnectionsListCached 缓存+单飞外壳（TTL 吸收弹框 2s 轮询；singleflight
// 合并并发；负缓存防故障打穿）。
func (h *Handlers) getConnectionsListCached() (connectionsListPayload, error) {
	connectionsListMu.Lock()
	now := time.Now()
	if now.Before(connectionsListExpireAt) {
		payload := connectionsListCache
		connectionsListMu.Unlock()
		return payload, nil
	}
	if now.Before(connectionsListNegUntil) {
		err := connectionsListNegErr
		connectionsListMu.Unlock()
		return connectionsListPayload{}, err
	}
	connectionsListMu.Unlock()

	value, err, _ := connectionsListGroup.Do("connections-list", func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), connectionsListTTL*4)
		defer cancel()
		output, err := netstatCommand(ctx).Output()
		if err != nil {
			connectionsListMu.Lock()
			connectionsListNegUntil = time.Now().Add(2 * time.Second)
			connectionsListNegErr = fmt.Errorf("execute netstat -tan: %w", err)
			connectionsListMu.Unlock()
			return connectionsListPayload{}, connectionsListNegErr
		}
		fresh := time.Now()
		entries := parseNetstatEntries(string(output))
		ports, upstreams := loadCaddyEndpoints()
		conns := filterCaddyConnections(entries, ports, upstreams)
		truncated := false
		if len(conns) > connectionsListMaxRows {
			sort.SliceStable(conns, func(a, b int) bool { return conns[a].Category < conns[b].Category })
			truncated = true
			conns = conns[:connectionsListMaxRows]
		}
		joinConnectionsMetadata(conns)
		connCounts := map[string]int64{}
		for _, e := range conns {
			connCounts[e.Category]++
		}
		requests, reqMonOK := fetchReqMonSnapshot(h.cfg.CaddyAdminURL, fresh)
		if reqMonOK {
			joinRequestMetadata(requests)
		}
		reqCounts := map[string]int64{}
		for _, r := range requests {
			reqCounts[r.Category]++
		}
		viewCounts := connCounts
		if reqMonOK {
			viewCounts = reqCounts // 请求视图：四分类=窗口语义
		}
		payload := connectionsListPayload{
			Counts:      viewCounts,
			ConnCounts:  connCounts,
			Requests:    requests,
			Connections: conns,
			Domains:     h.collectDomainStats(),
			ReqMon:      reqMonOK,
			Truncated:   truncated,
			GeneratedAt: fresh.UTC().Format("2006-01-02 15:04:05"),
		}
		connectionsListMu.Lock()
		connectionsListCache = payload
		connectionsListExpireAt = time.Now().Add(connectionsListTTL)
		connectionsListNegUntil, connectionsListNegErr = time.Time{}, nil
		connectionsListMu.Unlock()
		return payload, nil
	})
	if err != nil {
		return connectionsListPayload{}, err
	}
	payload, _ := value.(connectionsListPayload)
	return payload, nil
}

// GetConnectionsList GET /metrics/connections/list：连接详情（lb_reqmon 逐请求
// 明细+Caddy 反代连接+按域名聚合指标；四分类=请求窗口/连接态双口径）。
func (h *Handlers) GetConnectionsList(c *gin.Context) {
	payload, err := h.getConnectionsListCached()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: apimsg.T(c, "k_c0d1164e"), MessageKey: "k_c0d1164e"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: payload})
}
