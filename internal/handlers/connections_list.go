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

// upstreamResolveTimeout 上游域名解析的共享总预算：DNS 挂起不得阻塞连接刷新
// （netstat 快照本身已有 TTL*4 预算，解析是其后置步骤，需独立有界）。预算
// 由一次 loadCaddyEndpoints 内全部未缓存域名共用——逐域名各给一份会让
// 总时延随上游数量线性放大（N 台挂起=N×预算）。
const upstreamResolveTimeout = 6 * time.Second

// upstreamResolveCacheMax 上游解析缓存条目上限：上游域名集合更替（规则增删/
// 改 host）时旧键不得只增不逐出。超限整体重置——与 enrichLocationCache 同形态
// （有界增长优先于精确 LRU，上游域名量级小，重建代价可忽略）。
const upstreamResolveCacheMax = 1024

// upstreamResolveLookup 上游域名解析缝（默认 net.Resolver.LookupIPAddr，带
// ctx 超时）；var 供测试注入挂起/失败形态，钉「解析有界」契约。
var upstreamResolveLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

type connectionEntry struct {
	Proto    string `json:"proto"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
	Category string `json:"category"` // established | time_wait | closed | listen(排除)
	Country  string `json:"country"`  // 远端归属地（enrichIPLocation）
}

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
	// RequestsTruncated 请求明细触达 500 行展示上限：requests 只含最新
	// 500 条，counts 的口径也是这 500 条（窗口内真实总数未知，插件快照
	// 只下发 top-N）。消费方据此呈现「500+（仅统计最新 500 条）」而非
	// 把封顶值当窗口总数。
	RequestsTruncated bool   `json:"requests_truncated"`
	GeneratedAt       string `json:"generated_at"`
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
// 截断，最新优先）。失败返回 nil, false, false（负缓存 30s 吸收弹框 2s 轮询）。
// 第三个返回值=窗口内条数触达展示上限：插件按 limit=500 只下发 newest-N，
// 窗口内真实总数 > 500 时最新 500 条必然全在窗内（len==500）；真实总数
// ≤ 500 时窗口内记录全在快照里，len 即准确计数。故 len 触达上限即封顶。
func fetchReqMonSnapshot(adminURL string, now time.Time) ([]requestEntry, bool, bool) {
	reqMonMu.Lock()
	unavailable := now.Before(reqMonUnavailableAt)
	reqMonMu.Unlock()
	if unavailable || adminURL == "" {
		return nil, false, false
	}
	resp, err := reqMonClient.Get(strings.TrimSuffix(adminURL, "/") + "/lb/reqmon/snapshot?limit=" + strconv.Itoa(connectionsListMaxRows))
	if err != nil {
		reqMonMarkUnavailable(now)
		return nil, false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		reqMonMarkUnavailable(now)
		return nil, false, false
	}
	var snap reqMonSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&snap); err != nil {
		reqMonMarkUnavailable(now)
		return nil, false, false
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
	truncated := len(out) >= connectionsListMaxRows
	if len(out) > connectionsListMaxRows {
		out = out[:connectionsListMaxRows]
	}
	return out, true, truncated
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

// joinRequestMetadata 请求明细叠加归属地（逐行 enrichIPLocation，进程内缓存
// 吸收重复 IP）+ 规则名映射（X-LB-Rule-ID → lb_rules.name；2026-11-12 用户
// 裁定：去 WAF 列，增反代数据）。
func joinRequestMetadata(entries []requestEntry) {
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

// storeUpstreamResolveEntry 写入解析缓存并执行容量淘汰（调用方不持锁）：
// 超过上限整体重置后再写入——缓存键只增不逐出会让上游域名集合更替时无界增长。
func storeUpstreamResolveEntry(key string, entry upstreamResolveEntry) {
	upstreamResolveMu.Lock()
	if upstreamResolveCache == nil {
		upstreamResolveCache = map[string]upstreamResolveEntry{}
	}
	if len(upstreamResolveCache) >= upstreamResolveCacheMax {
		upstreamResolveCache = map[string]upstreamResolveEntry{}
	}
	upstreamResolveCache[key] = entry
	upstreamResolveMu.Unlock()
}

// connectionCategoryPriority 连接态的截断保留优先级（数值小者优先保留）：
// established=活跃（排障主视图）→ time_wait=待关闭 → closed=已关闭。
// 超上限截断按此排序，活跃连接最后才被丢弃；未知分类兜底排末位。
func connectionCategoryPriority(category string) int {
	switch category {
	case "established":
		return 0
	case "time_wait":
		return 1
	case "closed":
		return 2
	default:
		return 3
	}
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
// host:port 集合（反代侧，含域名一次性解析缓存）。全部未缓存域名共享
// upstreamResolveTimeout 总预算（DNS 挂起时总时延有界，不随上游数放大）。
func loadCaddyEndpoints() (map[int]struct{}, map[string]struct{}) {
	ports := map[int]struct{}{}
	upstreams := map[string]struct{}{}
	if db.DB == nil {
		return ports, upstreams
	}
	// 只收启用规则的监听端口：禁用规则不参与渲染（caddy.go WHERE enabled=1），
	// 其端口不应再被当作 Caddy 流量——否则停用规则后该端口上的其他连接
	// 会被误判为 Caddy 端点（2026-11 全量附录 P3）。
	if rows, err := db.DB.Query(`SELECT listen_port FROM lb_rules WHERE enabled IN ('1',1)`); err == nil {
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
	resolveCtx, cancelResolve := context.WithTimeout(context.Background(), upstreamResolveTimeout)
	defer cancelResolve()
	for _, u := range ups {
		key := strings.ToLower(strings.TrimSpace(u.host))
		upstreamResolveMu.Lock()
		cached, ok := upstreamResolveCache[key]
		upstreamResolveMu.Unlock()
		if !ok || now.After(cached.expiresAt) {
			ips := map[string]struct{}{}
			if net.ParseIP(key) != nil {
				ips[key] = struct{}{}
			} else {
				// 共享预算解析：DNS 挂起不得阻塞连接刷新（LookupIPAddr 在
				// ctx 到期时返回 ctx.Err，见 net/lookup.go 的 ctx.Done 分支）；
				// 预算耗尽后其余域名直接按空解析集缓存，不再逐台等待。
				resolved, err := upstreamResolveLookup(resolveCtx, key)
				if err == nil {
					for _, ip := range resolved {
						ips[ip.IP.String()] = struct{}{}
					}
				}
			}
			cached = upstreamResolveEntry{ips: ips, expiresAt: now.Add(time.Minute)}
			storeUpstreamResolveEntry(key, cached)
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

// joinConnectionsMetadata 远端地址剥端口后叠加归属地（逐行 enrichIPLocation，
// 进程内缓存吸收重复 IP）。剥端口走 splitHostPortAddr 单源（与流量判别同口径）：
// IPv4 host:port / [v6]:port / 无括号 v6:port 都按最后一个冒号切——此前只认
// 「≤1 个冒号」的 IPv4 形态，IPv6 远端带端口整体进查库，归属地恒空。
func joinConnectionsMetadata(entries []connectionEntry) {
	for i := range entries {
		host, _ := splitHostPortAddr(entries[i].Remote)
		if host != "" && host != "*" {
			entries[i].Remote = host
		} else {
			entries[i].Remote = strings.TrimPrefix(entries[i].Remote, "*:")
		}
	}
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
	// nil-cfg 零值契约（config_degradation_test 同族）：嵌入/测试装配形态
	// 未注入 cfg 时返回空列表零值，不裸解引用 panic。
	if h.cfg == nil {
		return connectionsListPayload{}, nil
	}
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
		// 计数按截断前全集：截断只收窄下发明细行，不得让活跃计数低报
		// （truncated=true 单独披露明细被截断，计数仍是全量事实）。
		connCounts := map[string]int64{}
		for _, e := range conns {
			connCounts[e.Category]++
		}
		truncated := false
		if len(conns) > connectionsListMaxRows {
			// 按连接态优先级保留：established（活跃）优先，其次 time_wait
			// （待关闭），最后 closed（已关闭）——字母序会把活跃连接先丢光。
			sort.SliceStable(conns, func(a, b int) bool {
				return connectionCategoryPriority(conns[a].Category) < connectionCategoryPriority(conns[b].Category)
			})
			truncated = true
			conns = conns[:connectionsListMaxRows]
		}
		joinConnectionsMetadata(conns)
		requests, reqMonOK, requestsTruncated := fetchReqMonSnapshot(h.cfg.CaddyAdminURL, fresh)
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
			Counts:            viewCounts,
			ConnCounts:        connCounts,
			Requests:          requests,
			Connections:       conns,
			Domains:           h.collectDomainStats(),
			ReqMon:            reqMonOK,
			Truncated:         truncated,
			RequestsTruncated: requestsTruncated,
			GeneratedAt:       fresh.UTC().Format("2006-01-02 15:04:05"),
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: apimsg.T(c, "system.connectionsListReadFailed"), MessageKey: "system.connectionsListReadFailed"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: payload})
}
