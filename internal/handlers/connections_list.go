package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"

	"github.com/gin-gonic/gin"
)

// audit138-A5 联动新增：连接明细端点（活跃/待关闭/已关闭/全部 四分类+归属地+
// 安全事件 IP 级叠加）。数据源三路复用既有管线：
//   - 连接表：netstat -tan（getConnectionStats 同命令，复用其缓存/单飞/负缓存）
//   - 归属地：enrichIPLocation（含 GeoIP 代际缓存）
//   - WAF 叠加：security_events 按 client_ip 批量查询（idx_security_events_ip_time）
//
// 性能契约（audit140 方案 A+三措施）：弹框打开才请求；singleflight 合并并发；
// TTL 缓存吸收轮询；去重 IP 批量 join 防逐连接放大；明细上限截断防大表响应。
const connectionsListTTL = 1500 * time.Millisecond
const connectionsListMaxRows = 500
const connectionsWAFWindowDays = 1

type connectionEntry struct {
	Proto       string `json:"proto"`
	Local       string `json:"local"`
	Remote      string `json:"remote"`
	State       string `json:"state"`
	Category    string `json:"category"`    // established | time_wait | closed | listen(排除)
	Country     string `json:"country"`     // 远端归属地（enrichIPLocation）
	WAFBlocked  int64  `json:"waf_blocked"` // 该远端 IP 近 24h WAF 拦截次数
	WAFDetected int64  `json:"waf_detected"`
	LastRule    string `json:"last_rule"` // 该 IP 最近命中规则（空=无记录）
}

type connectionsListPayload struct {
	Counts      map[string]int64  `json:"counts"`
	Entries     []connectionEntry `json:"entries"`
	Truncated   bool              `json:"truncated"`
	GeneratedAt string            `json:"generated_at"`
}

var (
	connectionsListMu       sync.Mutex
	connectionsListCache    connectionsListPayload
	connectionsListExpireAt time.Time
	connectionsListNegUntil time.Time
	connectionsListNegErr   error
)

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

	counts, _ := querySecurityEventSummary(ips, connectionsWAFWindowDays)
	for i := range entries {
		ip := entries[i].Remote
		entries[i].Country = enrichIPLocation(ip)
		if c, ok := counts[ip]; ok {
			entries[i].WAFBlocked = c.blocked
			entries[i].WAFDetected = c.detected
			entries[i].LastRule = c.rule
		}
	}
}

type secEventIPSummary struct {
	blocked  int64
	detected int64
	rule     string
}

// querySecurityEventSummary 去重 IP 集合的近 N 天安全事件摘要（拦截/检测计数
// +最近命中规则）。IP 集合为空时零查询。单条 SQL 批量（IN 列表）防逐 IP 放大。
func querySecurityEventSummary(ips []string, days int) (map[string]secEventIPSummary, error) {
	out := map[string]secEventIPSummary{}
	if len(ips) == 0 || db.MetricsDB == nil {
		return out, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ips)), ",")
	args := make([]any, 0, len(ips)+1)
	for _, ip := range ips {
		args = append(args, ip)
	}
	args = append(args, days)
	query := `SELECT client_ip,
			SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked,
			SUM(CASE WHEN action<>'blocked' THEN 1 ELSE 0 END) AS detected,
			MAX(rule_triggered) AS last_rule
		FROM security_events
		WHERE client_ip IN (` + placeholders + `) AND event_time >= datetime('now', '-' || ? || ' days')
		GROUP BY client_ip`
	rows, err := db.MetricsDB.Query(query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, lastRuleCol string
		var blocked, detected int64
		if err := rows.Scan(&ip, &blocked, &detected, &lastRuleCol); err != nil {
			continue
		}
		out[ip] = secEventIPSummary{blocked: blocked, detected: detected, rule: lastRuleCol}
	}
	return out, nil
}

// getConnectionsListCached 缓存+单飞外壳（镜像 getConnectionStats 范式：TTL
// 吸收弹框 2s 轮询；singleflight 合并并发；负缓存防故障打穿）。
func getConnectionsListCached() (connectionsListPayload, error) {
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

	value, err, _ := connectionStatsGroup.Do("connections-list", func() (any, error) {
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
		entries := parseNetstatEntries(string(output))
		truncated := false
		if len(entries) > connectionsListMaxRows {
			// 截断优先保留 established（活跃视图主分类），其余按 category 稳定排序截断。
			sort.SliceStable(entries, func(a, b int) bool {
				return entries[a].Category < entries[b].Category
			})
			truncated = true
			entries = entries[:connectionsListMaxRows]
		}
		joinConnectionsMetadata(entries)
		sort.SliceStable(entries, func(a, b int) bool { return entries[a].Proto < entries[b].Proto })
		counts := map[string]int64{}
		payload := connectionsListPayload{Entries: entries, Truncated: truncated, GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05")}
		for _, e := range entries {
			counts[e.Category]++
		}
		payload.Counts = counts
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

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// GetConnectionsList GET /metrics/connections/list：连接明细（四分类+归属地+WAF 叠加）。
func (h *Handlers) GetConnectionsList(c *gin.Context) {
	payload, err := getConnectionsListCached()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: apimsg.T(c, "k_c0d1164e"), MessageKey: "k_c0d1164e"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: payload})
}
