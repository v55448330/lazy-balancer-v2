package handlers

// 策略列表「24h 拦截/触发」列的聚合缓存：该聚合对 metrics 库 security_events
// 做近 24h 全窗口扫描（百万行事件表上是一次重扫描），而策略列表在 UI 上按秒
// 级轮询、多个页签并存。同一窗口锚点内（分钟粒度）+ TTL 30s 复用结果，
// 与安全总览近 7 天聚合（securityOverviewAggCache）同范式。
//
// 缓存键只有 (metrics 库句柄, 24h 窗口锚点)：聚合本身是逐 policy_id 的
// 全表 GROUP BY，与「本次请求筛选了哪些策略」无耦合——消费侧按 policy ID 取值，
// 未命中的 ID 一律为 0，因此策略集不参与键（把策略集编入键只会让每个筛选条件
// 各自缓存一份相同聚合）。失败不缓存（错误显式上抛，下轮重试）。

import (
	"database/sql"
	"sync"
	"time"

	"lazy-balancer-v2/internal/services"
)

// securityPolicy24hCountsCacheTTL 缓存有效期（测试可缩短）。
var securityPolicy24hCountsCacheTTL = 30 * time.Second

type securityPolicy24hCounts struct {
	blocked map[int]int
	trigger map[int]int
}

type securityPolicy24hCountsKey struct {
	metrics *sql.DB
	anchor  string // 24h 窗口锚点（UTC 分钟串）
}

type securityPolicy24hCountsEntry struct {
	counts    securityPolicy24hCounts
	expiresAt time.Time
}

var (
	securityPolicy24hCountsMu    sync.Mutex
	securityPolicy24hCountsCache = map[securityPolicy24hCountsKey]securityPolicy24hCountsEntry{}
)

// loadSecurityPolicy24hCounts 返回近 24h 每策略的 blocked / 触发（blocked+logged）
// 计数（命中缓存时零查询）。归因口径同 securityEventsAttributePolicy（多策略 CRS
// 重叠按 policy_id ASC 首绑定归因）——展示层记账口径，非引擎级判定。
func loadSecurityPolicy24hCounts(metricsDB *sql.DB, now time.Time) (securityPolicy24hCounts, error) {
	key := securityPolicy24hCountsKey{metrics: metricsDB, anchor: now.UTC().Format("2006-01-02 15:04")}
	if securityPolicy24hCountsCacheTTL > 0 {
		securityPolicy24hCountsMu.Lock()
		if entry, ok := securityPolicy24hCountsCache[key]; ok && now.Before(entry.expiresAt) {
			counts := entry.counts
			securityPolicy24hCountsMu.Unlock()
			return counts, nil
		}
		securityPolicy24hCountsMu.Unlock()
	}

	counts := securityPolicy24hCounts{blocked: map[int]int{}, trigger: map[int]int{}}
	// 走 idx_security_events_action_time 索引范围（action 等值 + event_time 范围），
	// 单趟扫描；blocked 仅计 blocked，trigger 计 blocked+logged（「24h 触发」列口径）。
	// 攻击口径谓词与总览/大屏/活跃源同源（services.AttackEventSQLPredicate）——
	// 不套谓词时爬虫放行族的 logged 事件会在策略列表计「触发」，而同一事件在
	// 总览「今日检测」为 0，同一屏幕上出现互相矛盾的数值。
	rows, err := metricsDB.Query(`SELECT policy_id, SUM(action='blocked'), COUNT(*) FROM security_events WHERE action IN ('blocked','logged') AND policy_id>0 AND event_time >= datetime('now','-1 day') AND ` + services.AttackEventSQLPredicate("rule_triggered", "action") + ` GROUP BY policy_id`)
	if err != nil {
		return counts, err
	}
	defer rows.Close()
	for rows.Next() {
		var pid, blockedCnt, totalCnt int
		if err := rows.Scan(&pid, &blockedCnt, &totalCnt); err != nil {
			return counts, err
		}
		counts.blocked[pid] = blockedCnt
		counts.trigger[pid] = totalCnt
	}
	if err := rows.Err(); err != nil {
		return counts, err
	}

	if securityPolicy24hCountsCacheTTL > 0 {
		securityPolicy24hCountsMu.Lock()
		// 只用锚点+句柄做键：条目数受 TTL 与分钟锚点约束（≤2）。
		if len(securityPolicy24hCountsCache) > 4 {
			securityPolicy24hCountsCache = map[securityPolicy24hCountsKey]securityPolicy24hCountsEntry{}
		}
		securityPolicy24hCountsCache[key] = securityPolicy24hCountsEntry{
			counts:    counts,
			expiresAt: now.Add(securityPolicy24hCountsCacheTTL),
		}
		securityPolicy24hCountsMu.Unlock()
	}
	return counts, nil
}
