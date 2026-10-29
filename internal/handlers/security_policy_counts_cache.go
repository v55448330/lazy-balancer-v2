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
//
// 三条硬约定：①命中与返回路径一律交副本——调用方改写返回 map 不得穿透缓存；
// ②miss 路径经 singleflight 合并（与 threatTrafficGroup 同形），并发 miss 不得
// 放大为 N 趟全窗口扫描；③锚点与扫描窗口同用调用方传入的 now 派生——
// SQL 侧 datetime('now') 是另一只时钟，容器时钟偏移时同一请求的锚点与窗口
// 会互相错位。

import (
	"database/sql"
	"fmt"
	"maps"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/services"
)

// securityPolicy24hCountsCacheTTL 缓存有效期（测试可缩短）。
var securityPolicy24hCountsCacheTTL = 30 * time.Second

// securityPolicy24hCountsGroup 同 (metrics 库, 窗口锚点) 并发 miss 合并为一趟
// 聚合扫描（策略列表多页签/多客户端秒级轮询，重扫描不随并发数放大）。
var securityPolicy24hCountsGroup singleflight.Group

type securityPolicy24hCounts struct {
	blocked map[int]int
	trigger map[int]int
}

// clone 返回两份 map 的独立副本：缓存条目、singleflight 合并的各等待方与
// 调用方之间不得共享底层 map——任一侧写穿透都会改写缓存与其它调用方的视图。
func (c securityPolicy24hCounts) clone() securityPolicy24hCounts {
	return securityPolicy24hCounts{blocked: maps.Clone(c.blocked), trigger: maps.Clone(c.trigger)}
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

// querySecurityPolicy24hCounts 执行 24h 聚合扫描（测试缝：并发合并验证以
// 计数包装本函数）。since 由调用方时钟派生并与锚点同源，格式与 event_time
// 落库格式一致（字符串比较即时间比较）。
var querySecurityPolicy24hCounts = func(metricsDB *sql.DB, since string) (securityPolicy24hCounts, error) {
	counts := securityPolicy24hCounts{blocked: map[int]int{}, trigger: map[int]int{}}
	// 走 idx_security_events_action_time 索引范围（action 等值 + event_time 范围），
	// 单趟扫描；blocked 仅计 blocked，trigger 计 blocked+logged（「24h 触发」列口径）。
	// 攻击口径谓词与总览/大屏/活跃源同源（services.AttackEventSQLPredicate）——
	// 不套谓词时爬虫放行族的 logged 事件会在策略列表计「触发」，而同一事件在
	// 总览「今日检测」为 0，同一屏幕上出现互相矛盾的数值。
	rows, err := metricsDB.Query(`SELECT policy_id, SUM(action='blocked'), COUNT(*) FROM security_events WHERE action IN ('blocked','logged') AND policy_id>0 AND event_time >= ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY policy_id`, since)
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
	return counts, nil
}

// loadSecurityPolicy24hCounts 返回近 24h 每策略的 blocked / 触发（blocked+logged）
// 计数（命中缓存时零查询）。归因口径同 securityEventsAttributePolicy（多策略 CRS
// 重叠按 policy_id ASC 首绑定归因）——展示层记账口径，非引擎级判定。
func loadSecurityPolicy24hCounts(metricsDB *sql.DB, now time.Time) (securityPolicy24hCounts, error) {
	key := securityPolicy24hCountsKey{metrics: metricsDB, anchor: now.UTC().Format("2006-01-02 15:04")}
	// 窗口下界与锚点同一时钟来源（now 派生），格式对齐 event_time 落库形态。
	since := now.UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	if securityPolicy24hCountsCacheTTL > 0 {
		securityPolicy24hCountsMu.Lock()
		if entry, ok := securityPolicy24hCountsCache[key]; ok && now.Before(entry.expiresAt) {
			counts := entry.counts.clone()
			securityPolicy24hCountsMu.Unlock()
			return counts, nil
		}
		securityPolicy24hCountsMu.Unlock()
	}

	result, err, _ := securityPolicy24hCountsGroup.Do(fmt.Sprintf("%p|%s", metricsDB, key.anchor), func() (any, error) {
		// 航班内二次检查：合并进来的并发请求直接复用首个成功结果。
		if securityPolicy24hCountsCacheTTL > 0 {
			securityPolicy24hCountsMu.Lock()
			if entry, ok := securityPolicy24hCountsCache[key]; ok && now.Before(entry.expiresAt) {
				counts := entry.counts.clone()
				securityPolicy24hCountsMu.Unlock()
				return counts, nil
			}
			securityPolicy24hCountsMu.Unlock()
		}
		counts, err := querySecurityPolicy24hCounts(metricsDB, since)
		if err != nil {
			return nil, err
		}
		if securityPolicy24hCountsCacheTTL > 0 {
			securityPolicy24hCountsMu.Lock()
			// 只用锚点+句柄做键：条目数受 TTL 与分钟锚点约束（≤2）。
			// 缓存条目存副本：与本次返回值（同样交副本）互不共享底层 map。
			if len(securityPolicy24hCountsCache) > 4 {
				securityPolicy24hCountsCache = map[securityPolicy24hCountsKey]securityPolicy24hCountsEntry{}
			}
			securityPolicy24hCountsCache[key] = securityPolicy24hCountsEntry{
				counts:    counts.clone(),
				expiresAt: now.Add(securityPolicy24hCountsCacheTTL),
			}
			securityPolicy24hCountsMu.Unlock()
		}
		return counts, nil
	})
	if err != nil {
		return securityPolicy24hCounts{}, err
	}
	return result.(securityPolicy24hCounts).clone(), nil
}
