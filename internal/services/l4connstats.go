package services

// L4（TCP）连接计数抓取与差分的单源：威胁大屏流量面板（handlers/
// threat_screen_cache.go 的 1-2s 轮询 serve 差分）与指标采集任务（30s 轮
// 伴生差分落库 lb_l4_conn_history）共用同一抓取实现与重置钳制语义。
// caddy admin /lb/l4-conn-stats 的计数器随 /load 重建归零（与 HTTP
// traffic-stats 同口径）；端点在旧镜像上不存在（404）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

// ErrL4ConnEndpointMissing 标识 admin 无 /lb/l4-conn-stats 端点（404，旧
// 镜像形态）：端点随 caddy 二进制编入，进程生命周期内不会出现——调用方按
// 「端点缺失」静默禁用后续轮询（IsL4ConnEndpointMissing 判定）。
var ErrL4ConnEndpointMissing = errors.New("l4-conn-stats endpoint missing")

// IsL4ConnEndpointMissing 报告 err 是否为端点缺失（404 哨兵）。
func IsL4ConnEndpointMissing(err error) bool {
	return errors.Is(err, ErrL4ConnEndpointMissing)
}

// L4TrafficRuleCounters 是单条 TCP 规则的连接计数快照（caddy l4sec 模块
// l4ConnStatsPayload 形状，JSON 键逐字锁定）。
type L4TrafficRuleCounters struct {
	AllowedTotal uint64            `json:"allowed_total"`
	DeniedTotal  uint64            `json:"denied_total"`
	Countries    map[string]uint64 `json:"countries"`
}

// L4TrafficRawSnapshot 是 /lb/l4-conn-stats 的原始快照（按规则 caddy id）。
type L4TrafficRawSnapshot struct {
	Rules map[string]L4TrafficRuleCounters `json:"rules"`
}

// DeltaUint64 单调差分：cur<prev（/load 归零形态）取 cur，否则 cur-prev。
// 重置钳制的唯一实现——所有计数器差分消费方（大屏 serve 差分、采集落库、
// 总览正常请求差分）共用，不得各自复刻。
func DeltaUint64(cur, prev uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// l4ConnFetchTimeout 是 /lb/l4-conn-stats 的抓取预算：与大屏 traffic-stats
// 抓取同容错（2s，不阻塞轮询协程）。
const l4ConnFetchTimeout = 2 * time.Second

// FetchL4ConnStats 抓取一次 L4 连接计数原始快照。不做日志（日志语义归调用
// 方：大屏路径逐次 warn，采集路径按状态转换口径）；任何失败（不可达/非
// 200/解码失败）返回错误，404 以 ErrL4ConnEndpointMissing 包装。
func FetchL4ConnStats(adminURL string) (L4TrafficRawSnapshot, error) {
	client := &http.Client{Timeout: l4ConnFetchTimeout}
	resp, err := client.Get(strings.TrimRight(adminURL, "/") + "/lb/l4-conn-stats")
	if err != nil {
		return L4TrafficRawSnapshot{}, fmt.Errorf("admin fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return L4TrafficRawSnapshot{}, fmt.Errorf("%w: admin status 404", ErrL4ConnEndpointMissing)
	}
	if resp.StatusCode != http.StatusOK {
		return L4TrafficRawSnapshot{}, fmt.Errorf("admin status %d", resp.StatusCode)
	}
	var snap L4TrafficRawSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snap); err != nil {
		return L4TrafficRawSnapshot{}, fmt.Errorf("decode failed: %w", err)
	}
	return snap, nil
}

// ---- 指标采集侧：30s 轮伴生差分落库 lb_l4_conn_history ----

// 采集差分簿记挂在 MetricsService 实例上（生产单例；测试新实例即新簿记，
// 不跨用例串基线）：按 admin URL 保存上次已消费快照。与大屏 serve 差分
// （handlers 侧 l4TrafficLastServe）互相独立——两个消费方各自维护自己的
// 基线，从同一单调计数器各取各的增量；抓取失败不推进基线（恢复轮的差分
// 从失败前的基线续算，中断期计数被真实计入）。

// SetL4AdminURL 注入采集侧抓取的 Caddy admin 地址（main 装配期调用；空值=
// 未接线，collectL4ConnHistory 静默跳过——测试/嵌入形态零抓取）。
func (m *MetricsService) SetL4AdminURL(adminURL string) {
	m.l4AdminURL = adminURL
}

// collectL4ConnHistory 单轮伴生采集：抓取 → 差分 → 落库。任何失败静默跳过
// （不落行、不失败采集轮——L4 历史是伴生数据面，不可达与大屏同口径降级；
// 端点缺失（旧镜像）确认后实例内禁用，非 404 失败按状态转换口径记日志，
// 首报 warn、恢复 info，30s 节拍下不刷屏）。
func (m *MetricsService) collectL4ConnHistory() {
	adminURL := strings.TrimRight(m.l4AdminURL, "/")
	if adminURL == "" || db.MetricsDB == nil {
		return
	}
	m.l4Mu.Lock()
	skip := m.l4Missing[adminURL]
	m.l4Mu.Unlock()
	if skip {
		return
	}

	snap, err := FetchL4ConnStats(adminURL)
	if err != nil {
		if IsL4ConnEndpointMissing(err) {
			m.l4Mu.Lock()
			m.l4Missing[adminURL] = true
			m.l4Mu.Unlock()
			return
		}
		if lvl := logStateTransition("l4-history-fetch", true); lvl != "" {
			Logf(lvl, "l4 conn history: fetch failed: %v", err)
		}
		return
	}
	if lvl := logStateTransition("l4-history-fetch", false); lvl != "" {
		Logf(lvl, "l4 conn history fetch recovered")
	}

	rows := m.consumeL4Delta(adminURL, snap)
	if len(rows) == 0 {
		m.publishL4Baseline(adminURL, snap)
		return
	}
	if err := storeL4ConnHistory(rows); err != nil {
		// 落库失败不推进基线：下一轮以旧基线重算会把本轮增量补上
		// （计数器单调时差分正确；重置形态取 cur 亦不丢真）。
		if lvl := logStateTransition("l4-history-store", true); lvl != "" {
			Logf(lvl, "l4 conn history: store failed: %v", err)
		}
		return
	}
	m.publishL4Baseline(adminURL, snap)
	if lvl := logStateTransition("l4-history-store", false); lvl != "" {
		Logf(lvl, "l4 conn history store recovered")
	}
}

// l4ConnRow 是单行差分增量（落库形状）。
type l4ConnRow struct {
	ruleID          string
	allowed, denied uint64
}

// consumeL4Delta 计算本轮差分增量行（零增量规则不落行）。基线推进与差分
// 计算分离：仅在落库成功（或无行）后 publishL4Baseline。首轮（无基线）
// 不落行——面板进程单独重启（Caddy 不重启）后 prev 为零值，若按「差分=
// 当前值」落行会把 caddy 计数器全量落成当日行（与 HTTP 侧持久累计锚点
// 不对称）；基线样本只记基线，次轮起正常差分。
func (m *MetricsService) consumeL4Delta(adminURL string, snap L4TrafficRawSnapshot) []l4ConnRow {
	m.l4Mu.Lock()
	defer m.l4Mu.Unlock()
	prev, hasBaseline := m.l4Last[adminURL]
	if !hasBaseline {
		return nil
	}
	var rows []l4ConnRow
	var globalAllowed, globalDenied uint64
	for cid, cur := range snap.Rules {
		was := prev.Rules[cid]
		allowed := DeltaUint64(cur.AllowedTotal, was.AllowedTotal)
		denied := DeltaUint64(cur.DeniedTotal, was.DeniedTotal)
		if allowed == 0 && denied == 0 {
			continue
		}
		rows = append(rows, l4ConnRow{ruleID: cid, allowed: allowed, denied: denied})
		globalAllowed += allowed
		globalDenied += denied
	}
	// 全局聚合行 rule_id=''：读侧（总览正常 TCP）只消费全局行，避免
	// per-rule 行双重求和。
	if globalAllowed > 0 || globalDenied > 0 {
		rows = append(rows, l4ConnRow{ruleID: "", allowed: globalAllowed, denied: globalDenied})
	}
	return rows
}

// publishL4Baseline 在落库成功后推进基线。
func (m *MetricsService) publishL4Baseline(adminURL string, snap L4TrafficRawSnapshot) {
	m.l4Mu.Lock()
	defer m.l4Mu.Unlock()
	m.l4Last[adminURL] = snap
}

// storeL4ConnHistory 单事务批量写入差分增量行（时间戳批内同一采样点，
// 与 storePerRuleMetrics 同口径）。
func storeL4ConnHistory(rows []l4ConnRow) error {
	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05")
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		return fmt.Errorf("begin l4 conn history batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`INSERT INTO lb_l4_conn_history (timestamp, rule_id, allowed, denied)
		VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare l4 conn history batch: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, row := range rows {
		if _, err := stmt.Exec(timestamp, row.ruleID, int64(row.allowed), int64(row.denied)); err != nil {
			return fmt.Errorf("store l4 conn history for %q: %w", row.ruleID, err)
		}
	}
	return tx.Commit()
}
