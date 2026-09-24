package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
)

// 威胁情报库（v2.3.2 名单化重构）：三个内置只读源（USTC/FireHOL level1/ET
// Compromised）的单一顺序更新任务。内容落 security_ip_lists 的 system=1
// 内置名单行（策略经 ip_acl_list_refs/ip_whitelist_refs 引用生效——
// 「引用即应用」，无全局兜底规则）；状态/计数/版本落 security_threat_sources
// （状态机镜像 CRS/IP2Region 更新族：idle/running/success/failed + 失败
// 指数退避）。内容与状态两表分离，渲染走名单引用的既有链路
// （mergedACLList → 聚合 → @ipListFast 文件投影）。

var ErrThreatUpdateRunning = errors.New("威胁情报库更新任务正在进行中")

const (
	threatMaxBodyBytes   = 16 << 20 // 16MB
	threatMaxEntries     = 200000
	threatMinParseRatio  = 0.5
	threatDownloadTimout = 30 * time.Second
)

type ThreatUpdateManager struct {
	mu            sync.Mutex
	running       bool
	runDone       chan struct{}
	schedulerStop chan struct{}
	schedulerDone chan struct{}
	// lastTrigger/lastFinishedAt 为任务级状态（status 端点 + 弹框展示）。
	lastTrigger     string
	lastStartedAt   string
	lastFinishedAt  string
	lastTaskOutcome string // success / failed / ""（未跑过）
}

// nil-until-init（镜像 CRS/IP2Region 管理器）：仅 main.go 初始化——集群
// promote/demote 路径的 SetMasterRole 在测试二进制中经 nil 守卫跳过，
// 不会把调度器（首轮即下载）带进无关测试。
var threatUpdateManager *ThreatUpdateManager

// InitThreatUpdateManager 初始化单例（main.go 启动装配调用一次）。
func InitThreatUpdateManager() {
	threatUpdateManager = &ThreatUpdateManager{}
}

func GetThreatUpdateManager() *ThreatUpdateManager {
	return threatUpdateManager
}

// ResetThreatUpdateManagerForTest 换成全新实例（含停调度器）——测试二进制
// 中初始化入口（main 不运行），同时切断跨测试的 running/调度器残留。
func ResetThreatUpdateManagerForTest() {
	if threatUpdateManager != nil {
		threatUpdateManager.StopScheduler()
	}
	threatUpdateManager = &ThreatUpdateManager{}
}

func (m *ThreatUpdateManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// TaskStatus 任务级状态快照（status 端点）。
type ThreatTaskStatus struct {
	Running    bool   `json:"running"`
	Trigger    string `json:"trigger"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Outcome    string `json:"outcome"`
}

func (m *ThreatUpdateManager) StatusSnapshot() ThreatTaskStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ThreatTaskStatus{
		Running:    m.running,
		Trigger:    m.lastTrigger,
		StartedAt:  m.lastStartedAt,
		FinishedAt: m.lastFinishedAt,
		Outcome:    m.lastTaskOutcome,
	}
}

// threatReloader 名单内容变化后的 Caddy 重载（main.go 注入 caddyReloader）——
// 引用名单的策略渲染产物（@ipListFast 文件）随新内容收敛，否则更新「成功」
// 但拦截面不变。
var threatReloader func() error

// SetThreatReloader 注册重载回调（nil=清除，测试用）。
func SetThreatReloader(fn func() error) {
	threatReloader = fn
}

// StartUpdate 异步启动更新任务（单实例在飞）；返回完成通道。
func (m *ThreatUpdateManager) StartUpdate(trigger string) (chan struct{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil, ErrThreatUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	done := m.runDone
	go func() {
		defer close(done)
		m.run(trigger)
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	return done, nil
}

// RunUpdate 同步执行更新任务（测试与内部路径）。
func (m *ThreatUpdateManager) RunUpdate(trigger string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrThreatUpdateRunning
	}
	m.running = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	m.run(trigger)
	return nil
}

type threatSourceRow struct {
	id            int
	name          string
	url           string
	updateEnabled bool
}

// threatDueSources 返回本次任务处理的源：manual=全部启用源；auto=启用且到期
// （next_update 空或已过）——失败源按退避排程单独重试，不拖累健康源的重下载。
func threatDueSources(trigger string) ([]threatSourceRow, error) {
	rows, err := db.DB.Query(`SELECT id, name, url, update_enabled, COALESCE(next_update,'')
		FROM security_threat_sources WHERE update_enabled=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []threatSourceRow
	now := time.Now().UTC()
	for rows.Next() {
		var s threatSourceRow
		var nextUpdate string
		if err := rows.Scan(&s.id, &s.name, &s.url, &s.updateEnabled, &nextUpdate); err != nil {
			return nil, err
		}
		// 名单为空视为到期（v2.3.2 名单化升级窗口：旧版写文件新版写名单，
		// 不补这条则升级后最长 24h 名单为空、引用策略零拦截）。
		if trigger != "manual" && nextUpdate != "" && !threatListEmpty(s.name) {
			if due, err := time.Parse(crsTimeLayout, nextUpdate); err == nil && now.Before(due) {
				continue
			}
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

// threatListEmpty 报告源对应内置名单是否为空（缺失/[] 视为空）。
func threatListEmpty(source string) bool {
	name := db.ThreatListNameBySource(source)
	if name == "" {
		return true
	}
	var entries string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE name=?`, name).Scan(&entries); err != nil {
		return true
	}
	return entries == "" || entries == "[]"
}

func (m *ThreatUpdateManager) run(trigger string) {
	m.mu.Lock()
	m.lastTrigger = trigger
	m.lastStartedAt = time.Now().UTC().Format(crsTimeLayout)
	m.mu.Unlock()
	sources, err := threatDueSources(trigger)
	if err != nil {
		Logf("error", "威胁情报库: 读取源列表失败: %v", err)
		return
	}
	if len(sources) == 0 {
		return
	}
	AppendThreatUpdateLog("INFO", "checking", fmt.Sprintf("开始更新威胁情报库（%d 个启用源）", len(sources)))
	var changedIDs []int // 内容真实变化的名单 id（重载门的判定面）
	anyFailed := false
	for _, source := range sources {
		changed, failed := m.updateOneSource(source, trigger)
		if changed {
			if id := threatListIDBySource(source.name); id > 0 {
				changedIDs = append(changedIDs, id)
			}
		}
		anyFailed = anyFailed || failed
	}
	m.mu.Lock()
	m.lastFinishedAt = time.Now().UTC().Format(crsTimeLayout)
	if anyFailed {
		m.lastTaskOutcome = "failed"
	} else {
		m.lastTaskOutcome = "success"
	}
	m.mu.Unlock()
	// 名单内容变化 → 一次重载（引用名单的策略渲染随新内容收敛）。
	// 重载门（2026-09-24 用户裁定）：变化的名单须被启用策略引用才重载——
	// 无引用方的变化不打扰在役配置。
	if len(changedIDs) == 0 {
		AppendThreatUpdateLog("INFO", "unchanged", "全部源名单内容未变化，不重载 Caddy 配置")
	} else if !threatListsReferencedByEnabledPolicy(changedIDs) {
		AppendThreatUpdateLog("INFO", "unchanged", "名单内容已变化但无启用策略引用，不重载 Caddy 配置")
	} else if threatReloader != nil {
		AppendThreatUpdateLog("INFO", "reloading", "名单内容已变化且被策略引用，重载 Caddy 配置")
		err := threatReloader()
		// 数据类更新触发的重载统一留操作日志（2026-09-24 用户裁定补齐——
		// 与 crs_update/ip2region_update 同口径，此前威胁库重载无审计）
		recordSystemReloadAudit("threat_update", err)
		if err != nil {
			Logf("error", "威胁情报库: 名单变化后重载失败: %v", err)
			AppendThreatUpdateLog("ERROR", "reloading", fmt.Sprintf("重载 Caddy 配置失败: %v", err))
		}
	}
}

// threatListIDBySource 源名 → 内置名单 id（缺失=0）。
func threatListIDBySource(source string) int {
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, db.ThreatListNameBySource(source)).Scan(&id); err != nil {
		return 0
	}
	return id
}

// threatListsReferencedByEnabledPolicy 报告任一名单 id 被启用策略引用
// （ip_acl_list_refs/ip_whitelist_refs 均为 JSON 数字数组）。查询失败按
// 「可能被引用」处理——宁可多一次重载，不欠引用方的渲染收敛。
func threatListsReferencedByEnabledPolicy(listIDs []int) bool {
	want := map[int]bool{}
	for _, id := range listIDs {
		want[id] = true
	}
	rows, err := db.DB.Query(`SELECT COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]') FROM security_policies WHERE enabled=1`)
	if err != nil {
		Logf("error", "威胁情报库: 读取策略引用失败（按被引用处理）: %v", err)
		return true
	}
	defer rows.Close()
	for rows.Next() {
		var aclRefs, wlRefs string
		if err := rows.Scan(&aclRefs, &wlRefs); err != nil {
			Logf("error", "威胁情报库: 扫描策略引用失败（按被引用处理）: %v", err)
			return true
		}
		for _, raw := range []string{aclRefs, wlRefs} {
			var ids []int
			if err := json.Unmarshal([]byte(raw), &ids); err != nil {
				continue
			}
			for _, id := range ids {
				if want[id] {
					return true
				}
			}
		}
	}
	return false
}

// updateOneSource 下载→解析→写内置名单→更新行状态；失败仅影响该源。
// 返回（名单内容是否变化， 是否失败）。
func (m *ThreatUpdateManager) updateOneSource(source threatSourceRow, trigger string) (bool, bool) {
	now := time.Now().UTC()
	nowStr := now.Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='running', message='', trigger=?, started_at=?, last_checked=?, updated_at=datetime('now') WHERE id=?`,
		trigger, nowStr, nowStr, source.id); err != nil {
		Logf("error", "威胁情报库: 标记源 %s 运行中失败: %v", source.name, err)
		return false, true
	}
	AppendThreatUpdateLog("INFO", "downloading", fmt.Sprintf("下载 %s（%s）", source.name, source.url))

	entries, rawHash, err := downloadAndParseThreatSource(source)
	finished := time.Now().UTC().Format(crsTimeLayout)
	if err != nil {
		failSourceRow(source.id, finished, err)
		AppendThreatUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", source.name, err))
		return false, true
	}

	// 两层哈希（2026-09-24 用户裁定）：原始字节哈希一致 → 内容必然未变，
	// 跳过聚合/写库（稳定源零聚合成本）；原始不同才聚合（乱序源如 USTC
	// 每次请求换序——原始哈希必然不同，聚合规范字节哈希终判防误判变化）。
	var storedRaw string
	if err := db.DB.QueryRow(`SELECT COALESCE(raw_hash,'') FROM security_threat_sources WHERE id=?`, source.id).Scan(&storedRaw); err != nil {
		Logf("error", "威胁情报库: 读源 %s 原始哈希失败: %v", source.name, err)
	}
	if storedRaw != "" && storedRaw == rawHash {
		// 名单行缺失（备份还原/异常清理）须穿透快速路径补建
		var listExists int
		err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, db.ThreatListNameBySource(source.name)).Scan(&listExists)
		switch {
		case err != nil:
			// F49-4：存在性判定失败不得按「存在」跳过（名单可能已缺失，
			// 跳过快照=拦截面静默为空）——记错并继续完整聚合/写库路径。
			Logf("error", "威胁情报库: 检查源 %s 内置名单存在性失败: %v", source.name, err)
		case listExists > 0:
			AppendThreatUpdateLog("INFO", "unchanged", fmt.Sprintf("源 %s 名单内容未变化（原始内容哈希一致），跳过解析写入", source.name))
			markSourceSuccess(source.id, len(entries), finished)
			return false, false
		}
	}

	// 聚合归一后写内置名单（内容未变化零写入——不重载、不 bump 集群版本）。
	merged := wafiplist.AggregateIPEntries(entries)
	changed, werr := writeThreatSystemList(source.name, merged)
	if werr != nil {
		failSourceRow(source.id, finished, fmt.Errorf("写入内置名单失败: %w", werr))
		AppendThreatUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 写入名单失败: %v", source.name, werr))
		return false, true
	}
	// 未变化也留痕（2026-09-24 用户裁定）：源级一条「未变化」日志，
	// 否则日志只见成功不见比对结论，无法区分「未拉取」与「未变化」。
	if !changed {
		AppendThreatUpdateLog("INFO", "unchanged", fmt.Sprintf("源 %s 名单内容未变化（哈希一致），跳过写入", source.name))
	}
	markSourceSuccess(source.id, len(entries), finished, rawHash)
	return changed, false
}

// markSourceSuccess 源成功状态落库（版本/条数/退避清零/下一窗口 + 原始字节哈希）。
// rawHash 空=兼容旧调用形态不写。
func markSourceSuccess(id int, entryCount int, finished string, rawHash ...string) {
	version := time.Now().UTC().Format("2006.01.02")
	next := threatNextSlot(time.Now().UTC())
	raw := ""
	if len(rawHash) > 0 {
		raw = rawHash[0]
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='success', message='', entry_count=?, version=?, finished_at=?, next_update=?, consecutive_failures=0, raw_hash=?, updated_at=datetime('now') WHERE id=?`,
		entryCount, version, finished, next, raw, id); err != nil {
		Logf("error", "威胁情报库: 更新源成功状态失败: %v", err)
	}
	// 源名仅用于日志，按 id 反查一次
	var name string
	_ = db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=?`, id).Scan(&name)
	Logf("info", "威胁情报库: 源 %s 更新成功（%d 条，版本 %s）", name, entryCount, version)
	AppendThreatUpdateLog("INFO", "success", fmt.Sprintf("源 %s 更新成功（%d 条，版本 %s）", name, entryCount, version))
}

// writeThreatSystemList 把聚合条目写入源对应的内置只读名单行
// （security_ip_lists system=1，name 经 db.ThreatListNameBySource 映射）；
// 行缺失时补建（备份还原/异常清理后的自愈）。
// 变更判定=内容哈希比对（2026-09-24 用户裁定）：聚合规范字节的 sha256 存
// security_threat_sources.content_hash——源站乱序返回同一集合（USTC 实测）
// 经聚合排序后字节稳定，哈希一致即未变化（不写名单、不重载、不 bump 集群
// 版本）；升级存量空哈希首跑按变化处理一次（自愈写哈希）。
// 返回 changed=内容真实变化。
func writeThreatSystemList(source string, entries []string) (bool, error) {
	name := db.ThreatListNameBySource(source)
	if name == "" {
		return false, fmt.Errorf("源 %s 未登记内置名单", source)
	}
	payload := make([]models.IPListEntry, 0, len(entries))
	for _, e := range entries {
		payload = append(payload, models.IPListEntry{Value: e})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("编码名单条目失败: %w", err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(encoded))
	// 名单行存在 + 哈希一致 → 未变化（名单行缺失即使哈希命中也须补建）
	var listExists int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, name).Scan(&listExists); err != nil {
		return false, fmt.Errorf("读内置名单失败: %w", err)
	}
	var storedHash string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_hash,'') FROM security_threat_sources WHERE name=?`, source).Scan(&storedHash); err != nil {
		return false, fmt.Errorf("读源哈希失败: %w", err)
	}
	if listExists > 0 && storedHash == hash && storedHash != "" {
		return false, nil
	}
	if listExists == 0 {
		// 行缺失自愈补建
		if _, ierr := db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
			VALUES (?, ?, '恶意 IP', ?, 1, datetime('now'), datetime('now'))`, name, threatListDescription(source), string(encoded)); ierr != nil {
			return false, fmt.Errorf("补建内置名单失败: %w", ierr)
		}
		// F49-P5-4：补建产生新 id——策略经 ip_acl_list_refs/ip_whitelist_refs
		// 持有的旧 id 引用已失效，必须响亮留痕引导重新绑定。
		Logf("warn", "威胁情报库: 内置名单 %q 已重建为新 id，原策略引用已失效，需重新绑定", name)
		RecordAuditLog("system", "重建", "威胁情报库", fmt.Sprintf("内置名单 %s 重建为新 id，原策略引用已失效，需重新绑定", name), "")
	} else {
		if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=?, updated_at=datetime('now') WHERE name=? AND system=1`, string(encoded), name); err != nil {
			return false, fmt.Errorf("更新内置名单失败: %w", err)
		}
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET content_hash=? WHERE name=?`, hash, source); err != nil {
		return false, fmt.Errorf("写源哈希失败: %w", err)
	}
	return true, nil
}

func threatListDescription(source string) string {
	for _, sl := range db.ThreatSystemLists {
		if sl.Source == source {
			return sl.Description
		}
	}
	return ""
}

// failSourceRow 失败落库：status=failed + message + consecutive_failures+1 +
// 指数退避 next_update（1h→2h→4h→8h→24h 封顶，镜像 CRS/IP2Region 语义）。
func failSourceRow(id int, finished string, cause error) {
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET consecutive_failures=consecutive_failures+1 WHERE id=?`, id); err != nil {
		Logf("error", "威胁情报库: 失败计数更新失败: %v", err)
	}
	var failures int
	if err := db.DB.QueryRow(`SELECT consecutive_failures FROM security_threat_sources WHERE id=?`, id).Scan(&failures); err != nil {
		failures = 1
	}
	next := time.Now().UTC().Add(updateRetryBackoff(failures)).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='failed', message=?, finished_at=?, next_update=?, updated_at=datetime('now') WHERE id=?`,
		cause.Error(), finished, next, id); err != nil {
		Logf("error", "威胁情报库: 失败状态落库失败: %v", err)
	}
	Logf("warn", "威胁情报库: 源更新失败: %v", cause)
}

// downloadAndParseThreatSource 下载并解析单源（format=plain）：
// 30s 超时、HTTP 200、body ≤16MB；空行与 #/; 注释跳过；可解析行比例 <50%
// 判失败（防错页/HTML 劫持）；条目 >200000 拒绝。
// 返回原始字节 sha256（两层哈希第一层快速路径，2026-09-24 用户裁定）：
// 原始一致即内容必然未变，调用方跳过聚合/写库；原始不同才走聚合规范哈希终判。
func downloadAndParseThreatSource(source threatSourceRow) ([]string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), threatDownloadTimout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("构造请求失败: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, threatMaxBodyBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("读取响应失败: %w", err)
	}
	if len(body) > threatMaxBodyBytes {
		return nil, "", fmt.Errorf("响应体超过 16MB 上限")
	}
	rawHash := fmt.Sprintf("%x", sha256.Sum256(body))

	var entries []string
	total := 0
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		total++
		if _, err := wafiplist.ParseIPEntry(line); err == nil {
			entries = append(entries, line)
		}
	}
	if total == 0 {
		return nil, "", fmt.Errorf("响应无可解析条目（空名单）")
	}
	if float64(len(entries))/float64(total) < threatMinParseRatio {
		return nil, "", fmt.Errorf("可解析行比例 %d/%d 低于 50%%——疑似错页或劫持", len(entries), total)
	}
	if len(entries) > threatMaxEntries {
		return nil, "", fmt.Errorf("条目数 %d 超过 200000 上限", len(entries))
	}
	return entries, rawHash, nil
}
