// Package services —— 搜索引擎/AI 爬虫官方 IP 名单定时更新任务（v2.3.8 用户
// 裁定：厂商 IP 名单必须自动保鲜，与威胁情报库更新族同构）。
//
// 机制：security_crawler_sources 源表（Google/OpenAI/Bing/360 官方 JSON/表）
// 每 24h 定时 + 手动触发下载 → 通用 CIDR 提取（JSON/HTML 通用解析）→
// security_ip_lists 系统名单（name='crawlerbot:<engine>'，system=1）原子快照
// 写入；失败保留上次快照（fail-safe，绝不以更新失败破坏既有豁免）。
// 验证器（caddygeoip.VerifyCrawler）按 IP 段命中即豁免（方法 C 与方法 B
// PTR 双跳并行），名单投影与既有安全_ip_lists 同表复用。
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lazy-balancer-v2/wafiplist"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// crawlerSource 官方 IP 名单源定义（security_threat_sources 同表复用——
// 与威胁情报库完全同机制：update_enabled/next_update/consecutive_failures/
// content_hash/entry_count/version 全部同源字段，不另建源表）。
type crawlerSource struct {
	Name   string
	URL    string
	Format string
}

// crawlerBotSources 内置源（官方文档地址；种子由 ensureCrawlerSources 幂等
// 写入 security_threat_sources（name 与 geoipnames.CrawlerEngine.ID 对齐）。
var crawlerBotSources = []crawlerSource{
	{Name: "googlebot", URL: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json", Format: "json"},
	{Name: "gptbot", URL: "https://openai.com/gptbot.json", Format: "json"},
	{Name: "bingbot", URL: "https://www.bing.com/toolbox/bingbot.json", Format: "json"},
	{Name: "so360spider", URL: "https://www.so.com/help/spider_ip.html", Format: "html"},
}

// ensureCrawlerSources 幂等种子（display_name 区分于威胁源；不更新威胁源行）。
func ensureCrawlerSources() error {
	for _, src := range crawlerBotSources {
		if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crawler_sources (name, display_name, url, format) VALUES (?, ?, ?, ?)`,
			src.Name, crawlerDisplayName(src.Name), src.URL, src.Format); err != nil {
			return err
		}
	}
	return nil
}

// crawlerDisplayName 展示名（与威胁源区分；稳定中文名）。
func crawlerDisplayName(engineID string) string {
	switch engineID {
	case "googlebot":
		return "爬虫机器人 Google"
	case "gptbot":
		return "爬虫机器人 OpenAI"
	case "bingbot":
		return "爬虫机器人 Bing"
	case "so360spider":
		return "爬虫机器人 360"
	}
	return engineID
}

// loadCrawlerSources 读启用源（security_threat_sources 的爬虫族行）。
func loadCrawlerSources() ([]crawlerSource, error) {
	rows, err := db.DB.Query(`SELECT name, url, format FROM security_crawler_sources WHERE update_enabled=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []crawlerSource
	for rows.Next() {
		var s crawlerSource
		if err := rows.Scan(&s.Name, &s.URL, &s.Format); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// cidrTokenRE 通用 CIDR/裸 IP 提取（JSON/HTML 通用；裸 IP 归一 /32）。
var cidrTokenRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)

// parseCrawlerCIDRs 从任意 JSON/HTML 文本提取 CIDR 与裸 IP（归一 /32）并去重。
// 裸 IP 解析失败（非合法 IP）跳过；超界掩码（>/32 或非数字）跳过。
func parseCrawlerCIDRs(body string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, tok := range cidrTokenRE.FindAllString(body, -1) {
		// 排除非 IP 数字串（如版本号 1.2.3.4.5）
		if _, err := netip.ParsePrefix(tok); err != nil {
			if _, aerr := netip.ParseAddr(tok); aerr == nil {
				tok += "/32"
			} else {
				continue
			}
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
}

// crawlerFetchBody 下载源文本（ctx 取消可断；body 上限 16MB）。
func crawlerFetchBody(ctx context.Context, src crawlerSource) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "lazy-balancer-v2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// upsertCrawlerIPList 名单行原子快照：内容变化才更新（entries JSON、
// updated_at、entry_count）；失败/空集不写（保留上次快照）。
// 同步推送插件内存态（模块边界友好：caddygeoip 独立模块不能 import 根 DB）。
func upsertCrawlerIPList(engineID string, entries []string) error {
	if len(entries) == 0 {
		return errors.New("空 IP 段列表（解析无产出）")
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	name := "crawlerbot:" + engineID
	// 名单行不存在 → 补建（system=1，category=搜索引擎爬虫）
	var exists int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, name).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		_, err = db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
			VALUES (?, ?, '搜索引擎爬虫', ?, 1, datetime('now'), datetime('now'))`, name, "crawlerbot:"+engineID, string(encoded))
	} else {
		_, err = db.DB.Exec(`UPDATE security_ip_lists SET entries=?, updated_at=datetime('now') WHERE name=? AND system=1`, string(encoded), name)
	}
	if err == nil {
		if err := writeCrawlerIPListSnapshot(engineID, entries); err != nil {
			Logf("error", "crawlerbot-update: 源 %s 写快照文件失败: %v", engineID, err)
		}
	}
	return err
}

// RunCrawlerBotUpdate 单轮全量更新（手动/自动同体）：逐源下载+解析+快照。
// 任一源失败记录失败态但**不回滚其它源**（与威胁库同语义：失败保留上次快照）。
func RunCrawlerBotUpdate(ctx context.Context, rc *taskengine.RunContext) error {
	if db.DB == nil {
		return errors.New("主库未初始化")
	}
	if err := ensureCrawlerSources(); err != nil {
		return err
	}
	sources, err := loadCrawlerSources()
	if err != nil {
		return err
	}
	var firstErr error
	for _, src := range sources {
		body, err := crawlerFetchBody(ctx, src)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 下载失败: %w", src.Name, err)
			}
			Logf("error", "crawlerbot-update: 源 %s 下载失败: %v", src.Name, err)
			continue
		}
		entries := parseCrawlerCIDRs(body)
		if err := upsertCrawlerIPList(src.Name, entries); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 写名单失败: %w", src.Name, err)
			}
			Logf("error", "crawlerbot-update: 源 %s 写名单失败: %v", src.Name, err)
			markCrawlerSourceFailed(src.Name)
			continue
		}
		markCrawlerSourceSuccess(src.Name, len(entries))
		Logf("info", "crawlerbot-update: 源 %s 更新 %d 个 IP 段", src.Name, len(entries))
	}
	return firstErr
}

const crawlerIPListFile = "/app/data/crawler-ip-lists.json"

var (
	crawlerSchedulerMu     sync.Mutex
	crawlerSchedulerCancel context.CancelFunc
	crawlerSchedulerDone   chan struct{}
)

// StartCrawlerBotScheduler 启动 24h 定时更新（主节点角色；幂等启动）。
// 同时把现有名单预载为共享快照文件（root 服务与插件唯一交换面）。
func StartCrawlerBotScheduler(ctx context.Context) {
	primeCrawlerIPLists()

	primeCrawlerIPLists()

	crawlerSchedulerMu.Lock()
	defer crawlerSchedulerMu.Unlock()
	if crawlerSchedulerDone != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	crawlerSchedulerCancel = cancel
	crawlerSchedulerDone = make(chan struct{})
	done := crawlerSchedulerDone
	go func() {
		defer close(done)
		// 启动即跑一轮（避免首 24h 名单为空）
		_ = RunCrawlerBotUpdate(runCtx, nil)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = RunCrawlerBotUpdate(runCtx, nil)
			case <-runCtx.Done():
				return
			}
		}
	}()
}

// StopCrawlerBotScheduler 停止调度（对称收尾；主节点降级/进程退出时调用）。
func StopCrawlerBotScheduler() {
	crawlerSchedulerMu.Lock()
	defer crawlerSchedulerMu.Unlock()
	if crawlerSchedulerCancel != nil {
		crawlerSchedulerCancel()
		crawlerSchedulerCancel = nil
	}
	if crawlerSchedulerDone != nil {
		<-crawlerSchedulerDone
		crawlerSchedulerDone = nil
	}
}

// markCrawlerSourceSuccess 源成功态：entry_count 更新 + version=成功日期 +
// consecutive_failures 清零 + next_update=+24h（与威胁源状态机同构）。
func markCrawlerSourceSuccess(name string, entryCount int) {
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET entry_count=?, version=?, update_status='success', message='', consecutive_failures=0, next_update=datetime('now','+24 hours'), finished_at=datetime('now') WHERE name=?`,
		entryCount, time.Now().UTC().Format("2006.01.02"), name)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写成功态失败: %v", name, err)
	}
}

// markCrawlerSourceFailed 源失败态：consecutive_failures+1、next_update 指数
// 退避（与威胁源同构：失败保留上次快照，内容表 entries 不动）。
func markCrawlerSourceFailed(name string) {
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='failed', message='下载或解析失败（保留上次快照）', consecutive_failures=consecutive_failures+1, next_update=datetime('now', printf('+%d minutes', 5 * (1 << consecutive_failures)), finished_at=datetime('now') WHERE name=?`, name)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写失败态失败: %v", name, err)
	}
}

// primeCrawlerIPLists 启动预载：security_ip_lists 全部 crawlerbot: 名单写为
// 快照文件（root 服务与插件的唯一交换面；模块边界友好）。
func primeCrawlerIPLists() error {
	rows, err := db.DB.Query(`SELECT name, COALESCE(entries,'') FROM security_ip_lists WHERE name LIKE 'crawlerbot:%' AND system=1`)
	if err != nil {
		Logf("error", "crawlerbot-update: 预载名单失败: %v", err)
		return err
	}
	defer rows.Close()
	all := map[string][]string{}
	for rows.Next() {
		var name, raw string
		if err := rows.Scan(&name, &raw); err != nil {
			continue
		}
		engineID := strings.TrimPrefix(name, "crawlerbot:")
		var entries []string
		if err := json.Unmarshal([]byte(raw), &entries); err != nil || len(entries) == 0 {
			continue
		}
		all[engineID] = entries
	}
	if len(all) > 0 {
		return writeCrawlerIPListSnapshotAll(all)
	}
	return nil
}

// writeCrawlerIPListSnapshotAll 全量快照：写 .iplist 源文件 + wafiplist .fast
// 预编译二进制（与威胁库同编译链，匹配器 ~82ns）。
func writeCrawlerIPListSnapshotAll(all map[string][]string) error {
	lines := make([]string, 0, 2048)
	for _, entries := range all {
		lines = append(lines, entries...)
	}
	// 单文件全量快照（引擎键并入 .fast 元数据注释行，插件按文件名+键索引读取）
	tmp := crawlerIPListFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, crawlerIPListFile); err != nil {
		return err
	}
	v4, v6 := splitCrawlerPrefixes(lines)
	return wafiplist.WriteFastFile(wafiplist.FastPath(crawlerIPListFile), v4, v6)
}

// writeCrawlerIPListSnapshot 单引擎增量快照写（读-改-写；root 服务内串行）。
func writeCrawlerIPListSnapshot(engineID string, entries []string) error {
	all := map[string][]string{}
	if data, err := os.ReadFile(crawlerIPListFile); err == nil {
		_ = json.Unmarshal(data, &all)
	}
	all[engineID] = entries
	return writeCrawlerIPListSnapshotAll(all)
}

// splitCrawlerPrefixes 文本行 → v4/v6 前缀分拣（WriteFastFile 需要）。
func splitCrawlerPrefixes(lines []string) (v4, v6 []netip.Prefix) {
	for _, line := range lines {
		p, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}
