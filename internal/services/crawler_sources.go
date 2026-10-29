package services

import (
	"time"

	"lazy-balancer-v2/internal/db"
)

// crawlerSource 爬虫地址库源定义（security_crawler_sources 独立源表；
// 状态机字段与威胁库同形，但配置/排程/任务互不共享）。
type crawlerSource struct {
	Name   string
	URL    string
	Format string
}

// crawlerBotSources 内置源（官方文档地址；种子由 ensureCrawlerSources 幂等
// 写入 security_crawler_sources（name 与 geoipnames.CrawlerEngine.ID 对齐）。
var crawlerBotSources = []crawlerSource{
	{Name: "googlebot", URL: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json", Format: "json"},
	{Name: "gptbot", URL: "https://openai.com/gptbot.json", Format: "json"},
	{Name: "bingbot", URL: "https://www.bing.com/toolbox/bingbot.json", Format: "json"},
	{Name: "so360spider", URL: "https://www.so.com/help/spider_ip.html", Format: "html"},
}

// CanonicalCrawlerSource 返回内置爬虫源的官方 URL 与解析格式；备份导入
// 借此覆盖携带值，合法 name 不能成为任意下载地址的通行证。
func CanonicalCrawlerSource(name string) (url, format string, ok bool) {
	for _, src := range crawlerBotSources {
		if src.Name == name {
			return src.URL, src.Format, true
		}
	}
	return "", "", false
}

// ensureCrawlerSources 幂等种子（display_name 区分于威胁源；不更新威胁源行）。
// 只保证内置行存在——运行期不覆盖既有 url/format（的 canonical 刷新
// 在启动路径 refreshCrawlerSources 中执行；更新任务每轮调用本函数只为补建
// 缺失行，不得改写既有配置）。
func ensureCrawlerSources() error {
	for _, src := range crawlerBotSources {
		if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crawler_sources (name, display_name, url, format) VALUES (?, ?, ?, ?)`,
			src.Name, crawlerDisplayName(src.Name), src.URL, src.Format); err != nil {
			return err
		}
	}
	return nil
}

// refreshCrawlerSources 启动期按 name 刷新内置源的 canonical url/format/展示名。
// URL/解析格式修正必须到达存量部署，否则旧实例继续每日产出错误名单；
// display_name 与名单名同一事实源（crawlerDisplayName），只靠 INSERT OR IGNORE
// 种子时代码改名永远到不了存量行，源表展示名与名单名长期分叉。
// 用户只能改 update_enabled，状态/排程/开关列保持原值。
func refreshCrawlerSources() error {
	for _, src := range crawlerBotSources {
		displayName := crawlerDisplayName(src.Name)
		if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET url=?, format=?, display_name=?, updated_at=datetime('now')
			WHERE name=? AND (COALESCE(url,'')<>? OR COALESCE(format,'')<>? OR COALESCE(display_name,'')<>?)`,
			src.URL, src.Format, displayName, src.Name, src.URL, src.Format, displayName); err != nil {
			return err
		}
	}
	return nil
}

// CrawlerIPListName 返回引擎对应的用户可读名单名（内部引擎 ID 与展示名分离）。
func CrawlerIPListName(engineID string) string {
	switch engineID {
	case "googlebot":
		return "Google 官方爬虫 IP（common-crawlers）"
	case "gptbot":
		return "OpenAI 官方爬虫 IP（GPTBot）"
	case "bingbot":
		return "Bing 官方爬虫 IP（Bingbot）"
	case "so360spider":
		return "360 官方爬虫 IP（360Spider）"
	}
	return engineID
}

// crawlerDisplayName 源表展示名与名单名同一事实源。
func crawlerDisplayName(engineID string) string { return CrawlerIPListName(engineID) }

// CrawlerSystemListNames 内置爬虫名单名全集（security_ip_lists system=1 的
// 合法来源之一）。备份导入的 system 名单白名单
// 与配额口径共用本注册表——新增内置源只改 crawlerBotSources 一处。
func CrawlerSystemListNames() []string {
	names := make([]string, 0, len(crawlerBotSources))
	for _, src := range crawlerBotSources {
		names = append(names, CrawlerIPListName(src.Name))
	}
	return names
}

// migrateCrawlerIPListNames 将旧内部键 crawlerbot:<engine> 迁移为用户可读名，
// 保留列表 ID、条目与策略引用；重复执行幂等。
func migrateCrawlerIPListNames() error {
	for _, src := range crawlerBotSources {
		if _, err := db.DB.Exec(`UPDATE security_ip_lists SET name=? WHERE name=? AND system=1`,
			CrawlerIPListName(src.Name), "crawlerbot:"+src.Name); err != nil {
			return err
		}
	}
	return nil
}

// crawlerDueSources 读取本次任务应处理的启用源：manual=全部；auto=仅
// next_update 为空或已到期者。排程只读 security_crawler_sources，不触碰威胁源。
func crawlerDueSources(trigger string) ([]crawlerSource, error) {
	rows, err := db.DB.Query(`SELECT name, url, format, COALESCE(next_update,'') FROM security_crawler_sources WHERE update_enabled=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []crawlerSource
	now := time.Now().UTC()
	for rows.Next() {
		var s crawlerSource
		var nextUpdate string
		if err := rows.Scan(&s.Name, &s.URL, &s.Format, &nextUpdate); err != nil {
			return nil, err
		}
		if trigger != "manual" && nextUpdate != "" {
			// 到期判定与 crawlerNextSlot/earliestEnabledSourceUpdate 同口径：
			// 库内允许平面串与 RFC3339 混格式，单布局 time.Parse 失败会被当作
			// 「已到期」→ 未到期的源被同轮提前下载。无法解析=按到期处理
			// （保持 fail-safe：只会多跑不会漏跑）。
			if due, ok := ParseUTCTimeDual(nextUpdate); ok && now.Before(due) {
				continue
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
