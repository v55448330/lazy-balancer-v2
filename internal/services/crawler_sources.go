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
			if due, err := time.Parse(crsTimeLayout, nextUpdate); err == nil && now.Before(due) {
				continue
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
