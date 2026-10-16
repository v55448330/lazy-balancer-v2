package services

import (
	"time"

	"lazy-balancer-v2/internal/db"
)

// SetCrawlerAutoUpdate 写爬虫地址库独立总闸（不共享 threat_auto_update），
// 开启时同步 StartLoop 并补空槽，确保业务开关直接转化为真实排程。
func SetCrawlerAutoUpdate(enabled bool) error {
	if err := setGlobalTaskAutoUpdate("crawler", enabled); err != nil {
		return err
	}
	if enabled {
		armCrawlerFirstSlots()
	}
	return nil
}

// CrawlerAutoUpdateEnabled 读爬虫地址库独立总闸。
func CrawlerAutoUpdateEnabled() bool { return globalTaskAutoUpdateEnabled("crawler") }

// armCrawlerFirstSlots 爬虫地址库首槽武装：启用自动更新时，空 next_update
// 的启用源写入独立排程槽；开启业务开关的调用方也必须经过这里。
func armCrawlerFirstSlots() {
	if db.DB == nil || !CrawlerAutoUpdateEnabled() {
		return
	}
	if err := ensureCrawlerSources(); err != nil {
		Logf("warn", "首槽武装：security_crawler_sources 种子失败: %v", err)
		return
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET next_update=? WHERE update_enabled=1 AND COALESCE(next_update,'')=''`, crawlerNextSlot(time.Now().UTC())); err != nil {
		Logf("warn", "首槽武装：security_crawler_sources 写入 next_update 失败: %v", err)
	}
}
