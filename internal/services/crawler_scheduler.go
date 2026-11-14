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

// ArmCrawlerFirstSlots 爬虫地址库首槽武装（导出入口）：单源启用
// 与总闸开启走同一实现——总闸已开但无非空 next_update 时，启用单个源必须
// 立即武装其排程槽，否则 NextSlotFn 恒空、任务永不触发（直到重启/重存排程）。
func ArmCrawlerFirstSlots() { armCrawlerFirstSlots() }

// armCrawlerFirstSlots 爬虫地址库首槽武装：启用自动更新时，空 next_update
// 的注册表内启用源写入独立排程槽；开启业务开关的调用方也必须经过这里。
// 只武装注册表内的源（与读侧槽域同源，对照 ArmThreatFirstSlots）：注册表外
// 启用行的槽没有任何推进写点，武装它只会留下惰性槽并与启动期清理互相抵消。
func armCrawlerFirstSlots() {
	if db.DB == nil || !CrawlerAutoUpdateEnabled() {
		return
	}
	if err := ensureCrawlerSources(); err != nil {
		Logf("warn", "首槽武装：security_crawler_sources 种子失败: %v", err)
		return
	}
	nameClause, args := sourceNameSetClause("name", crawlerSourceRegistryNames(), false)
	args = append([]any{crawlerNextSlot(time.Now().UTC())}, args...)
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET next_update=? WHERE update_enabled=1 AND COALESCE(next_update,'')=''`+nameClause, args...); err != nil {
		Logf("warn", "首槽武装：security_crawler_sources 写入 next_update 失败: %v", err)
	}
}
