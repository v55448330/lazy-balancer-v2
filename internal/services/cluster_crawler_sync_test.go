package services

import (
	"context"
	"encoding/json"
	"testing"
)

// 爬虫地址库独立源表与排程随集群快照传播：拆分后不得依赖威胁源表通道。
func TestClusterSnapshot_crawlerSourcesAndScheduleRoundTrip(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if err := SetCrawlerAutoUpdate(false); err != nil {
		t.Fatal(err)
	}
	if err := SetCrawlerSchedule([]int{2, 4}, "05:30"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0, entry_count=170, version='2026.10.16', update_status='success' WHERE name='googlebot'`); err != nil {
		t.Fatal(err)
	}

	// When
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// Then：快照携带独立源表与独立配置
	var rows []map[string]any
	if err := json.Unmarshal(snapshot.SecurityCrawlerSources, &rows); err != nil {
		t.Fatalf("快照未携带 security_crawler_sources: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("crawler rows=%d, want 4", len(rows))
	}
	if snapshot.BasicSettings.CrawlerAutoUpdate == nil || *snapshot.BasicSettings.CrawlerAutoUpdate || snapshot.BasicSettings.CrawlerScheduleDays == nil || *snapshot.BasicSettings.CrawlerScheduleDays != "2,4" || snapshot.BasicSettings.CrawlerScheduleTime == nil || *snapshot.BasicSettings.CrawlerScheduleTime != "05:30" {
		t.Fatalf("快照爬虫配置错误: %+v", snapshot.BasicSettings)
	}

	// 从端清空并改坏配置后重放 → 独立源表与配置忠实恢复
	if _, err := database.Exec(`DELETE FROM security_crawler_sources; UPDATE global_config SET crawler_auto_update=1,crawler_schedule_days='1',crawler_schedule_time='03:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	var enabled, entryCount int
	var version, status string
	if err := database.QueryRow(`SELECT update_enabled,entry_count,version,update_status FROM security_crawler_sources WHERE name='googlebot'`).Scan(&enabled, &entryCount, &version, &status); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 || entryCount != 170 || version != "2026.10.16" || status != "success" {
		t.Errorf("应用后爬虫源状态漂移: enabled=%d count=%d version=%q status=%q", enabled, entryCount, version, status)
	}
	var auto int
	var days, hhmm string
	if err := database.QueryRow(`SELECT crawler_auto_update,crawler_schedule_days,crawler_schedule_time FROM global_config WHERE id=1`).Scan(&auto, &days, &hhmm); err != nil {
		t.Fatal(err)
	}
	if auto != 0 || days != "2,4" || hhmm != "05:30" {
		t.Errorf("应用后爬虫配置漂移: auto=%d days=%s time=%s", auto, days, hhmm)
	}
}

func TestClusterSnapshot_securitySectionHashTracksCrawlerSources(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	first, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// When：仅切换爬虫源开关
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0 WHERE name='googlebot'`); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	second, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if first.SectionHashes["security"] == second.SectionHashes["security"] {
		t.Fatal("爬虫地址库行变化必须改变 security 节哈希")
	}
}
