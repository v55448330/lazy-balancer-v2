package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/taskengine"
)

// 爬虫源名运行期门（带外边角）：源名白名单此前只在播种/导入侧，带外 INSERT
// 一行未知名启用源（UI 只改 update_enabled、导入拒绝未知名，均无此写入口）即让
// 每日任务抓取任意地址，且解析结果经 upsert 写成新的 system=1 名单——名单名
// 不在备份白名单内，连带封死备份导入恢复通道。运行期读取必须与导入侧共用同一
// 内置集合判定：未知名跳过（不下载、不写名单）并留痕。
func TestRunCrawlerBotUpdate_skipsUnknownSourceName(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.66.0/24"}]}`))
	}))
	defer ts.Close()
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	// 内置源全部停用；带外 INSERT 未知名启用源
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		INSERT INTO security_crawler_sources (name, display_name, url, format, update_enabled)
		VALUES ('evil-source', 'evil', ?, 'json', 1)`, ts.URL); err != nil {
		t.Fatal(err)
	}

	// When：手动轮
	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Then：不下载、不写名单
	if n := hits.Load(); n != 0 {
		t.Fatalf("未知源被下载 %d 次, want 0（运行期必须有内置名门）", n)
	}
	var lists int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='evil-source'`).Scan(&lists); err != nil {
		t.Fatal(err)
	}
	if lists != 0 {
		t.Fatalf("未知源写出 %d 条 security_ip_lists 行, want 0", lists)
	}
	// 未知名行不得被标记运行/失败（本轮未处理）
	var status string
	if err := database.QueryRow(`SELECT COALESCE(update_status,'') FROM security_crawler_sources WHERE name='evil-source'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == "running" || status == "success" {
		t.Fatalf("未知源状态被推进: %q", status)
	}
	// WARN 留痕
	logText := readTaskLog(t, "crawlerbot-update")
	if !strings.Contains(logText, "evil-source") || !strings.Contains(logText, "非内置爬虫源") {
		t.Fatalf("任务日志缺少未知源留痕:\n%s", logText)
	}
}

// 回归形状：已知名源照常更新（门不得误伤内置集合）。
func TestRunCrawlerBotUpdate_knownSourcesStillUpdate(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.66.0/24"},{"ipv4Prefix":"66.249.67.0/24"}]}`))
	}))
	defer ts.Close()
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	// 收缩门基线走 DB 分支（与生命周期用例同形态）
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24", "66.249.67.0/24"}); err != nil {
		t.Fatal(err)
	}

	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	var status string
	if err := database.QueryRow(`SELECT COALESCE(update_status,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "success" {
		t.Fatalf("内置源更新状态=%q, want success（门不得误伤已知名）", status)
	}
}
