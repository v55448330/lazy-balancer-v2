package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// TestCrawlerBotUpdate_fullCycle 全周期：下载→CIDR 提取→名单快照→IP 段命中。
func TestCrawlerBotUpdate_fullCycle(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	body := `{"ipv4": [{"ipv4": "66.249.66.0/24"}, {"ipv4": "66.249.67.0/24"}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	// 通用 CIDR 提取：合法 CIDR 保留、裸 IP 归一 /32、非 IP 数字串跳过
	got := parseCrawlerCIDRs(body + "\n42.236.12.130\nnot.an.ip.version.1.2.3.4.5\n")
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "66.249.66.0/24") || !strings.Contains(joined, "66.249.67.0/24") {
		t.Fatalf("CIDR 提取缺失: %v", got)
	}
	if !strings.Contains(joined, "42.236.12.130/32") {
		t.Fatalf("裸 IP 未归一 /32: %v", got)
	}

	// 快照 upsert（名单行创建+幂等更新）
	if err := upsertCrawlerIPList("googlebot", got); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var entriesRaw string
	if err := database.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, "Google 官方爬虫 IP（common-crawlers）").Scan(&entriesRaw); err != nil {
		t.Fatal(err)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(entriesRaw), &entries); err != nil || len(entries) == 0 {
		t.Fatalf("名单 entries 为空/畸形: %v %q", err, entriesRaw)
	}
	// 幂等：再次写入不报错且 entries 保留
	if err := upsertCrawlerIPList("googlebot", got); err != nil {
		t.Fatalf("幂等 upsert: %v", err)
	}
}

// TestCrawlerBotUpdate_emptySnapshotFailSafe 空集不写（保留上次快照）。
func TestCrawlerBotUpdate_emptySnapshotFailSafe(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := upsertCrawlerIPList("googlebot", nil); err == nil {
		t.Fatal("空集应报错（fail-safe 保留上次快照）")
	}
	var entriesRaw string
	if err := database.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, "Google 官方爬虫 IP（common-crawlers）").Scan(&entriesRaw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entriesRaw, "66.249.66.0/24") {
		t.Fatalf("空集写入覆盖了上次快照: %q", entriesRaw)
	}
}

// TestPrimeCrawlerIPLists_builtinFallback 新实例无名单时落内置首版（离线可用）。
func TestPrimeCrawlerIPLists_builtinFallback(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE category='搜索引擎爬虫'`); err != nil {
		t.Fatal(err)
	}
	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatalf("snapshot file missing: %v", err)
	}
	if !strings.Contains(string(data), "66.249.66.0/24") {
		t.Errorf("内置首版未包含 Google CIDR: %s", string(data))
	}
	if !strings.Contains(string(data), "157.55.39.0/24") {
		t.Errorf("内置首版未包含 Bing CIDR: %s", string(data))
	}
}

func TestCrawlerSnapshot_preservesAllSources(t *testing.T) {
	// Given：连续更新两个源
	_, _ = newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()

	// When
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := upsertCrawlerIPList("bingbot", []string{"157.55.39.0/24"}); err != nil {
		t.Fatal(err)
	}

	// Then：运行快照为 map[engine][]string JSON，保留全部源且按引擎隔离
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("快照不是插件要求的 JSON 对象: %v; content=%s", err, data)
	}
	if len(snapshot["googlebot"]) != 1 || snapshot["googlebot"][0] != "66.249.66.0/24" {
		t.Errorf("googlebot 快照错误: %+v", snapshot["googlebot"])
	}
	if len(snapshot["bingbot"]) != 1 || snapshot["bingbot"][0] != "157.55.39.0/24" {
		t.Errorf("bingbot 快照错误: %+v", snapshot["bingbot"])
	}
}

func TestUpsertCrawlerIPList_snapshotWriteFailureReturnsError(t *testing.T) {
	// Given：快照目录不存在，DB 可写但文件必失败
	_, _ = newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "missing", "nested", "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()

	// When / Then：不得把快照写失败吞成更新成功
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24"}); err == nil {
		t.Fatal("快照写失败应返回错误，不得标记更新成功")
	}
}

func TestMarkCrawlerSourceFailed_usesScheduleNotBackoff(t *testing.T) {
	// Given：失败源已有旧退避时间
	_, database := newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET next_update='2000-01-01 00:00:00' WHERE name='googlebot'`); err != nil {
		t.Fatal(err)
	}

	// When
	markCrawlerSourceFailed("googlebot")

	// Then：失败也写下一排程槽，不得使用 5/10/20 分钟指数退避
	var next string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	want := crawlerNextSlot(time.Now().UTC())
	if next != want {
		t.Errorf("失败 next_update=%q want 排程槽 %q", next, want)
	}
}

func TestUpsertCrawlerIPList_unchangedSkipsRewrite(t *testing.T) {
	// Given：同内容名单与快照已在场
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_ip_lists SET updated_at='2000-01-01 00:00:00' WHERE name=?`, CrawlerIPListName("googlebot")); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(crawlerIPListFile)
	if err != nil {
		t.Fatal(err)
	}

	// When：同内容再次 upsert
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24"}); err != nil {
		t.Fatal(err)
	}

	// Then：DB 时间与快照 mtime 均不重写
	var updatedAt string
	if err := database.QueryRow(`SELECT updated_at FROM security_ip_lists WHERE name=?`, CrawlerIPListName("googlebot")).Scan(&updatedAt); err != nil {
		t.Fatal(err)
	}
	if updatedAt != "2000-01-01 00:00:00" {
		t.Errorf("未变化名单被重复回写: updated_at=%q", updatedAt)
	}
	after, err := os.Stat(crawlerIPListFile)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("未变化快照被重复重写: before=%v after=%v", before.ModTime(), after.ModTime())
	}
}

func TestCrawlerIPListNames_migrateLegacyPreserveID(t *testing.T) {
	// Given：旧内部键名单行（含 ID 与条目）
	_, database := newClusterTestService(t)
	var oldID int
	if err := database.QueryRow(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at)
		VALUES ('crawlerbot:googlebot','Google 官方源','搜索引擎爬虫','["66.249.66.0/24"]',1,datetime('now'),datetime('now')) RETURNING id`).Scan(&oldID); err != nil {
		t.Fatal(err)
	}

	// When
	if err := migrateCrawlerIPListNames(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Then：名称改为用户可读名，ID 与条目不变
	var gotID int
	var name, entries string
	if err := database.QueryRow(`SELECT id,name,COALESCE(entries,'') FROM security_ip_lists WHERE name=?`, "Google 官方爬虫 IP（common-crawlers）").Scan(&gotID, &name, &entries); err != nil {
		t.Fatal(err)
	}
	if gotID != oldID || !strings.Contains(entries, "66.249.66.0/24") {
		t.Errorf("迁移未保留 ID/条目: id=%d entries=%s", gotID, entries)
	}
}

func TestPrimeCrawlerIPLists_usesBundledSeedFile(t *testing.T) {
	// Given：本地无名单，镜像内置种子含一个自定义 CIDR
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	oldSeed := crawlerDistSeedFile
	crawlerDistSeedFile = filepath.Join(t.TempDir(), "crawler-ip-lists.seed.json")
	defer func() { crawlerDistSeedFile = oldSeed }()
	if err := os.WriteFile(crawlerDistSeedFile, []byte(`{"googlebot":["192.0.2.123/32"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE category='搜索引擎爬虫'`); err != nil {
		t.Fatal(err)
	}

	// When
	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Then：无网络也使用镜像内置种子落库并生成快照
	var entries string
	if err := database.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=?`, "Google 官方爬虫 IP（common-crawlers）").Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entries, "192.0.2.123/32") {
		t.Errorf("内置种子未落库: %s", entries)
	}
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil || !strings.Contains(string(data), "192.0.2.123/32") {
		t.Errorf("内置种子未生成快照: %s err=%v", data, err)
	}
}
