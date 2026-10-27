package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
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
	got, err := parseCrawlerCIDRsForFormat(body+"\n42.236.12.130\nnot.an.ip.version.1.2.3.4.5\n", "")
	if err != nil {
		t.Fatalf("parse crawler CIDRs: %v", err)
	}
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
	// 内置首版=官方快照（googlebot 官方段以 /27 粒度发布，
	// 旧断言 66.249.66.0/24 钉的是已删除的手写表形态）。
	if !strings.Contains(string(data), "192.178.4.0/27") {
		t.Errorf("内置首版未包含 Google CIDR: %s", string(data))
	}
	if !strings.Contains(string(data), "157.55.39.0/24") {
		t.Errorf("内置首版未包含 Bing CIDR: %s", string(data))
	}
}

// TestCrawlerUpdate_partialCommitFailureMessage 部分提交形态的源失败文案：
// DB 行已更新而运行快照写失败时，面板不得显示「保留上次快照」（与实际相反）。
func TestCrawlerUpdate_partialCommitFailureMessage(t *testing.T) {
	newClusterTestService(t)
	oldFile := crawlerIPListFile
	dir := t.TempDir()
	crawlerIPListFile = filepath.Join(dir, "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"10.11.0.0/24"},{"ipv4Prefix":"10.12.0.0/24"}]}`))
	}))
	t.Cleanup(ts.Close)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	// 收缩门基线：3 条既有条目（2 条新条目 > 半数，不触发收缩拒绝）。
	if err := upsertCrawlerIPList("googlebot", []string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"}); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	// 快照目录只读 → DB 行写入成功而快照写失败（部分提交）。
	if os.Geteuid() == 0 {
		t.Skip("root 忽略目录权限位，无法构造快照写失败")
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"}); err == nil {
		t.Fatal("快照写失败必须让本轮失败（不得静默当成功）")
	}

	var status, message string
	if err := db.DB.QueryRow(`SELECT update_status, COALESCE(message,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("源状态=%q, want failed", status)
	}
	if strings.Contains(message, "保留上次快照") {
		t.Fatalf("部分提交（DB 已更新）不得显示「保留上次快照」: %q", message)
	}
	if !strings.Contains(message, "数据库已更新") {
		t.Fatalf("源失败文案未说明真实类别: %q", message)
	}
	// DB 确实已换新内容（部分提交成立的前提）。
	var entries string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, CrawlerIPListName("googlebot")).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entries, "10.11.0.0/24") {
		t.Fatalf("DB 未写入新名单（部分提交前提不成立）: %q", entries)
	}
}

// TestCrawlerUpdate_successStateWriteFailureBackfillsFailedState 成功态写失败时
// 尽力补写 failed 终态：源行不得停留 running（自动更新随后被关闭时该行会
// 长期显示「运行中」）。
func TestCrawlerUpdate_successStateWriteFailureBackfillsFailedState(t *testing.T) {
	newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"10.11.0.0/24"},{"ipv4Prefix":"10.12.0.0/24"}]}`))
	}))
	t.Cleanup(ts.Close)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	if err := upsertCrawlerIPList("googlebot", []string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"}); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	// 只拒绝 success 终态写（failed 终态仍可写）——成功态写失败的唯一注入点。
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_crawler_success BEFORE UPDATE ON security_crawler_sources
		WHEN NEW.update_status='success' BEGIN SELECT RAISE(ABORT,'injected success-state failure'); END;`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`DROP TRIGGER IF EXISTS reject_crawler_success`) })

	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"}); err == nil {
		t.Fatal("成功态写失败必须让本轮失败（不得 success 掩盖）")
	}

	var status, message string
	if err := db.DB.QueryRow(`SELECT update_status, COALESCE(message,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("源状态=%q, want failed（不得停留 running）", status)
	}
	if !strings.Contains(message, "源状态写失败") {
		t.Fatalf("补写失败态文案未说明真实类别: %q", message)
	}
}

// TestPrimeCrawlerIPLists_writesSnapshotOnce 启动预载只写一次全量快照：
// 逐引擎播种阶段只落 DB——带快照形态会在 DB 尚未补种完时各写一次全量快照，
// 插件可能读到「合法 JSON 但只含部分引擎」的中间态（iprange 引擎缺项即
// Transient，合法爬虫失去豁免）。
func TestPrimeCrawlerIPLists_writesSnapshotOnce(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE category='搜索引擎爬虫'`); err != nil {
		t.Fatal(err)
	}
	oldObserver := crawlerSnapshotWriteObserver
	writes := 0
	crawlerSnapshotWriteObserver = func() { writes++ }
	t.Cleanup(func() { crawlerSnapshotWriteObserver = oldObserver })

	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if writes != 1 {
		t.Fatalf("Prime 全量快照写入次数=%d, want 1（逐引擎中间态快照会被插件当作完整集合读取）", writes)
	}
	// 唯一那次写必须已含全部内置引擎。
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatalf("snapshot file missing: %v", err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("invalid snapshot JSON: %v (%s)", err, data)
	}
	for _, src := range crawlerBotSources {
		if len(snapshot[src.Name]) == 0 {
			t.Errorf("快照缺少引擎 %s", src.Name)
		}
	}
}

// TestPrimeCrawlerIPLists_migratesOnce 启动预载只跑一次名单名迁移：迁移必须
// 在读库之前完成（读库以名单名为键，旧键未迁移会让逐引擎写入落到另一行），
// 且不得在逐引擎循环前重复调用（每引擎一次迁移 = N 条幂等 UPDATE）。
func TestPrimeCrawlerIPLists_migratesOnce(t *testing.T) {
	_, _ = newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	var migrates atomic.Int64
	oldMigrate := crawlerIPListMigrate
	crawlerIPListMigrate = func() error {
		migrates.Add(1)
		return oldMigrate()
	}
	t.Cleanup(func() { crawlerIPListMigrate = oldMigrate })

	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if got := migrates.Load(); got != 1 {
		t.Fatalf("Prime 名单名迁移 %d 次, want 1（重复迁移=每引擎 N 条幂等 UPDATE）", got)
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

	// When（auto 触发：现存槽已过期 → 推进）
	markCrawlerSourceFailed("googlebot", "auto", "测试失败")

	// Then：失败写下一排程槽（非 5/10/20 分钟指数退避）
	var next string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	want := crawlerNextSlot(time.Now().UTC())
	if next != want {
		t.Errorf("失败 next_update=%q want 排程槽 %q", next, want)
	}
}

// crawlerbot 源族排程槽写入门禁：失败落仅 auto 推进、成功落 auto/manual 同权
// （manual 仅推进已过期槽）。未来槽一律不回拨；手动失败不得抢先推进过期槽
// ——引擎按退避重投同一槽，业务吃掉它=该自动槽静默消失。旧实现无条件改写
// next_update：手动轮可静默吞掉当天自动轮，一次瞬时手动失败可抑制自动重试。
func TestCrawlerSlotAdvance_triggerGate(t *testing.T) {
	const past = "2000-01-01 00:00:00"
	future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02 15:04:05")
	write := map[string]func(string, string){
		"success": func(name, trigger string) { markCrawlerSourceSuccess(name, trigger, 1) },
		"failed":  func(name, trigger string) { markCrawlerSourceFailed(name, trigger, "测试失败") },
	}
	cases := []struct {
		name         string
		kind         string
		trigger      string
		initial      string
		wantAdvanced bool
	}{
		{name: "auto success advances past slot", kind: "success", trigger: "auto", initial: past, wantAdvanced: true},
		{name: "auto failed advances past slot", kind: "failed", trigger: "auto", initial: past, wantAdvanced: true},
		// 手动成功必须推进过期槽：引擎成功轮已消费该槽，业务不推进=自动更新停摆。
		{name: "manual success advances past slot", kind: "success", trigger: "manual", initial: past, wantAdvanced: true},
		{name: "manual failed keeps slot", kind: "failed", trigger: "manual", initial: past, wantAdvanced: false},
		{name: "auto success keeps future slot", kind: "success", trigger: "auto", initial: future, wantAdvanced: false},
		{name: "auto failed keeps future slot", kind: "failed", trigger: "auto", initial: future, wantAdvanced: false},
		{name: "manual success keeps future slot", kind: "success", trigger: "manual", initial: future, wantAdvanced: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			if err := ensureCrawlerSources(); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(`UPDATE security_crawler_sources SET next_update=? WHERE name='googlebot'`, tc.initial); err != nil {
				t.Fatal(err)
			}

			write[tc.kind]("googlebot", tc.trigger)

			var next string
			if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&next); err != nil {
				t.Fatal(err)
			}
			if tc.wantAdvanced {
				if want := crawlerNextSlot(time.Now().UTC()); next != want {
					t.Fatalf("next_update=%q, want advanced slot %q", next, want)
				}
			} else if next != tc.initial {
				t.Fatalf("next_update=%q, want unchanged %q (gate violated)", next, tc.initial)
			}
		})
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

// 回退 /load 无系统重载审计 ——

// 爬虫名单变化且投影热路径未证实收敛 → 真实 /load 必须与 threat_update/autoban
// 同口径留系统重载审计（成功/失败两态）。
func TestCrawlerFallbackReload_recordsSystemAudit(t *testing.T) {
	newClusterTestService(t)
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	t.Cleanup(func() { threatProjectionRefresher, threatReloader = oldRefresher, oldReloader })
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) { return ProjectionNeedForce, nil }
	threatReloader = func() error { return nil }

	convergeIPListProjectionAfterMutation("crawlerbot-update")
	var success int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务' AND detail LIKE ?`, "%爬虫地址库更新%").Scan(&success); err != nil {
		t.Fatal(err)
	}
	if success != 1 {
		t.Fatalf("爬虫回退 /load 成功审计行=%d, want 1（与 threat_update/autoban 同口径留系统重载审计）", success)
	}

	threatReloader = func() error { return errors.New("injected reload failure") }
	convergeIPListProjectionAfterMutation("crawlerbot-update")
	var failure int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载失败' AND resource='Caddy服务' AND detail LIKE ? AND detail LIKE ?`, "%爬虫地址库更新%", "%injected reload failure%").Scan(&failure); err != nil {
		t.Fatal(err)
	}
	if failure != 1 {
		t.Fatalf("爬虫回退 /load 失败审计行=%d, want 1", failure)
	}
}

// 快照变化判定顺序敏感 ——

// 同集合换序不得判为变化（源站重排不产生写放大/「更新成功」噪声），且未变化
// 不重写 DB entries（展示顺序保持）；真实内容变化仍须探测到。
func TestCrawlerUpsert_changeDetectionIgnoresOrder(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	first := []string{"66.249.66.0/24", "66.249.67.0/24"}
	changed, err := upsertCrawlerIPListChanged("googlebot", first)
	if err != nil || !changed {
		t.Fatalf("首次写入 changed=%v err=%v, want true/nil", changed, err)
	}
	// 同集合换序：不得判为变化（源站重排不产生写放大/「更新成功」噪声）。
	changed, err = upsertCrawlerIPListChanged("googlebot", []string{"66.249.67.0/24", "66.249.66.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("同集合换序必须判为未变化（顺序敏感的字节比较=历史修复）")
	}
	// DB 展示顺序保持原状（未变化不重写）。
	var raw string
	if err := database.QueryRow(`SELECT entries FROM security_ip_lists WHERE name=? AND system=1`, CrawlerIPListName("googlebot")).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || stored[0].Value != "66.249.66.0/24" {
		t.Fatalf("未变化不得重写 DB entries（顺序应保持）: %+v", stored)
	}
	// 真实变化仍须探测到。
	changed, err = upsertCrawlerIPListChanged("googlebot", []string{"66.249.66.0/24"})
	if err != nil || !changed {
		t.Fatalf("内容变化 changed=%v err=%v, want true/nil", changed, err)
	}
}

// Prime 的播种判据必须是逐引擎缺项：库内已有其它引擎时，缺失引擎仍要补种
// 内置首版；已有引擎的名单内容不得被内置首版覆盖。
func TestPrimeCrawlerIPLists_seedsOnlyMissingEngines(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()

	// Given：库内只有 bingbot，且内容是被上游更新过的自定义集合
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE category='搜索引擎爬虫'`); err != nil {
		t.Fatal(err)
	}
	const customBing = "203.0.113.0/24"
	if err := upsertCrawlerIPList("bingbot", []string{customBing}); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{"googlebot", "gptbot", "so360spider"} {
		if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name=? AND system=1`, CrawlerIPListName(engine)); err != nil {
			t.Fatal(err)
		}
	}

	// When
	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Then：四个引擎名单齐全（缺失的三个被内置首版补种），已有引擎内容不变
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range crawlerBotSources {
		if len(all[src.Name]) == 0 {
			t.Errorf("引擎 %s 名单缺失——部分播种失败后重启不再补种", src.Name)
		}
	}
	if len(all["bingbot"]) != 1 || all["bingbot"][0] != customBing {
		t.Fatalf("已有引擎名单被内置首版覆盖: %+v", all["bingbot"])
	}
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatalf("snapshot file missing: %v", err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("invalid snapshot JSON: %v (%s)", err, data)
	}
	for _, src := range crawlerBotSources {
		if len(snapshot[src.Name]) == 0 {
			t.Errorf("运行快照缺少引擎 %s（快照缩水=插件读取侧豁免失效）", src.Name)
		}
	}
}

// 播种中途失败时不得写全量快照（保留上一份），恢复后下一次 Prime 继续补种
// 并重建完整快照。
func TestPrimeCrawlerIPLists_partialFailureKeepsSnapshotAndHeals(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(dir, "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()

	// Given：一次成功的 Prime 产生四引擎快照
	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("initial prime: %v", err)
	}
	before, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatal(err)
	}
	// 删除一个引擎名单行，并把快照目录设为不可写（模拟播种/落盘失败）
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name=? AND system=1`, CrawlerIPListName("googlebot")); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root 忽略目录权限位，无法构造播种写失败")
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	// When：快照写失败
	if err := GetCrawlerUpdateManager().Prime(); err == nil {
		t.Fatal("快照写失败必须上抛（不得静默把部分集合当成功）")
	}

	// Then：上一份快照原样保留（不得缩水为缺引擎的集合）
	after, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatalf("previous snapshot vanished: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("失败轮改写了快照:\n before=%s\n after=%s", before, after)
	}

	// When：目录恢复可写后再次启动
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("retry prime: %v", err)
	}

	// Then：快照重新包含全部引擎
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("invalid snapshot JSON: %v (%s)", err, data)
	}
	for _, src := range crawlerBotSources {
		if len(snapshot[src.Name]) == 0 {
			t.Errorf("恢复后快照仍缺引擎 %s", src.Name)
		}
	}
}

// changed 的契约是「DB 内容真实变化」。DB 未变、仅运行快照缺失/陈旧时，
// upsert 只重建快照并返回 changed=false——否则 RunUpdate 会按「名单内容变化」
// 触发名单投影收敛并写「名单内容变化经投影热路径收敛」日志，口径与事实相反。
func TestUpsertCrawlerIPList_unchangedContentRebuiltSnapshotIsNotChanged(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	entries := []string{"66.249.66.0/24"}
	if err := upsertCrawlerIPList("googlebot", entries); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_ip_lists SET updated_at='2000-01-01 00:00:00' WHERE name=?`, CrawlerIPListName("googlebot")); err != nil {
		t.Fatal(err)
	}
	// Given：DB 内容不变，运行快照缺失（首轮写失败/升级遗留形态）
	if err := os.Remove(crawlerIPListFile); err != nil {
		t.Fatal(err)
	}

	// When
	changed, err := upsertCrawlerIPListChanged("googlebot", entries)
	if err != nil {
		t.Fatalf("快照重建必须成功: %v", err)
	}

	// Then：不算内容变化，快照已按 DB 内容重建，DB 行未被重写
	if changed {
		t.Fatal("DB 内容未变时 changed 必须为 false（快照重建不是内容变化）")
	}
	var updatedAt string
	if err := database.QueryRow(`SELECT updated_at FROM security_ip_lists WHERE name=?`, CrawlerIPListName("googlebot")).Scan(&updatedAt); err != nil {
		t.Fatal(err)
	}
	if updatedAt != "2000-01-01 00:00:00" {
		t.Errorf("未变化名单被重复回写: updated_at=%q", updatedAt)
	}
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatalf("运行快照未重建: %v", err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("invalid snapshot JSON: %v (%s)", err, data)
	}
	if got := snapshot["googlebot"]; len(got) != 1 || got[0] != entries[0] {
		t.Fatalf("快照内容=%v, want %v", got, entries)
	}

	// 回归形状：DB 内容真实变化时 changed 仍为 true。
	changed, err = upsertCrawlerIPListChanged("googlebot", []string{"66.249.66.0/24", "66.249.67.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("DB 内容变化必须返回 changed=true")
	}
}

// 行存在但显式为空（entries='[]'）与「行缺失」必须区分：前者是带外/导入裁剪
// 后的显式空集合（意图=该引擎豁免不生效），启动补种不得把它复活成内置首版；
// 后者才需要补种，否则升级/部分失败会永久丢豁免。
func TestPrime_explicitEmptyCrawlerListRowIsNotReseeded(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	// Given：so360spider 行存在但条目为空；googlebot 行缺失
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE category='搜索引擎爬虫'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
		VALUES (?, '', '搜索引擎爬虫', '[]', 1, datetime('now'), datetime('now'))`, CrawlerIPListName("so360spider")); err != nil {
		t.Fatal(err)
	}

	// When
	if err := GetCrawlerUpdateManager().Prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Then：显式空行保持为空（不被内置首版覆盖）
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		t.Fatal(err)
	}
	if entries, ok := all["so360spider"]; !ok || len(entries) != 0 {
		t.Fatalf("显式空名单行被补种复活: %v（应为空集合）", entries)
	}
	// And：行缺失的引擎照旧补种内置首版
	for _, src := range crawlerBotSources {
		if src.Name == "so360spider" {
			continue
		}
		if len(all[src.Name]) == 0 {
			t.Errorf("缺失引擎 %s 未被补种（显式空判定不得波及行缺失形态）", src.Name)
		}
	}
	// And：运行快照保留该引擎的空数组（显式空 ≠ 缺失，插件两形态均判 Transient，
	// 但快照读者能看出是显式空而非漏种）
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatalf("snapshot file missing: %v", err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("invalid snapshot JSON: %v (%s)", err, data)
	}
	entries, ok := snapshot["so360spider"]
	if !ok {
		t.Fatalf("运行快照丢了显式空引擎: %s", data)
	}
	if len(entries) != 0 {
		t.Fatalf("运行快照把显式空名单写成 %v, want 空集合", entries)
	}
}
