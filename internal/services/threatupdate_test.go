package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 威胁情报库名单化（v2.3.2 重构）测试基座：三源指向 httptest 桩；
// 内容与行状态分离——条目写 security_ip_lists 的 system=1 内置名单行，
// 状态/计数/版本写 security_threat_sources。
func setupThreatTest(t *testing.T, bodies map[string][]string, failSources map[string]bool, rawBodies map[string]string) {
	t.Helper()
	ResetThreatUpdateManagerForTest()
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		name := name
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if failSources[name] {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			if raw, ok := rawBodies[name]; ok {
				_, _ = w.Write([]byte(raw))
				return
			}
			list := bodies[name]
			if list == nil {
				list = []string{"203.0.113.1", "10.9.0.0/24"} // 缺省合法两条目
			}
			_, _ = w.Write([]byte(strings.Join(list, "\n") + "\n"))
		}))
		t.Cleanup(server.Close)
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name=?`, server.URL, name); err != nil {
			t.Fatal(err)
		}
	}
}

func readThreatRow(t *testing.T, name string) (status, version, message string, count, failures int) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT update_status, version, message, entry_count, consecutive_failures FROM security_threat_sources WHERE name=?`, name).
		Scan(&status, &version, &message, &count, &failures); err != nil {
		t.Fatal(err)
	}
	return
}

// 读内置名单条目值集合（内容写面断言入口）。
func readThreatListEntries(t *testing.T, source string) []string {
	t.Helper()
	name := db.ThreatListNameBySource(source)
	if name == "" {
		t.Fatalf("未登记的源: %s", source)
	}
	var entriesJSON string
	var system int
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]'), system FROM security_ip_lists WHERE name=?`, name).Scan(&entriesJSON, &system); err != nil {
		t.Fatalf("内置名单缺失 %q: %v", name, err)
	}
	if system != 1 {
		t.Fatalf("名单 %q system=%d, want 1", name, system)
	}
	var entries []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Value)
	}
	return out
}

// 单任务按 id 升序执行全部启用源；条目聚合后写入内置名单行；
// 行状态 success、entry_count=解析条数、version=成功日期。
func TestThreatUpdate_runsEnabledSourcesInOrder(t *testing.T) {
	newClusterTestService(t)
	var mu sync.Mutex
	var order []string
	setupThreatTest(t, nil, nil, nil)
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		name := name
		var url string
		if err := db.DB.QueryRow(`SELECT url FROM security_threat_sources WHERE name=?`, name).Scan(&url); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			_, _ = w.Write([]byte("203.0.113.1\n10.9.0.0/24\n"))
		}))
		t.Cleanup(server.Close)
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name=?`, server.URL, name); err != nil {
			t.Fatal(err)
		}
	}

	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run update: %v", err)
	}

	wantOrder := []string{"ustc", "firehol_l1", "et_compromised"}
	if fmt.Sprint(order) != fmt.Sprint(wantOrder) {
		t.Fatalf("执行顺序=%v, want %v", order, wantOrder)
	}
	today := time.Now().UTC().Format("2006.01.02")
	for _, name := range wantOrder {
		entries := readThreatListEntries(t, name)
		if len(entries) != 2 || entries[0] != "10.9.0.0/24" || entries[1] != "203.0.113.1/32" {
			t.Fatalf("源 %s 名单=%v, want 聚合排序 [10.9.0.0/24 203.0.113.1/32]", name, entries)
		}
		status, version, _, count, failures := readThreatRow(t, name)
		if status != "success" || count != 2 || version != today || failures != 0 {
			t.Fatalf("源 %s 行=(%s,%d,%q,fail=%d), want (success,2,%q,0)", name, status, count, version, failures, today)
		}
	}
}

// 单源失败不中断其余源；失败源行 failed+message+consecutive_failures+1；
// 失败源名单内容保持上次成功值（不被清空）。
func TestThreatUpdate_sourceFailureKeepsOldListAndContinues(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// 第二轮：firehol_l1 失败、ustc 换内容
	server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server500.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='firehol_l1'`, server500.URL); err != nil {
		t.Fatal(err)
	}
	ustc2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.9\n"))
	}))
	t.Cleanup(ustc2.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, ustc2.URL); err != nil {
		t.Fatal(err)
	}

	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("second run: %v", err)
	}

	status, _, message, _, failures := readThreatRow(t, "firehol_l1")
	if status != "failed" || message == "" || failures != 1 {
		t.Fatalf("失败源行=(%s,%q,fail=%d), want (failed,非空 message,1)", status, message, failures)
	}
	if status, _, _, _, _ := readThreatRow(t, "ustc"); status != "success" {
		t.Fatalf("ustc 应继续成功, got %s", status)
	}
	// ustc 名单更新为新内容；firehol 名单保持首轮内容
	if got := readThreatListEntries(t, "ustc"); len(got) != 1 || got[0] != "198.51.100.9/32" {
		t.Fatalf("ustc 名单=%v, want [198.51.100.9/32]", got)
	}
	if got := readThreatListEntries(t, "firehol_l1"); len(got) != 2 {
		t.Fatalf("失败源名单须保留旧内容, got=%v", got)
	}
}

// 解析守卫：可解析行比例 <50% 判失败（防错页/HTML 劫持）；条目 >200000 拒绝。
func TestThreatUpdate_parseGuards(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, map[string]string{
		"ustc": "<html><body>not a list</body></html>\n203.0.113.1\n", // 1/2 可解析=50% 边界 → 通过
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>\n<body>\n203.0.113.1\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='firehol_l1'`, srv.URL); err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("203.0.113.1\n", 200001)
	srvHuge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	}))
	t.Cleanup(srvHuge.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='et_compromised'`, srvHuge.URL); err != nil {
		t.Fatal(err)
	}

	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if status, _, _, _, _ := readThreatRow(t, "ustc"); status != "success" {
		t.Fatalf("50%% 边界应通过, got %s", status)
	}
	if status, _, _, _, _ := readThreatRow(t, "firehol_l1"); status != "failed" {
		t.Fatalf("可解析比例 <50%% 必须失败, got %s", status)
	}
	if status, _, _, _, _ := readThreatRow(t, "et_compromised"); status != "failed" {
		t.Fatalf("超 200000 条目必须拒绝, got %s", status)
	}
}

// update_enabled=0 的源被跳过（不下载、不动行、不写名单）。
func TestThreatUpdate_updateDisabledSourceSkipped(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0 WHERE name='firehol_l1'`); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if status, _, _, _, _ := readThreatRow(t, "firehol_l1"); status != "idle" {
		t.Fatalf("禁用更新的源不得被触碰, got status=%s", status)
	}
	if got := readThreatListEntries(t, "firehol_l1"); len(got) != 0 {
		t.Fatalf("禁用更新的源不得写名单: %v", got)
	}
}

// 名单内容变化触发一次 Caddy 重载（引用名单的策略渲染产物随新内容收敛）；
// 内容未变化不重载。
func TestThreatUpdate_listChangeTriggersReload(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	var reloads int
	SetThreatReloader(func() error { reloads++; return nil })
	t.Cleanup(func() { SetThreatReloader(nil) })

	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1（名单新增内容→重载）", reloads)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("内容未变化不应重载: reloads=%d", reloads)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.99\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run3: %v", err)
	}
	if reloads != 2 {
		t.Fatalf("名单内容变化须再重载: reloads=%d", reloads)
	}
}

// 重复触发返回 ErrThreatUpdateRunning（409 语义由 handler 映射）。
func TestThreatUpdate_duplicateStartRejected(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=?`, srv.URL); err != nil {
		t.Fatal(err)
	}

	done1, err := GetThreatUpdateManager().StartUpdate("manual")
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if _, err := GetThreatUpdateManager().StartUpdate("manual"); err == nil {
		t.Fatal("重复启动必须拒绝")
	}
	close(block)
	<-done1
}

// 名单为空视为到期（升级窗口：旧版写文件新版写名单——next_update 未到期但
// 名单空的源必须进 auto 任务；名单有内容且未到期才跳过）。
func TestThreatDueSources_emptyListIsDue(t *testing.T) {
	newClusterTestService(t)
	// Given：三源 next_update 全在未来
	future := time.Now().UTC().Add(24 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=?`, future); err != nil {
		t.Fatal(err)
	}

	// 名单全空 → 全部到期
	due, err := threatDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 3 {
		t.Fatalf("名单为空时应全部到期, got %d", len(due))
	}

	// ustc 名单填内容 → 仅剩 2 个到期
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='[{"value":"203.0.113.1/32","remark":""}]' WHERE name='威胁情报库-中科大黑 IP'`); err != nil {
		t.Fatal(err)
	}
	due, err = threatDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("ustc 名单有内容后应剩 2 个到期, got %d", len(due))
	}
	for _, s := range due {
		if s.name == "ustc" {
			t.Fatal("ustc 名单有内容且未到期, 不应进 auto 任务")
		}
	}
}
