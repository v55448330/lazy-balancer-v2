package services

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 威胁情报库测试基座：临时数据目录 + 三源指向 httptest 桩。
// bodies: 每源条目；failSources: 返回 500 的源；rawBodies: 原始载荷（畸形/超大用）。
func setupThreatTest(t *testing.T, bodies map[string][]string, failSources map[string]bool, rawBodies map[string]string) {
	t.Helper()
	ResetThreatUpdateManagerForTest()
	oldDir := ThreatDataDir
	ThreatDataDir = t.TempDir()
	t.Cleanup(func() { ThreatDataDir = oldDir })

	names := []string{"ustc", "firehol_l1", "et_compromised"}
	for _, name := range names {
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

// 单任务按 id 升序执行全部启用源；每源文件落盘、行状态 success、
// version=成功日期；合并文件=三源并集聚合去重。
func TestThreatUpdate_runsEnabledSourcesInOrder(t *testing.T) {
	_, database := newClusterTestService(t)
	_ = database
	var mu sync.Mutex
	var order []string
	setupThreatTest(t, nil, nil, nil)
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		name := name
		var url string
		if err := db.DB.QueryRow(`SELECT url FROM security_threat_sources WHERE name=?`, name).Scan(&url); err != nil {
			t.Fatal(err)
		}
		// 用计数桩替换：记录调用顺序
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
		_ = url
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
		if _, err := os.Stat(filepath.Join(ThreatDataDir, name+".txt")); err != nil {
			t.Fatalf("源文件缺失 %s: %v", name, err)
		}
		status, version, _, count, failures := readThreatRow(t, name)
		if status != "success" || count != 2 || version != today || failures != 0 {
			t.Fatalf("源 %s 行=(%s,%d,%q,fail=%d), want (success,2,%q,0)", name, status, count, version, failures, today)
		}
	}
	merged, err := os.ReadFile(filepath.Join(ThreatDataDir, "intel-merged.txt"))
	if err != nil {
		t.Fatalf("合并文件缺失: %v", err)
	}
	if string(merged) != "10.9.0.0/24\n203.0.113.1/32\n" {
		t.Fatalf("合并文件=%q, want 聚合去重并集", merged)
	}
}

// 单源失败不中断其余源；失败源行 status=failed+message+consecutive_failures+1；
// 合并文件包含失败源的上次成功文件（旧文件保留）。
func TestThreatUpdate_sourceFailureKeepsOldFileAndContinues(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	// 首轮全部成功
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
	if status, _, _, _, _ := readThreatRow(t, "et_compromised"); status != "success" {
		t.Fatalf("et_compromised 应继续成功, got %s", status)
	}
	// 合并：ustc 新内容 + firehol 旧文件（203.0.113.1+10.9.0.0/24）+ et 内容
	merged, err := os.ReadFile(filepath.Join(ThreatDataDir, "intel-merged.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"198.51.100.9/32", "203.0.113.1/32", "10.9.0.0/24"} {
		if !strings.Contains(string(merged), want) {
			t.Fatalf("合并文件缺 %s（失败源旧文件须保留生效）:\n%s", want, merged)
		}
	}
}

// 解析守卫：可解析行比例 <50% 判失败（防错页/HTML 劫持）；条目 >200000 拒绝。
func TestThreatUpdate_parseGuards(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, map[string]string{
		"ustc": "<html><body>not a list</body></html>\n203.0.113.1\n", // 1/2 可解析=50% 边界 → 通过
	})
	// firehol：1/3 可解析 <50% → 失败
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>\n<body>\n203.0.113.1\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='firehol_l1'`, srv.URL); err != nil {
		t.Fatal(err)
	}
	// et：超上限
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

// update_enabled=0 的源被跳过（不下载、不动行、不进合并）。
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
	if _, err := os.Stat(filepath.Join(ThreatDataDir, "firehol_l1.txt")); !os.IsNotExist(err) {
		t.Fatalf("禁用更新的源不得产文件: %v", err)
	}
}

// apply_enabled=0 的源更新但不进合并文件；全关时合并文件不写。
func TestThreatUpdate_applyDisabledExcludedFromMerged(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET apply_enabled=0 WHERE name IN ('ustc','firehol_l1')`); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run: %v", err)
	}
	merged, err := os.ReadFile(filepath.Join(ThreatDataDir, "intel-merged.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// 仅 et_compromised 进合并（每源内容同 203.0.113.1+10.9.0.0/24）
	if string(merged) != "10.9.0.0/24\n203.0.113.1/32\n" {
		t.Fatalf("合并文件=%q", merged)
	}

	// 全关 → 合并文件不存在
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET apply_enabled=0`); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(ThreatDataDir, "intel-merged.txt")); err != nil {
		t.Fatal(err)
	}
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ThreatDataDir, "intel-merged.txt")); !os.IsNotExist(err) {
		t.Fatalf("全部 apply 关闭时不得产合并文件: %v", err)
	}
}

// 重复触发返回 ErrThreatUpdateRunning（409 语义由 handler 映射）。
func TestThreatUpdate_duplicateStartRejected(t *testing.T) {
	newClusterTestService(t)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	t.Cleanup(srv.Close)
	setupThreatTest(t, nil, nil, nil)
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

// 更新后合并文件变化必须触发 Caddy 重载（id:14 规则随之生效/停用）——
// 否则更新「成功」但拦截面不变（与 CRS/IP2Region 更新后 reloader 同族）。
func TestThreatUpdate_mergedChangeTriggersReload(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	var reloads int
	SetThreatReloader(func() error { reloads++; return nil })
	t.Cleanup(func() { SetThreatReloader(nil) })

	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1（合并文件新增→重载）", reloads)
	}

	// 同内容再跑一轮：合并文件未变化 → 不重载
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("内容未变化不应重载: reloads=%d", reloads)
	}

	// 内容变化（换源内容）→ 再重载
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
		t.Fatalf("合并内容变化须再重载: reloads=%d", reloads)
	}
}
