package services

// 更新器 panic 终态的审计口径与「版本行读故障不得折叠成哨兵」的钉测。

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

const updateTestWaitBudget = 3 * time.Second

func waitUpdateTestSignal(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(updateTestWaitBudget):
		t.Fatalf("%s 未在 %s 内完成", what, updateTestWaitBudget)
	}
}

// panic 轮的操作审计必须与正常终态同口径：action=「更新失败」、恰 1 条、
// 详文为中文阶段（不得回落成 reolading/installing 等英文 token）。
func TestIP2RegionStartUpdate_panicRoundAuditsFailureOnce(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { panic("injected reloader panic") }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, done, "panic 轮 IP2Region 更新")

	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='IP数据库'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("panic 轮审计条数=%d, want 1（终态单记）", rows)
	}
	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, COALESCE(detail,'') FROM audit_log WHERE resource='IP数据库'`).Scan(&action, &detail); err != nil {
		t.Fatal(err)
	}
	if action != "更新失败" {
		t.Fatalf("action=%q, want 更新失败（panic 必须落失败语义）", action)
	}
	if !strings.Contains(detail, "更新失败（触发：manual）") {
		t.Fatalf("detail=%q, want 中文阶段前缀（不得回落英文 token）", detail)
	}
	if strings.Contains(detail, "reloading") || strings.Contains(detail, "installing") {
		t.Fatalf("detail=%q 混入英文阶段 token", detail)
	}
}

// threat 侧 panic：终态 lastTaskOutcome=failed，且审计为「更新失败」恰 1 条
// （旧实现读到上一轮 outcome，首轮为空串 → 记成「更新成功」）。
func TestThreatRunUpdate_panicRoundAuditsFailureOnce(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		panic("injected download panic")
	})}
	t.Cleanup(func() { http.DefaultClient = oldClient })

	m := GetThreatUpdateManager()
	// 任务体 panic 被函数内 recover 拦截 → 终态 failed → RunUpdate 返回失败哨兵。
	if err := m.RunUpdate("manual", &taskengine.RunContext{Trigger: "manual"}); !errors.Is(err, ErrThreatUpdateFailed) {
		t.Fatalf("RunUpdate err=%v, want ErrThreatUpdateFailed（panic 轮必须记失败）", err)
	}
	if got := m.StatusSnapshot().Outcome; got != "failed" {
		t.Fatalf("outcome=%q, want failed", got)
	}
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='威胁情报库'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("panic 轮审计条数=%d, want 1", rows)
	}
	var action string
	if err := db.AuditDB.QueryRow(`SELECT action FROM audit_log WHERE resource='威胁情报库'`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != "更新失败" {
		t.Fatalf("action=%q, want 更新失败", action)
	}
}

// 更新 goroutine 内的 panic（拉取/安装/reloader 等任意环节）必须被拦截并落定
// failed 终态——裸 goroutine 的未捕获 panic=整个 admin 进程退出。IP2Region 与
// 威胁族已有两层 recover，CRS 族此前完全没有：同类异常直接把进程带走。
func TestCRSStartUpdate_recoversPanickingRun(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { panic("injected fetch panic") }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, done, "panic 恢复的 CRS 更新")

	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("status=%q, want failed（panic 必须落定失败终态）", status)
	}
	if !strings.Contains(message, "injected fetch panic") {
		t.Fatalf("message=%q, want 携带 panic 内容", message)
	}
	if m.IsRunning() {
		t.Fatal("running 标记必须已复位")
	}
}

// panic 轮的终态审计必须与正常失败同口径：action=「更新失败」、恰 1 条、
// 详文为中文阶段（不得读到 checking 等中间阶段被记成「更新」）。
func TestCRSStartUpdate_panicRoundAuditsFailureOnce(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { panic("injected fetch panic") }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, done, "panic 轮 CRS 更新")

	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='CRS规则库'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("panic 轮审计条数=%d, want 1（终态单记）", rows)
	}
	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, COALESCE(detail,'') FROM audit_log WHERE resource='CRS规则库'`).Scan(&action, &detail); err != nil {
		t.Fatal(err)
	}
	if action != "更新失败" {
		t.Fatalf("action=%q, want 更新失败（panic 必须落失败语义）", action)
	}
	if !strings.Contains(detail, "更新失败（触发：manual）") {
		t.Fatalf("detail=%q, want 中文阶段前缀", detail)
	}
}

// 安装前版本行读故障必须中止安装（不得以 unknown 哨兵继续），且 live xdb 与
// 版本行都不被改动——否则重载失败回滚会把真实 tag 覆写成哨兵。
func TestIP2RegionDownloadAndInstall_abortsOnVersionRowReadFault(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	// 预置既有 live 库（fresh-install 形态没有「更新前基线」可比对）。
	writeTestXDB(t, ip2regionLivePath, testSegments)
	liveBefore, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}

	// 注入读故障：同名对象改为指向缺失表的视图（SELECT 报错，UPDATE 同样失败）。
	if _, err := db.DB.Exec(`ALTER TABLE security_ip2region_version RENAME TO security_ip2region_version_orig`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE VIEW security_ip2region_version AS SELECT * FROM missing_version_source`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`DROP VIEW IF EXISTS security_ip2region_version`)
		_, _ = db.DB.Exec(`ALTER TABLE security_ip2region_version_orig RENAME TO security_ip2region_version`)
	})

	installErr := m.downloadAndInstall(context.Background(), "v9.9.9")
	if installErr == nil || !strings.Contains(installErr.Error(), "读取安装前 IP2Region 版本行") {
		t.Fatalf("install err=%v, want 版本行读故障中止", installErr)
	}

	// 磁盘未被触碰（安装未发生），也未创建 .bak。
	liveAfter, rerr := os.ReadFile(ip2regionLivePath)
	if rerr != nil || string(liveAfter) != string(liveBefore) {
		t.Fatalf("live 文件被改动（读故障必须中止安装），err=%v", rerr)
	}
	if _, serr := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(serr) {
		t.Fatalf("读故障中止不得留下 .bak, stat err=%v", serr)
	}

	// 恢复表后版本行仍是真实 tag（无人写 unknown）。
	if _, err := db.DB.Exec(`DROP VIEW security_ip2region_version`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`ALTER TABLE security_ip2region_version_orig RENAME TO security_ip2region_version`); err != nil {
		t.Fatal(err)
	}
	if v, verr := GetIP2RegionVersion(); verr != nil || v != "v3.0.0" {
		t.Fatalf("版本行=%q,%v, want v3.0.0（不得被覆写成 unknown）", v, verr)
	}
}
