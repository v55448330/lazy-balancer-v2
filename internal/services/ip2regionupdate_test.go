package services

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func newTestIP2RegionManager(t *testing.T) *IP2RegionUpdateManager {
	stubUpdateRetrySleep(t) // 任务内重试等待即时化（同 newTestCRSManager）
	// 与 CRS 更新族同口径：TOFU 基线与快照路径重定向到临时目录，DB 句柄
	// 保存/还原——更新族测试不得触碰真实数据卷或串用例。
	redirectUpdateTestGlobals(t)

	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))

	m := newIP2RegionUpdateManager(func() error { return nil })
	return m
}

func seedIP2RegionVersionRow(t *testing.T, version string, autoUpdate bool) {
	t.Helper()
	if _, err := db.DB.Exec(
		"INSERT OR REPLACE INTO security_ip2region_version (id, version, auto_update) VALUES (1, ?, ?)",
		version, autoUpdate,
	); err != nil {
		t.Fatal(err)
	}
}

func ip2RegionVersionRow(t *testing.T) (version, status, message, finishedAt, lastChecked, nextUpdate string, autoUpdate bool) {
	t.Helper()
	err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,''), COALESCE(message,''),
		COALESCE(finished_at,''), COALESCE(last_checked,''), COALESCE(next_update,''), auto_update
		FROM security_ip2region_version WHERE id=1`).
		Scan(&version, &status, &message, &finishedAt, &lastChecked, &nextUpdate, &autoUpdate)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func fakeIP2RegionDownload(t *testing.T, valid bool) func(context.Context, string, string, downloadProgressFunc) error {
	t.Helper()
	return func(_ context.Context, _ string, dest string, _ downloadProgressFunc) error {
		if !valid {
			return os.WriteFile(dest, []byte("not an xdb"), 0644)
		}
		writeTestXDB(t, dest, testSegments)
		return nil
	}
}

func TestIP2RegionUpdateRun_success(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldLive, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	backupObserved := false
	m.reloader = func() error {
		reloads++
		backup, readErr := os.ReadFile(ip2regionLivePath + ".bak")
		backupObserved = readErr == nil && string(backup) == string(oldLive)
		return nil
	}

	// When a manual update runs to completion
	m.run("manual", nil)

	// Then the DB row reflects success at the new version
	version, status, message, finishedAt, _, _, _ := ip2RegionVersionRow(t)
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0", version)
	}
	if status != "success" {
		t.Fatalf("update_status=%q, want success", status)
	}
	if message != "" {
		t.Fatalf("message=%q, want empty", message)
	}
	if finishedAt == "" {
		t.Fatal("finished_at empty after success")
	}

	// And the new xdb is in place at the live path, searcher reloaded, staging cleaned
	if _, err := os.Stat(ip2regionLivePath); err != nil {
		t.Fatalf("live xdb missing: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1", reloads)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(ip2regionLivePath), ".staging")); !os.IsNotExist(err) {
		t.Fatal(".staging should be cleaned up")
	}
	if !backupObserved {
		t.Fatal("带既有 live 的成功轮必须实际创建本轮 .bak（正控）")
	}
	// 1.2：成功后.bak 须清理，不残留陈旧备份
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("live xdb .bak should be cleaned after success")
	}
}

// 取消落在「安装段已落盘、Caddy 重载尚未执行」的窗口：未重载即未生效——
// live xdb、版本行、sidecar 必须回滚到同代基线，reloader 不得被调用。
func TestIP2RegionUpdateRun_cancelAfterInstallRollsBackSameGeneration(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	oldReload := reloadIP2RegionSearcher
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })
	cancelIssued := false
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		if reloadCalls == 1 {
			// 安装段末的内存热换完成后立刻取消（该窗口即用户点取消的落点）。
			cancelIssued = m.CancelRunning()
		}
		return Reload()
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatalf("start update: %v", err)
	}
	waitUpdateTestSignal(t, done, "安装后取消的 IP2Region 更新")

	if !cancelIssued {
		t.Fatal("前置：安装段末的取消必须命中在途运行（CancelRunning=false）")
	}
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("取消后 live xdb 必须回滚到更新前基线（err=%v）", err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("取消回滚必须消费本运行的 .bak")
	}
	if reloads != 0 {
		t.Fatalf("reloader 调用 %d 次，want 0（未重载即未生效，取消不得触发重载）", reloads)
	}
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "cancelled" {
		t.Fatalf("update_status=%q, want cancelled (message=%q)", status, message)
	}
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want v3.0.0（版本行必须同代回滚）", version)
	}
	if side, sErr := os.ReadFile(ip2regionLivePath + ".version"); sErr != nil || strings.TrimSpace(string(side)) != "v3.0.0" {
		t.Fatalf(".version sidecar=%q,%v, want v3.0.0（sidecar 必须同代回滚）", string(side), sErr)
	}
}

// 下载期取消（安装段未提交）：零回滚——live 保持取消前形态、无 .bak 残留、
// 版本行保持旧值、reloader 不调用。
func TestIP2RegionUpdateRun_cancelDuringDownloadKeepsDisk(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = func(ctx context.Context, _, _ string, _ downloadProgressFunc) error {
		m.CancelRunning()
		<-ctx.Done()
		return ctx.Err()
	}
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatalf("start update: %v", err)
	}
	waitUpdateTestSignal(t, done, "下载期取消的 IP2Region 更新")

	if _, err := os.Stat(ip2regionLivePath); !os.IsNotExist(err) {
		t.Fatalf("下载期取消不得产生 live 文件（stat err=%v）", err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("下载期取消不得留下 .bak")
	}
	if reloads != 0 {
		t.Fatalf("reloader 调用 %d 次，want 0", reloads)
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "cancelled" || version != "v3.0.0" {
		t.Fatalf("(status,version)=(%q,%q), want (cancelled,v3.0.0)", status, version)
	}
}

func TestIP2RegionUpdateRun_skipWhenSameVersion(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string, downloadProgressFunc) error { downloadCalled = true; return nil }
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// 预置 stale sidecar（崩溃遗留形态）——
	// skip 路径的 rewriteVersionIfMissingOrStale 须把它校正为当前 tag，
	// 否则 stale tag 无限期不愈。
	sidecar := ip2regionLivePath + ".version"
	if err := os.WriteFile(sidecar, []byte("v0.0.1"), 0644); err != nil {
		t.Fatal(err)
	}

	// When an update finds the same commit
	m.run("auto", nil)

	// Then nothing is downloaded and no reload happens
	if downloadCalled {
		t.Fatal("must skip download when commit equals current version")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0", reloads)
	}
	_, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success", status)
	}
	if message != "已是最新版本" {
		t.Fatalf("message=%q, want 已是最新版本", message)
	}
	// stale sidecar 已被校正为 fetchLatestTag 同值
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("sidecar missing after skip-path refresh: %v", err)
	}
	if got := strings.TrimSpace(string(raw)); got != "v3.0.0" {
		t.Fatalf("sidecar=%q, want v3.0.0（stale 未愈）", got)
	}
}

func TestIP2RegionUpdateRun_fetchFailure(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("network error") }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string, downloadProgressFunc) error { downloadCalled = true; return nil }
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the commit check fails
	m.run("manual", nil)

	// Then the row is marked failed, nothing downloaded or reloaded
	_, status, message, finishedAt, lastChecked, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if message == "" {
		t.Fatal("message empty after failure")
	}
	if finishedAt == "" {
		t.Fatal("finished_at empty after failure")
	}
	if lastChecked == "" {
		t.Fatal("last_checked should be recorded on fetch failure")
	}
	if downloadCalled {
		t.Fatal("download must not run when fetch fails")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0", reloads)
	}
}

func TestIP2RegionUpdateRun_invalidDownloadFails(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	oldLive := "old-live-content"
	if err := os.WriteFile(ip2regionLivePath, []byte(oldLive), 0644); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, false)
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the downloaded file fails validation
	m.run("manual", nil)

	// Then the update fails and the old live file is untouched
	_, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != oldLive {
		t.Fatalf("live xdb was modified on failed update: %q, %v", data, err)
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0", reloads)
	}
}

func TestIP2RegionUpdateRun_reloadFailureRollsBackXDB(t *testing.T) {
	// Given 一个已安装的旧 xdb 与一个必然失败一次的 reloader（镜像 CRS fail() 的
	// restoreBackup+重试路径， 1.2）：reloader 失败时磁盘不得停留在新库、DB
	// 记录旧版本+failed 的不一致状态。旧 live 用合法 xdb 使还原后的内存热换成
	// 功、走主路径（自此热换失败不再升级、仅记 warn，由另外两个
	// KeepsBaseline 用例覆盖）。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload boom")
		}
		return nil
	}

	// When 安装后首次 reload 失败
	m.run("manual", nil)

	// Then 旧 xdb 已还原、.bak 被回滚消费、reloader 重试一次、状态 failed
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("live xdb not rolled back: %v", err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("xdb .bak should be consumed by rollback")
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, rollback reload succeeds)", reloads)
	}
	_, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
}

func TestIP2RegionUpdateRun_staleBakNotConsumedByRollback(t *testing.T) {
	// Given 跨运行崩溃窗口残留的陈旧.bak：上一运行在 rename 成功后、
	// reloader 前崩溃，.bak 是旧 xdb 唯一副本。本运行 live 原本缺失（不创建新
	// 备份，bakCreated=false），reloader 失败时 rollbackXDB 不得消费该陈旧副本。
	// 自此 bakCreated==false 且 dist 缺失时走 fail-open：磁盘/内存已是新库，
	// DB 按成功落库保持三方一致；陈旧 .bak 仍原样保留。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	staleBak := "stale-bak-from-crashed-run"
	if err := os.WriteFile(ip2regionLivePath+".bak", []byte(staleBak), 0644); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return errors.New("reload boom") }

	// When 安装成功但 reloader 持续失败
	m.run("manual", nil)

	// Then 陈旧 .bak 原样保留（未被回滚消费），live 不被还原到陈旧副本；
	// 无基线可用时按 fail-open 记 success+新 tag
	data, err := os.ReadFile(ip2regionLivePath + ".bak")
	if err != nil || string(data) != staleBak {
		t.Fatalf("stale .bak should be preserved untouched: %q, %v", data, err)
	}
	live, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatalf("live xdb missing: %v", err)
	}
	if string(live) == staleBak {
		t.Fatal("live xdb must not be rolled back to stale .bak content")
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success (fail-open)", status)
	}
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0 (fail-open 记录新 tag)", version)
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (fail-open 落库前补一次 reloader 重试)", reloads)
	}
}

func TestIP2RegionUpdateRun_reloadFailureFallsBackToDistOnFreshInstall(t *testing.T) {
	// Given 全新部署：live xdb 不存在（无旧库可备份，bakCreated=false），dist
	// 基线存在。reloader 必然失败一次——修复前 rollbackXDB 静默跳过，
	// 磁盘/内存是新库、DB 记 failed+旧版本（unknown），三方长期不一致。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "unknown", true)
	// 用合法 xdb 作为 dist 基线（「更新前状态」的权威副本）
	dir := t.TempDir()
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, testSegments)
	live := filepath.Join(dir, "data", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(live), 0755); err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, live, dist)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload boom")
		}
		return nil
	}

	// When 安装成功但 reloader 首次失败
	m.run("manual", nil)

	// Then dist 基线已复制回 live、reloader 重试一次、DB 记 failed+旧版本
	// （unknown），磁盘/内存/DB 三方一致（均为「更新前状态」）
	gotLive, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatalf("live xdb missing after dist fallback: %v", err)
	}
	wantLive, err := os.ReadFile(dist)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotLive) != string(wantLive) {
		t.Fatal("live xdb content mismatch with dist baseline after fallback")
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, fallback reload succeeds)", reloads)
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if version != "bundled" {
		t.Fatalf("version=%q, want bundled (dist 基线，版本不可知)", version)
	}
}

func TestIP2RegionUpdateRun_reloadFailureFailOpenWhenNoBaseline(t *testing.T) {
	// Given 全新部署且 dist 也缺失（newTestIP2RegionManager 默认 dist 指向不
	// 存在路径）：无任何「更新前基线」可回退， fail-open——磁盘/内存已
	// 是新库，DB 按成功落库保持三方一致。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "unknown", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return errors.New("reload boom") }

	// When 安装成功、reloader 持续失败、且无任何基线可回退
	m.run("manual", nil)

	// Then DB 按成功落库（fail-open），live 保留新库，版本列追上新 tag
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success (fail-open)", status)
	}
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0 (fail-open 记录新 tag)", version)
	}
	if message == "" {
		t.Fatal("message 应保留 reloader 错误以便排查")
	}
	if _, err := os.Stat(ip2regionLivePath); err != nil {
		t.Fatalf("live xdb missing: %v", err)
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (fail-open 落库前补一次 reloader 重试)", reloads)
	}
}

func TestIP2RegionUpdateRun_installReloadFailureGoesToRollback(t *testing.T) {
	// Given：安装 rename 成功但内存热换失败（seam 注入首次调用失败）——
	// 磁盘已是新库而内存 searcher 仍是旧库，必须视同 reloader 失败进入同一回滚
	// 路径：rollbackXDB 还原磁盘+内存，DB 记 failed+旧版本，三方一致；旧实现吞掉
	// Reload 返回值，直接按 failed 落库会留下「磁盘新、内存旧、DB failed+旧」。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	oldReload := reloadIP2RegionSearcher
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		if reloadCalls == 1 {
			return errors.New("forced: install hot-swap failure")
		}
		return Reload()
	}
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When 安装后内存热换失败
	m.run("manual", nil)

	// Then 走回滚路径：live 还原为旧库、.bak 被消费、DB 记 failed+旧版本且
	// message 注明热换失败；reloader 在热换失败时不做无谓的首次调用，仅在
	// 回滚还原后对称重试一次
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("live xdb not rolled back after hot-swap failure: %v", err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal(".bak should be consumed by rollback")
	}
	if reloadCalls != 2 {
		t.Fatalf("reload calls=%d, want 2 (install hot-swap fails, rollback restore succeeds)", reloadCalls)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (reloader skipped on hot-swap failure, retried once after rollback)", reloads)
	}
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want v3.0.0 (回滚到更新前基线时回写 prevVersion)", version)
	}
	if !strings.Contains(message, "重载 ip2region 内存索引失败") {
		t.Fatalf("message=%q, want 注明内存热换失败", message)
	}
}

// restored 分支 reloader 调用补 nil 守卫（镜像本函数
// 两处与 CRS 侧口径）——包内直构（测试/未来重构）注入 nil reloader
// 时，回滚还原后的对称重载此前会 panic。nil 语义与 CRS 一致：不尝试重载、
// 不记审计，回滚落库路径照常。
func TestIP2RegionUpdateRun_rollbackReloadSkippedWhenReloaderNil(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	oldReload := reloadIP2RegionSearcher
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		if reloadCalls == 1 {
			return errors.New("forced: install hot-swap failure")
		}
		return Reload()
	}
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = nil

	// When 安装热换失败 → 回滚 restored 分支（nil reloader 不得 panic）
	m.run("manual", nil)

	// Then 磁盘回滚、.bak 消费、DB 记 failed+旧版本
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("live xdb not rolled back: %v", err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal(".bak should be consumed by rollback")
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want v3.0.0 (保持旧版本)", version)
	}
}

func TestIP2RegionUpdateRun_rollbackRenameSuccessReloadFailKeepsBaseline(t *testing.T) {
	// Given：rename 级磁盘还原成功（live=更新前基线 v2，.bak 被消费）
	// 后内存热换失败——不得升级到 copy/dist：rename 已消费 .bak，copy 级必然
	// 失败、dist 必然执行，镜像捆绑的 v1 会覆盖已正确还原的基线，造成
	// 磁盘(dist v1)≠DB(failed+v2) 分叉且基线不可恢复。热换失败仅记 warn，
	// 按 restored=true 返回（内存 searcher 滞后为瞬态，下次 reload/重启自愈）。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	// dist 用不同内容（v1 镜像捆绑版），证明未被复制到 live
	dir := filepath.Dir(ip2regionLivePath)
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, append([]xdbSegment{}, testSegments[1:]...))
	distBytes, err := os.ReadFile(dist)
	if err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, ip2regionLivePath, dist)

	oldReload := reloadIP2RegionSearcher
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		if reloadCalls == 2 {
			return errors.New("forced: post-rename hot-swap failure")
		}
		return Reload()
	}
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload boom")
		}
		return nil
	}

	// When 安装后 reloader 首次失败、rename 还原后的热换被注入失败
	m.run("manual", nil)

	// Then 不升级：live=更新前基线（非 dist 内容）、.bak 被 rename 消费、
	// reloader 重试一次、DB 记 failed+旧版本（磁盘/DB 一致）
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("live xdb should be the restored pre-update baseline: %v", err)
	}
	if string(data) == string(distBytes) {
		t.Fatal("live xdb must NOT be overwritten by dist fallback after disk restore succeeded")
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal(".bak should be consumed by rename restore")
	}
	if reloadCalls != 2 {
		t.Fatalf("reload calls=%d, want 2 (install ok, post-rename fails; no escalation)", reloadCalls)
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, rollback reload retried)", reloads)
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want v3.0.0 (保持旧版本)", version)
	}
}

func TestIP2RegionUpdateRun_rollbackCopySuccessReloadFailKeepsBaseline(t *testing.T) {
	// Given：rename 级被注入失败、copy 级磁盘还原成功（live=更新前
	// 基线）后内存热换失败——同样不得升级到 dist 回退覆盖正确基线（旧实现
	// 会让 live=dist 镜像旧版，磁盘≠DB 分叉且基线虽在盘上但 live 已被污染）。
	// 热换失败仅记 warn，按 restored=true 返回。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(ip2regionLivePath)
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, append([]xdbSegment{}, testSegments[1:]...))
	distBytes, err := os.ReadFile(dist)
	if err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, ip2regionLivePath, dist)

	oldRename := osRename
	osRename = func(src, dst string) error {
		if strings.HasSuffix(src, ".bak") {
			return errors.New("forced: bak rename failure")
		}
		return oldRename(src, dst)
	}
	t.Cleanup(func() { osRename = oldRename })
	oldReload := reloadIP2RegionSearcher
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		if reloadCalls == 2 {
			return errors.New("forced: post-copy hot-swap failure")
		}
		return Reload()
	}
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload boom")
		}
		return nil
	}

	// When 安装后 reloader 首次失败、copy 还原后的热换被注入失败
	m.run("manual", nil)

	// Then 不升级到 dist：live=更新前基线（非 dist 内容）、.bak 被清理（与
	// rename 消费语义对齐）、reloader 重试一次、DB 记 failed+旧版本
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("live xdb should be the restored pre-update baseline: %v", err)
	}
	if string(data) == string(distBytes) {
		t.Fatal("live xdb must NOT be overwritten by dist fallback after disk restore succeeded")
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal(".bak should be removed after successful copy restore")
	}
	if reloadCalls != 2 {
		t.Fatalf("reload calls=%d, want 2 (install ok, post-copy fails; no escalation)", reloadCalls)
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, rollback reload retried)", reloads)
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want v3.0.0 (保持旧版本)", version)
	}
}

func TestIP2RegionUpdateRun_rollbackDistCopySuccessReloadFailKeepsBaseline(t *testing.T) {
	// Given （与同口径的 dist 级情形）：安装热换失败（seam
	// 恒失败），且 .bak 在回滚前丢失（seam 首次调用时删除，模拟极端故障窗
	// 口）——自此.bak 级磁盘还原成功后热换失败不再升级，故只有.bak
	// 缺失才能到达 dist 级。dist copy 成功后磁盘已是 dist 基线（发行版捆绑
	// 旧版），热换失败不得再走 error→fail-open： fail-open 前提「磁盘已
	// 是新库」在 dist copy 成功后不成立，旧实现会记 success+新 tag，造成
	// 磁盘(dist 旧版)≠DB(新 tag) 的永久分叉。修复后与 rename/copy 级同口
	// 径：warn + restored=true，由 run() 记 failed+旧版本。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	dir := filepath.Dir(ip2regionLivePath)
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, append([]xdbSegment{}, testSegments[1:]...))
	distBytes, err := os.ReadFile(dist)
	if err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, ip2regionLivePath, dist)

	oldReload := reloadIP2RegionSearcher
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		if reloadCalls == 1 {
			// 安装热换时点：.bak 已创建（downloadAndInstall 备份先于热换），
			// 删除它使 rollbackXDB 跳过 .bak 级、直达 dist 级。
			if err := os.Remove(ip2regionLivePath + ".bak"); err != nil {
				t.Errorf("remove bak for dist-path forcing: %v", err)
			}
		}
		return errors.New("forced: hot-swap always fails")
	}
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return errors.New("reload boom") }

	// When 安装热换失败、dist copy 落盘成功但 dist 级热换失败
	m.run("manual", nil)

	// Then 不 fail-open：live=dist 基线、DB 记 failed+旧版本（磁盘/DB 一
	// 致），message 保留热换失败注记；reloader 在回滚后补一次重试
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(distBytes) {
		t.Fatalf("live xdb should be the dist baseline after dist restore: %v", err)
	}
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed (dist copy 成功后 fail-open 前提不成立)", status)
	}
	if version != "bundled" {
		t.Fatalf("version=%q, want bundled (dist 回退不得冒称 prevVersion)", version)
	}
	if !strings.Contains(message, "重载 ip2region 内存索引失败") {
		t.Fatalf("message=%q, want 保留热换失败注记", message)
	}
	if reloadCalls != 2 {
		t.Fatalf("reload calls=%d, want 2 (install hot-swap fails, dist-level reload fails)", reloadCalls)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (热换失败跳过首次 reloader，回滚后补一次重试)", reloads)
	}
}

func TestIP2RegionUpdateRun_rollbackRenameFailureFallsBackToCopy(t *testing.T) {
	// Given 升级链第一环：.bak→live 的 rename 失败（权限/IO），但.bak
	// 本身完好——rollbackXDB 不得直接返回 error（旧实现会重演「磁盘/内存新库、
	// DB 记 failed+旧版本」三方分叉），应升级为 copyFile 还原。用 osRename seam
	// 只对 .bak 源注入失败，copyFile 内部的原子 rename 不受影响。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	// 旧 live 用合法 xdb 使 copy 还原后的内存热换成功、走主路径（自此
	// 热换失败不再升级，由 rollbackCopySuccessReloadFailKeepsBaseline 覆盖）。
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	old := osRename
	osRename = func(src, dst string) error {
		if strings.HasSuffix(src, ".bak") {
			return errors.New("forced: bak rename failure")
		}
		return old(src, dst)
	}
	t.Cleanup(func() { osRename = old })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload boom")
		}
		return nil
	}

	// When 安装后首次 reload 失败、.bak rename 被注入失败
	m.run("manual", nil)

	// Then copyFile 升级还原成功：live 回到旧库内容、.bak 被清理（与 rename 消
	// 费语义对齐）、reloader 重试一次、DB 记 failed+旧版本（三方一致）
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("live xdb not restored via copy fallback: %v", err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal(".bak should be removed after successful copy restore")
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, rollback reload succeeds)", reloads)
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want v3.0.0 (保持旧版本)", version)
	}
}

func TestIP2RegionUpdateRun_rollbackAllBaselinesFailOpenRejected(t *testing.T) {
	// Given 升级链全部失败：reloader 首次失败时将 live 替换为目录，
	// 此后 rename（file→dir，EISDIR）与 copyFile（tmp→dir 同样 EISDIR）均失
	// 败，dist 回退的 copyFile 亦失败——rollbackXDB 返回 error，调用方必须改走
	// fail-open（磁盘/内存已是新库，DB 记 success+新 tag 跟随实际状态），不得
	// 记 failed+旧版本。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	oldLive := "old-live-content"
	if err := os.WriteFile(ip2regionLivePath, []byte(oldLive), 0644); err != nil {
		t.Fatal(err)
	}
	// dist 基线存在（copy 目标 live 是目录，dist 回退同样失败）
	dir := filepath.Dir(ip2regionLivePath)
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, testSegments)
	withIP2RegionPaths(t, ip2regionLivePath, dist)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			// 安装已完成：把 live 换成目录，使后续所有还原手段的 rename 全部失败
			if err := os.Remove(ip2regionLivePath); err != nil {
				t.Errorf("remove live for dir swap: %v", err)
			}
			if err := os.Mkdir(ip2regionLivePath, 0755); err != nil {
				t.Errorf("replace live with dir: %v", err)
			}
		}
		return errors.New("reload boom")
	}

	// When 安装成功但 reloader 持续失败、且全部回滚基线均失败
	m.run("manual", nil)

	// Then：回滚全败时 live 是目录（非新工件普通文件）→ fail-open
	// **被拒绝**，DB 记 failed+旧版本（不得把未验证字节认成已生效）。
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed (fail-open precondition must reject a directory live path)", status)
	}
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want v3.0.0 (回写旧版本)", version)
	}
	_ = message
	if info, err := os.Stat(ip2regionLivePath); err != nil || !info.IsDir() {
		t.Fatalf("live path should remain the swapped-in directory (no restore succeeded): %v", err)
	}
	if data, err := os.ReadFile(ip2regionLivePath + ".bak"); err != nil || string(data) != oldLive {
		t.Fatalf(".bak should be preserved untouched when all restore attempts fail: %q, %v", data, err)
	}
	assertNoTempResidue(t, filepath.Dir(ip2regionLivePath))
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (fail-open rejected; no retry reloader)", reloads)
	}
}
func TestIP2RegionUpdateRun_failOpenRejectsDigestAndValidationGates(t *testing.T) {
	for _, mode := range []string{"digest", "validate"} {
		t.Run(mode, func(t *testing.T) {
			m := newTestIP2RegionManager(t)
			seedIP2RegionVersionRow(t, "v3.0.0", true)
			writeTestXDB(t, ip2regionLivePath, testSegments)
			m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
			m.downloadXDB = fakeIP2RegionDownload(t, true)
			reloads := 0
			m.reloader = func() error {
				reloads++
				// 去掉唯一回滚基线，强制进入 fail-open 门；live 保持普通文件，
				// 使摘要不一致与 validate 两门各自成为首个拒绝点。
				if err := os.Remove(ip2regionLivePath + ".bak"); err != nil {
					t.Errorf("remove current backup: %v", err)
				}
				switch mode {
				case "digest":
					m.newXdbSha = strings.Repeat("0", sha256.Size*2)
				case "validate":
					corrupt := []byte("regular but invalid xdb")
					if err := os.WriteFile(ip2regionLivePath, corrupt, 0644); err != nil {
						t.Errorf("corrupt live xdb: %v", err)
					}
					sum := sha256.Sum256(corrupt)
					m.newXdbSha = hex.EncodeToString(sum[:])
				}
				return errors.New("reload boom")
			}

			m.run("manual", nil)

			version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
			if status != "failed" || version != "v3.0.0" {
				t.Fatalf("%s 门拒绝后 (status,version)=(%q,%q), want (failed,v3.0.0)", mode, status, version)
			}
			if m.failOpenPreconditionHolds() {
				t.Fatalf("%s 门被绕过后 failOpenPreconditionHolds()=true", mode)
			}
			if reloads != 1 {
				t.Fatalf("reloads=%d, want 1（拒绝 fail-open 后不得恢复重载）", reloads)
			}
		})
	}
}

func TestStartIP2RegionUpdate_conflictWhenRunning(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	block := make(chan struct{})
	entered := make(chan struct{})
	m.fetchLatestTag = func(context.Context) (string, error) {
		close(entered)
		<-block
		return "v3.0.0", nil
	}
	m.downloadXDB = func(context.Context, string, string, downloadProgressFunc) error { return nil }

	// Given a running update
	if _, err := m.StartUpdate("manual", nil); err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, entered, "IP2Region 冲突用例进入首轮更新")

	// When a second update is requested
	// Then it is rejected with ErrIP2RegionUpdateRunning
	if _, err := m.StartUpdate("manual", nil); !errors.Is(err, ErrIP2RegionUpdateRunning) {
		t.Fatalf("StartUpdate()=%v, want ErrIP2RegionUpdateRunning", err)
	}
	if !m.IsRunning() {
		t.Fatal("IsRunning()=false while update in flight")
	}

	close(block)
	waitUpdateTestSignal(t, m.runDone, "IP2Region 冲突用例首轮更新")
	if m.IsRunning() {
		t.Fatal("IsRunning()=true after run finished")
	}
}

func TestSetIP2RegionAutoUpdate_preservesVersion(t *testing.T) {
	m := newTestIP2RegionManager(t)
	_ = m
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	// When toggling auto update off
	if err := SetIP2RegionAutoUpdate(false); err != nil {
		t.Fatal(err)
	}

	// Then the version is preserved
	version, _, _, _, _, _, autoUpdate := ip2RegionVersionRow(t)
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want preserved old-commit", version)
	}
	if autoUpdate {
		t.Fatal("auto_update should be false")
	}
}

func countIP2RegionFailedAudits(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='IP数据库' AND action='更新失败'").Scan(&n); err != nil {
		t.Fatalf("count failed audit entries: %v", err)
	}
	return n
}

// （2026-09-29 裁定口径）：操作审计由 run() 的 defer 每轮单记——
// fail() 本体零审计（曾内联「仅首败审计」，与 defer 双记已撤）。
func TestIP2RegionUpdateFail_auditRecordedByRunDeferPerRun(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	// fail() 直调不产生操作审计（计数器职责保留）
	m.fail(errors.New("第一次失败"))
	if got := countIP2RegionFailedAudits(t); got != 0 {
		t.Fatalf("fail() 直调应零审计, got %d", got)
	}

	// 镜像 CRS 版补 run() 级断言——经 run() 的失败轮
	// 每轮恰 1 条（defer 单记）。
	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("查询失败") }
	m.run("auto", nil)
	if got := countIP2RegionFailedAudits(t); got != 1 {
		t.Fatalf("一次失败 run 应 1 条审计, got %d", got)
	}
}

// 计数 UPDATE 失败不得影响审计口径：run() 的 defer 每轮恰记 1 条失败审计，
// 与 fail() 中连续失败计数（同一版本行 UPDATE）是否落库完全解耦。
// （旧用例断言「预读计数+1 判定审计」——该内联审计早已撤销，用例恒真。）
func TestIP2RegionUpdateFail_counterUpdateFailureStillAuditsOncePerRun(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	// 注入版本行 UPDATE 失败（fail() 的计数落库与 run 的 mark-start 同表）
	if _, err := db.DB.Exec(`CREATE TRIGGER ip2r_fail_counter_update BEFORE UPDATE ON security_ip2region_version
		BEGIN SELECT RAISE(ABORT, 'injected counter update failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS ip2r_fail_counter_update") })

	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("查询失败") }
	m.run("auto", nil)

	if got := countIP2RegionFailedAudits(t); got != 1 {
		t.Fatalf("失败 run 的审计条数=%d, want 1（计数落库失败不得改变审计口径）", got)
	}
}

func TestWriteIP2RegionUpdateLog_rotatesBeforeWriteAtSize(t *testing.T) {
	// 旧用例名声称「尺寸轮转」但只断言行数（未覆盖写前尺寸
	// 滚动）——此处按真实阈值驱动：预置接近阈值的历史内容，写入一行必须
	// 先滚动到 .1，活动文件只含新行。随后放宽阈值再验证 tee 单点（每行只
	// 写一次）。
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir("") })
	taskengine.SetTaskLogSizeBytesFn(func() int64 { return 64 })
	t.Cleanup(func() { taskengine.SetTaskLogSizeBytesFn(nil) })

	path := taskengine.TaskLogPath("ip2region")
	history := strings.Repeat("h", 60)
	if err := os.WriteFile(path, []byte(history), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：一行写入使 size+line 超阈
	WriteIP2RegionUpdateLog("INFO", "checking", "x")

	// Then：写前滚动——.1 保留滚动前字节，活动文件只含新行
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("写前尺寸滚动未发生（.1 缺失）: %v", err)
	}
	if len(rotated) != len(history) {
		t.Fatalf(".1 大小=%d, want %d（滚动应保留滚动前全部字节）", len(rotated), len(history))
	}
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(active), history) {
		t.Fatalf("活动文件仍含滚动前内容: %q", active)
	}
	if !strings.Contains(string(active), "[INFO] checking - x") {
		t.Fatalf("活动文件缺少滚动后的新行: %q", active)
	}

	// tee 单点：放宽阈值后 100 行写入应恰 100 行
	taskengine.SetTaskLogSizeBytesFn(func() int64 { return 1 << 20 })
	for range 100 {
		WriteIP2RegionUpdateLog("INFO", "tee", "y")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "[INFO] tee - y"); n != 100 {
		t.Fatalf("100 行写入应恰 100 行（tee 单点），got %d", n)
	}
}

// 裁定 2026-09-07（残余项处置）：IP 库更新触发的真实 Caddy 重载统一留痕
// （system 归因，对齐 certissuer/集群同步的既有口径）。
func TestIP2RegionUpdate_recordsReloadAudit(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { return nil }
	m.run("manual", nil)

	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务' AND detail LIKE '%IP 库更新%'").Scan(&n); err != nil {
		t.Fatalf("query reload audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("reload audit rows=%d, want 1（真实重载必须留痕）", n)
	}
}

func TestIP2RegionUpdate_recordsReloadFailureAudit(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { return errors.New("reload boom") }
	m.run("manual", nil)

	// 主重载失败 + 回滚后的恢复重载失败 = 2 行「重载失败」
	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='重载失败' AND resource='Caddy服务' AND detail LIKE '%IP 库更新%'").Scan(&n); err != nil {
		t.Fatalf("query reload failure audit: %v", err)
	}
	if n != 2 {
		t.Fatalf("reload failure audit rows=%d, want 2（主重载+回滚恢复重载）", n)
	}
}

// demote 竞态从节点中止口径镜像 CRS——起点角色复查中止须落 skipped 终态并
// 审计「更新跳过」，
// 不得记「更新失败」（从节点中止是正常语义，非故障）。
func TestIP2RegionUpdateRun_slaveAbortsSkipSemantics(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }

	// Given 从节点角色（demote 竞态窗口内）；When 经 StartUpdate（生产入口）驱动：
	// state 置 trigger 后 StatusSnapshot 读内存终态（直调 run() 时 state 无 trigger
	// 会回退行状态，观察不到中止终态）。
	done, err := m.StartUpdate("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, done, "从节点中止的 IP2Region 更新")

	// Then 内存终态=skipped（非 failed），审计记「更新跳过」非「更新失败」
	snap := m.StatusSnapshot()
	if snap.Status != "skipped" {
		t.Fatalf("status=%q, want skipped（从节点中止是跳过语义，镜像 CRS）", snap.Status)
	}
	var failed, skipped int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='IP数据库' AND action='更新失败'").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='IP数据库' AND detail LIKE '%更新跳过%'").Scan(&skipped); err != nil {
		t.Fatal(err)
	}
	if failed != 0 || skipped != 1 {
		t.Fatalf("failed=%d skipped=%d, want 0/1（从节点中止不得记更新失败）", failed, skipped)
	}
}

func TestIP2RegionUpdateRun_usesTaskRunStartedAt(t *testing.T) {
	// Given：task_runs 预插行与期望 UTC 时刻。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("stop after start") }
	runID, wantUTC := seedTaskRunForTime(t, "ip2region", "2026-10-17 14:09:17")

	// When：经生产 StartUpdate 入口运行。
	done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: context.Background(), RunID: runID, Trigger: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, done, "使用 task_runs 时间的 IP2Region 更新")

	// Then：版本行 started_at 与 task_runs 同源。
	var startedAt string
	if err := db.DB.QueryRow(`SELECT COALESCE(started_at,'') FROM security_ip2region_version WHERE id=1`).Scan(&startedAt); err != nil {
		t.Fatal(err)
	}
	if startedAt != wantUTC {
		t.Fatalf("started_at=%q, want task_runs 同源 UTC %q", startedAt, wantUTC)
	}
}

func TestIP2RegionUpdateRun_bundledSentinelCanEstablishRemoteBaseline(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "bundled", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { return nil }

	m.run("manual", nil)

	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" || version != "v3.1.0" {
		t.Fatalf("bundled baseline update: version=%q status=%q, want v3.1.0/success", version, status)
	}
}

func TestIP2RegionFailOpenPrecondition_rejectsMissingLive(t *testing.T) {
	m := newTestIP2RegionManager(t)
	m.newXdbSha = "deadbeef"
	if m.failOpenPreconditionHolds() {
		t.Fatal("missing live xdb must not satisfy fail-open precondition")
	}
}

// 陈旧.bak 只在本运行创建时才可清理（成功路径）。
func TestIP2RegionUpdateRun_freshInstallKeepsStaleBakOnSuccess(t *testing.T) {
	// Given 全新部署（live 缺失→本轮不建备份）+ 跨运行残留 .bak
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "unknown", true)
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	stale := []byte("stale-bak-from-crashed-run")
	if err := os.WriteFile(live+".bak", stale, 0644); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { return nil }

	// When 更新成功
	m.run("manual", nil)

	// Then 陈旧 .bak 原样保留（bakCreated=false → 不得清理他运行的恢复副本）
	got, err := os.ReadFile(live + ".bak")
	if err != nil || string(got) != string(stale) {
		t.Fatalf("成功路径删除了非本运行创建的陈旧 .bak: %q, %v", got, err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("live xdb 未安装: %v", err)
	}
	if _, status, _, _, _, _, _ := ip2RegionVersionRow(t); status != "success" {
		t.Fatalf("update_status=%q, want success", status)
	}
}

// 安装 rename 失败路径同样不得清理非本运行的.bak。
func TestIP2RegionUpdateRun_freshInstallKeepsStaleBakOnRenameFailure(t *testing.T) {
	// Given 同上，但安装 rename 失败（安装未发生）
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "unknown", true)
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	stale := []byte("stale-bak-from-crashed-run")
	if err := os.WriteFile(live+".bak", stale, 0644); err != nil {
		t.Fatal(err)
	}
	oldRename := osRename
	osRename = func(src, dst string) error {
		if dst == live {
			return errors.New("forced rename failure")
		}
		return oldRename(src, dst)
	}
	t.Cleanup(func() { osRename = oldRename })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { return nil }

	// When
	m.run("manual", nil)

	// Then 安装未发生且陈旧 .bak 未被删除
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("rename 失败后 live 不应存在: %v", err)
	}
	got, err := os.ReadFile(live + ".bak")
	if err != nil || string(got) != string(stale) {
		t.Fatalf("rename 失败路径删除了非本运行创建的陈旧 .bak: %q, %v", got, err)
	}
}

// 截断 xdb（头部完好、整体短小）必须被安装校验拒绝且不得 panic：
// BufferCache 装载只校验 256B 头，探针搜索的向量索引切片越界在旧实现是
// 进程级 panic。
func TestValidateIP2RegionXDB_rejectsTruncatedXDBWithoutPanic(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "full.xdb")
	writeTestXDB(t, full, testSegments)
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	// 头部（256B）+ 部分向量索引：NewV4Config 全部校验通过，但
	// 114.114.114.114 探针的向量索引偏移 234640 已越出文件。
	truncated := filepath.Join(dir, "truncated.xdb")
	if err := os.WriteFile(truncated, data[:100000], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateIP2RegionXDB(truncated); err == nil {
		t.Fatal("截断的 xdb 必须被校验拒绝")
	}
}

// 结构自检门通过但段数据指针损坏的 xdb：探针搜索在绑定库内 panic，
// 校验必须把 panic 转成错误（不得外溢为进程崩溃）。
func TestValidateIP2RegionXDB_recoversProbePanicOnCorruptSegment(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "corrupt.xdb")
	writeTestXDB(t, full, testSegments)
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	// 改写 114.114.x.x 的向量索引条目：非零起点（绕过零指针短路）+
	// 巨大终点 → 二分首读即越出内容缓冲（头内段索引指针保持原值，
	// 结构自检门不受影响）。
	const vectorEntryOff = 256 + (114*256+114)*8
	binary.LittleEndian.PutUint32(data[vectorEntryOff:], 524544)
	binary.LittleEndian.PutUint32(data[vectorEntryOff+4:], 0x7FFFFF00)
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateIP2RegionXDB(full); err == nil {
		t.Fatal("段数据指针损坏的 xdb 必须被校验拒绝（recover 转错误）")
	} else if !strings.Contains(err.Error(), "内部异常") && !strings.Contains(err.Error(), "搜索失败") {
		t.Fatalf("错误须指明校验失败: %v", err)
	}
}

// 更新 goroutine 内的 panic（热换/reloader 等任意环节）必须被拦截并落定
// failed 终态——裸 goroutine 的未捕获 panic=进程退出。
func TestIP2RegionStartUpdate_recoversPanickingRun(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { panic("injected reloader panic") }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, done, "panic 恢复的 IP2Region 更新")

	_, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("status=%q, want failed（panic 必须落定失败终态）", status)
	}
	if !strings.Contains(message, "injected reloader panic") {
		t.Fatalf("message=%q, want 携带 panic 内容", message)
	}
	if m.IsRunning() {
		t.Fatal("running 标记必须已复位")
	}
}

// 更新前版本不可知（行存在但版本为空串，或行缺失）时的回滚：磁盘已还原为更新前
// 字节，版本行/sidecar 不得停留在安装段写入的新 tag——那会让下一轮
// tag == currentVersion 命中「已是最新」短路，旧库永不重装（自愈通道关闭）。
// 修复后写保守标识 bundled，下一轮远端数值 tag 能重建基线。
func TestIP2RegionUpdateRun_rollbackWithUnknownPreviousVersionWritesSentinel(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	oldBytes, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	oldReload := reloadIP2RegionSearcher
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		if reloadCalls == 1 {
			return errors.New("forced: install hot-swap failure")
		}
		return Reload()
	}
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { return nil }

	// When 安装后热换失败 → 回滚（磁盘还原、版本行未知）
	m.run("manual", nil)

	// Then 磁盘回到更新前字节，版本行与 sidecar 都不是新 tag，而是保守标识
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(oldBytes) {
		t.Fatalf("live xdb 未还原到更新前基线: %v", err)
	}
	version, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if version == "v3.1.0" {
		t.Fatalf("version=%q：回滚后版本行不得停留在安装段写入的新 tag（磁盘旧/行新）", version)
	}
	if version != "bundled" {
		t.Fatalf("version=%q, want bundled（版本不可知的唯一表达）", version)
	}
	sidecar, err := os.ReadFile(ip2regionLivePath + ".version")
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if got := strings.TrimSpace(string(sidecar)); got != "bundled" {
		t.Fatalf("sidecar=%q, want bundled", got)
	}

	// And 自愈：下一轮远端仍是 v3.1.0 时不得走「已是最新」短路——必须重装。
	var fetched int
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetched++
		return "v3.1.0", nil
	}
	reloadIP2RegionSearcher = func() error { return nil }
	m.run("manual", nil)
	if fetched == 0 {
		t.Fatal("回滚后的下一轮未重新拉取远端 tag（被「已是最新」短路）")
	}
	version, status, _, _, _, _, _ = ip2RegionVersionRow(t)
	if status != "success" || version != "v3.1.0" {
		t.Fatalf("自愈轮 version=%q status=%q, want v3.1.0/success", version, status)
	}
}
