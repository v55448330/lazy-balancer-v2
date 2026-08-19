package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func newTestIP2RegionManager(t *testing.T) *IP2RegionUpdateManager {
	t.Helper()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	oldLogDir := ip2RegionUpdateLogDir
	ip2RegionUpdateLogDir = t.TempDir()
	t.Cleanup(func() { ip2RegionUpdateLogDir = oldLogDir })

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

func fakeIP2RegionDownload(t *testing.T, valid bool) func(context.Context, string, string) error {
	t.Helper()
	return func(_ context.Context, _ string, dest string) error {
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

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When a manual update runs to completion
	m.run("manual")

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
	// R39 1.2：成功后 .bak 须清理，不残留陈旧备份
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("live xdb .bak should be cleaned after success")
	}
}

func TestIP2RegionUpdateRun_skipWhenSameVersion(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string) error { downloadCalled = true; return nil }
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When an update finds the same commit
	m.run("auto")

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
}

func TestIP2RegionUpdateRun_fetchFailure(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("network error") }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string) error { downloadCalled = true; return nil }
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the commit check fails
	m.run("manual")

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
	m.run("manual")

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
	// restoreBackup+重试路径，R39 1.2）：reloader 失败时磁盘不得停留在新库、DB
	// 记录旧版本+failed 的不一致状态。旧 live 必须是合法 xdb——R46 B-F1 起
	// 还原后的内存热换失败视为该级还原失败，非法内容会触发升级链而非还原成功。
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
	m.run("manual")

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
	// Given 跨运行崩溃窗口残留的陈旧 .bak（R40 F1）：上一运行在 rename 成功后、
	// reloader 前崩溃，.bak 是旧 xdb 唯一副本。本运行 live 原本缺失（不创建新
	// 备份，bakCreated=false），reloader 失败时 rollbackXDB 不得消费该陈旧副本。
	// R44 F1 起 bakCreated==false 且 dist 缺失时走 fail-open：磁盘/内存已是新库，
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
	m.run("manual")

	// Then 陈旧 .bak 原样保留（未被回滚消费），live 不被还原到陈旧副本；
	// 无基线可用时按 fail-open 记 success+新 tag（R44 F1）
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
		t.Fatalf("update_status=%q, want success (R44 F1 fail-open)", status)
	}
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0 (fail-open 记录新 tag)", version)
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (R45 F1-C：fail-open 落库前补一次 reloader 重试)", reloads)
	}
}

func TestIP2RegionUpdateRun_reloadFailureFallsBackToDistOnFreshInstall(t *testing.T) {
	// Given 全新部署：live xdb 不存在（无旧库可备份，bakCreated=false），dist
	// 基线存在。reloader 必然失败一次——R44 F1 修复前 rollbackXDB 静默跳过，
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
	m.run("manual")

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
	if version != "unknown" {
		t.Fatalf("version=%q, want unknown (保持旧版本)", version)
	}
}

func TestIP2RegionUpdateRun_reloadFailureFailOpenWhenNoBaseline(t *testing.T) {
	// Given 全新部署且 dist 也缺失（newTestIP2RegionManager 默认 dist 指向不
	// 存在路径）：无任何「更新前基线」可回退，R44 F1 fail-open——磁盘/内存已
	// 是新库，DB 按成功落库保持三方一致。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "unknown", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return errors.New("reload boom") }

	// When 安装成功、reloader 持续失败、且无任何基线可回退
	m.run("manual")

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
		t.Fatalf("reloads=%d, want 2 (R45 F1-C：fail-open 落库前补一次 reloader 重试)", reloads)
	}
}

func TestIP2RegionUpdateRun_installReloadFailureGoesToRollback(t *testing.T) {
	// Given R46 B-F1：安装 rename 成功但内存热换失败（seam 注入首次调用失败）——
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
	m.run("manual")

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
		t.Fatalf("version=%q, want v3.0.0 (保持旧版本)", version)
	}
	if !strings.Contains(message, "重载 ip2region 内存索引失败") {
		t.Fatalf("message=%q, want 注明内存热换失败", message)
	}
}

func TestIP2RegionUpdateRun_rollbackReloadFailureEscalatesToDist(t *testing.T) {
	// Given R46 B-F1：回滚级别的内存热换失败视为该级还原失败——osRename 注入
	// .bak rename 失败使 copy 级生效，copy 还原后热换失败（seam 第 2 次调用），
	// 必须继续升级到 dist 回退而非按 restored 返回（否则磁盘=旧库、内存=新库、
	// DB=failed+旧版本，三方分叉复现）。
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
	m.run("manual")

	// Then 升级到 dist 回退成功：live=dist 基线、DB 记 failed+旧版本、
	// reloader 重试一次（三方一致，均为「更新前基线」口径）
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != string(distBytes) {
		t.Fatalf("live xdb not restored via dist fallback: %v", err)
	}
	if reloadCalls != 3 {
		t.Fatalf("reload calls=%d, want 3 (install ok, post-copy fails, post-dist succeeds)", reloadCalls)
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

func TestIP2RegionUpdateRun_rollbackAllReloadsFailFailOpenMemoryNote(t *testing.T) {
	// Given R46 B-F1 最坏路径：安装热换失败（seam 恒失败），回滚升级链的磁盘
	// 操作部分成功（rename 还原、dist 回退均落盘）但每一级的内存热换都失败——
	// rollbackXDB 必须返回 error，调用方走 fail-open（DB 跟随实际状态），且
	// message 必须注明「内存 searcher 未切换，重启后生效」：DB 记 success 而
	// 内存仍是旧库，重启前这是唯一可见痕迹。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	writeTestXDB(t, ip2regionLivePath, testSegments)
	dir := filepath.Dir(ip2regionLivePath)
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, append([]xdbSegment{}, testSegments[1:]...))
	withIP2RegionPaths(t, ip2regionLivePath, dist)

	oldReload := reloadIP2RegionSearcher
	reloadCalls := 0
	reloadIP2RegionSearcher = func() error {
		reloadCalls++
		return errors.New("forced: hot-swap always fails")
	}
	t.Cleanup(func() { reloadIP2RegionSearcher = oldReload })

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return errors.New("reload boom") }

	// When 安装热换失败且回滚各级热换全部失败
	m.run("manual")

	// Then fail-open：DB 记 success+新 tag，message 同时保留重载失败警告与
	// 「内存 searcher 未切换，重启后生效」注记；reloader 仅在 fail-open 落库前
	// 按 F1-C 补一次重试
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success (fail-open)", status)
	}
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0 (fail-open 记录新 tag)", version)
	}
	if !strings.Contains(message, "内存 searcher 未切换，重启后生效") {
		t.Fatalf("message=%q, want 注明内存 searcher 未切换、重启后生效", message)
	}
	if !strings.Contains(message, "重载 Caddy 配置失败") {
		t.Fatalf("message=%q, want 保留重载失败警告", message)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (热换失败跳过首次 reloader，fail-open 落库前补一次重试)", reloads)
	}
}

func TestIP2RegionUpdateRun_rollbackRenameFailureFallsBackToCopy(t *testing.T) {
	// Given R45 F1-A 升级链第一环：.bak→live 的 rename 失败（权限/IO），但 .bak
	// 本身完好——rollbackXDB 不得直接返回 error（旧实现会重演「磁盘/内存新库、
	// DB 记 failed+旧版本」三方分叉），应升级为 copyFile 还原。用 osRename seam
	// 只对 .bak 源注入失败，copyFile 内部的原子 rename 不受影响。
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	// 旧 live 用合法 xdb：R46 B-F1 起 copy 还原后的内存热换计入该级成败，
	// 非法内容会让热换失败、继续升级而非还原成功。
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
	m.run("manual")

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

func TestIP2RegionUpdateRun_rollbackAllBaselinesFailFailOpen(t *testing.T) {
	// Given R45 F1-A 升级链全部失败：reloader 首次失败时将 live 替换为目录，
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
	m.run("manual")

	// Then 调用方走 fail-open：DB 记 success+新 tag，message 保留重载失败警告
	// 并注明 Caddy 侧待下次重载生效；.bak 未被消费（保全副本）；fail-open 路径
	// 按 F1-C 补一次 reloader 重试
	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success (R45 F1-A fail-open)", status)
	}
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0 (fail-open 记录新 tag)", version)
	}
	if !strings.Contains(message, "重载 Caddy 配置失败") || !strings.Contains(message, "待下次重载生效") {
		t.Fatalf("message=%q, want 重载失败警告并注明 Caddy 侧待下次重载生效", message)
	}
	if info, err := os.Stat(ip2regionLivePath); err != nil || !info.IsDir() {
		t.Fatalf("live path should remain the swapped-in directory (no restore succeeded): %v", err)
	}
	if data, err := os.ReadFile(ip2regionLivePath + ".bak"); err != nil || string(data) != oldLive {
		t.Fatalf(".bak should be preserved untouched when all restore attempts fail: %q, %v", data, err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("copyFile tmp residue should be cleaned up after failed restore")
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, fail-open retry fails)", reloads)
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
	m.downloadXDB = func(context.Context, string, string) error { return nil }

	// Given a running update
	if err := m.StartUpdate("manual"); err != nil {
		t.Fatal(err)
	}
	<-entered

	// When a second update is requested
	// Then it is rejected with ErrIP2RegionUpdateRunning
	if err := m.StartUpdate("manual"); !errors.Is(err, ErrIP2RegionUpdateRunning) {
		t.Fatalf("StartUpdate()=%v, want ErrIP2RegionUpdateRunning", err)
	}
	if !m.IsRunning() {
		t.Fatal("IsRunning()=false while update in flight")
	}

	close(block)
	<-m.runDone
	if m.IsRunning() {
		t.Fatal("IsRunning()=true after run finished")
	}
}

func TestIP2RegionSchedulerTick_autoOffDoesNothing(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", false)

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v3.0.0", nil
	}

	// When the scheduler ticks with auto_update off
	m.schedulerTick(time.Now())

	// Then nothing happens and next_update stays empty
	if fetchCalled {
		t.Fatal("no update should run when auto_update is off")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("next_update=%q, want empty", nextUpdate)
	}
}

func TestIP2RegionSchedulerTick_initializesNextUpdate(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v3.0.0", nil
	}

	// When the scheduler ticks with auto on and no next_update recorded
	m.schedulerTick(now)

	// Then next_update is scheduled 24h out without running immediately
	if fetchCalled {
		t.Fatal("first tick should only schedule, not run")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	want := now.Add(24 * time.Hour).Format(crsTimeLayout)
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want %q", nextUpdate, want)
	}
}

func TestIP2RegionSchedulerTick_runsWhenDue(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1",
		now.Add(-time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}

	fetched := make(chan struct{})
	var fetchOnce func()
	fetchOnce = func() { close(fetched) }
	m.fetchLatestTag = func(context.Context) (string, error) {
		if fetchOnce != nil {
			fetchOnce()
			fetchOnce = nil
		}
		return "v3.0.0", nil // same version -> auto no-op, finishes fast
	}

	// When the scheduler ticks past next_update
	m.schedulerTick(now)

	// Then an auto update starts and next_update is pushed 24h out
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("due scheduler tick should start an auto update")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	want := now.Add(24 * time.Hour).Format(crsTimeLayout)
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want %q", nextUpdate, want)
	}
}

func TestIP2RegionSchedulerTick_slaveSkips(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v3.0.0", nil
	}

	// When the scheduler ticks on a slave node
	m.schedulerTick(time.Now())

	// Then it does nothing
	if fetchCalled {
		t.Fatal("slave node must not run IP2Region updates")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("next_update=%q, want empty on slave", nextUpdate)
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
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='IP2Region 数据库' AND action='更新' AND detail LIKE '%结果：失败%'").Scan(&n); err != nil {
		t.Fatalf("count failed audit entries: %v", err)
	}
	return n
}

func TestIP2RegionUpdateFail_auditsOnlyFirstFailure(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	// Given a first consecutive failure: audited once (counter 0 → 1)
	m.fail(errors.New("第一次失败"))
	if got := countIP2RegionFailedAudits(t); got != 1 {
		t.Fatalf("failed audits after 1st failure = %d, want 1", got)
	}

	// When the second consecutive failure occurs (counter 1 → 2)
	// Then no duplicate audit is written (R36 F3)
	m.fail(errors.New("第二次失败"))
	if got := countIP2RegionFailedAudits(t); got != 1 {
		t.Fatalf("failed audits after 2nd failure = %d, want 1 (no duplicate)", got)
	}
}

func TestIP2RegionUpdateFail_counterUpdateFailureDoesNotReaudit(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	// 模拟第 1 次失败已落库（计数=1、已审计）；随后计数 UPDATE 持续失败（RAISE
	// ABORT 触发器）：审计判定必须用「预读计数+1」=2，不得回退到旧计数 1 导致
	// 第 2 次失败重复写审计（R36 F3）。
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET consecutive_failures=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER ip2r_fail_counter_update BEFORE UPDATE ON security_ip2region_version
		BEGIN SELECT RAISE(ABORT, 'injected counter update failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS ip2r_fail_counter_update") })

	m.fail(errors.New("第二次失败"))

	if got := countIP2RegionFailedAudits(t); got != 0 {
		t.Fatalf("failed audits = %d, want 0（UPDATE 失败时旧代码会重复审计）", got)
	}
}

func TestWriteIP2RegionUpdateLog_rotatesAtSize(t *testing.T) {
	dir := t.TempDir()
	oldDir := ip2RegionUpdateLogDir
	ip2RegionUpdateLogDir = dir
	t.Cleanup(func() { ip2RegionUpdateLogDir = oldDir })

	path := IP2RegionUpdateLogPath()
	for i := 0; i < 2000; i++ {
		writeIP2RegionUpdateLog("INFO", "checking", "x")
	}

	// Then the primary log file exists and the size cap keeps rotation bounded
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 2*getCertJobLogSizeBytes() {
		t.Fatalf("log size=%d exceeds rotation cap", info.Size())
	}
}
