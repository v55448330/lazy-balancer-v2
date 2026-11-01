package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// —— 单任务双源更新（IPv6 数据源）——
//
// 语义钉测：v4 主链结果定性任务终态；v6 源独立安装/独立落库（成功=版本行+
// sidecar+success，失败=failed+WARN 不反噬 v4 的 success）；「已是最新」短路
// 按 v4/v6 各自货币性分派（v4 最新但 v6 未装 → 仅补 v6）。

// seedV6Row 种 v6 开关与版本（行必已存在——seedIP2RegionVersionRow 先行）。
func seedV6Row(t *testing.T, enabled bool, version string) {
	t.Helper()
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET v6_enabled=?, v6_version=? WHERE id=1", enabled, version); err != nil {
		t.Fatal(err)
	}
}

func fakeV6Download(t *testing.T, valid bool) func(context.Context, string, string, downloadProgressFunc) error {
	t.Helper()
	return func(_ context.Context, _ string, dest string, _ downloadProgressFunc) error {
		if !valid {
			return os.WriteFile(dest, []byte("not an xdb"), 0644)
		}
		writeTestXDBV6(t, dest, defaultV6TestSegments())
		return nil
	}
}

func TestIP2RegionUpdateRun_dualSource_installsBothFamilies(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	seedV6Row(t, true, "")
	writeTestXDB(t, ip2regionLivePath, testSegments)
	withIP2RegionV6Paths(t, filepath.Join(filepath.Dir(ip2regionLivePath), "ip2region_v6.xdb"), filepath.Join(filepath.Dir(ip2regionLivePath), "missing-dist-v6.xdb"))

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.downloadXDBV6 = fakeV6Download(t, true)
	m.run("manual", nil)

	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if version != "v3.1.0" || status != "success" {
		t.Fatalf("v4 row version=%q status=%q message=%q, want v3.1.0/success", version, status, message)
	}
	v6Version, err := GetIP2RegionV6Version()
	if err != nil || v6Version != "v3.1.0" {
		t.Fatalf("v6 version=%q err=%v, want v3.1.0", v6Version, err)
	}
	if _, err := os.Stat(ip2regionV6LivePath); err != nil {
		t.Fatalf("v6 live file must be installed: %v", err)
	}
	if _, err := os.Stat(ip2regionV6LivePath + ".version"); err != nil {
		t.Fatalf("v6 sidecar must be written: %v", err)
	}
	if status, _ := v6SourceStatus(t); status != "success" {
		t.Fatalf("v6 source status=%q, want success", status)
	}
	if _, err := os.Stat(ip2regionV6LivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("v6 bak must be cleaned on success: %v", err)
	}
}

func TestIP2RegionUpdateRun_v6FailureDoesNotDragV4(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	seedV6Row(t, true, "")
	writeTestXDB(t, ip2regionLivePath, testSegments)
	withIP2RegionV6Paths(t, filepath.Join(filepath.Dir(ip2regionLivePath), "ip2region_v6.xdb"), filepath.Join(filepath.Dir(ip2regionLivePath), "missing-dist-v6.xdb"))

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.downloadXDBV6 = fakeV6Download(t, false)
	m.run("manual", nil)

	version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if version != "v3.1.0" || status != "success" {
		t.Fatalf("v4 must stay success when v6 fails: version=%q status=%q message=%q", version, status, message)
	}
	srcStatus, srcMessage := v6SourceStatus(t)
	if srcStatus != "failed" || !strings.Contains(srcMessage, "校验") && !strings.Contains(srcMessage, "下载") {
		t.Fatalf("v6 source must record failure: status=%q message=%q", srcStatus, srcMessage)
	}
	if _, err := os.Stat(ip2regionV6LivePath); !os.IsNotExist(err) {
		t.Fatalf("broken v6 must not be installed: %v", err)
	}
}

func TestIP2RegionUpdateRun_v4CurrentV6Missing_installsV6Only(t *testing.T) {
	m := newTestIP2RegionManager(t)
	// v4 已是 v3.1.0（远端 tag 相同）；v6 刚开启未装——「已是最新」短路必须
	// 放行进安装段补齐 v6（v4 不再下载/换库）。
	seedIP2RegionVersionRow(t, "v3.1.0", true)
	seedV6Row(t, true, "")
	writeTestXDB(t, ip2regionLivePath, testSegments)
	liveBefore, err := os.ReadFile(ip2regionLivePath)
	if err != nil {
		t.Fatal(err)
	}
	withIP2RegionV6Paths(t, filepath.Join(filepath.Dir(ip2regionLivePath), "ip2region_v6.xdb"), filepath.Join(filepath.Dir(ip2regionLivePath), "missing-dist-v6.xdb"))

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	v4Downloads := 0
	m.downloadXDB = func(ctx context.Context, tag, dest string, progress downloadProgressFunc) error {
		v4Downloads++
		return fakeIP2RegionDownload(t, true)(ctx, tag, dest, progress)
	}
	m.downloadXDBV6 = fakeV6Download(t, true)
	m.run("manual", nil)

	if v4Downloads != 0 {
		t.Fatalf("v4 current must skip download, got %d downloads", v4Downloads)
	}
	if liveAfter, err := os.ReadFile(ip2regionLivePath); err != nil || string(liveAfter) != string(liveBefore) {
		t.Fatalf("v4 live must be untouched: err=%v sameBytes=%v", err, liveAfter != nil && string(liveAfter) == string(liveBefore))
	}
	if v6Version, verr := GetIP2RegionV6Version(); verr != nil || v6Version != "v3.1.0" {
		t.Fatalf("v6 must be installed: version=%q err=%v", v6Version, verr)
	}
}

func TestIP2RegionUpdateRun_v6Disabled_skipsV6Segment(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	seedV6Row(t, false, "")
	writeTestXDB(t, ip2regionLivePath, testSegments)
	withIP2RegionV6Paths(t, filepath.Join(filepath.Dir(ip2regionLivePath), "ip2region_v6.xdb"), filepath.Join(filepath.Dir(ip2regionLivePath), "missing-dist-v6.xdb"))

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	v6Downloads := 0
	m.downloadXDBV6 = func(ctx context.Context, tag, dest string, progress downloadProgressFunc) error {
		v6Downloads++
		return fakeV6Download(t, true)(ctx, tag, dest, progress)
	}
	m.run("manual", nil)

	if v6Downloads != 0 {
		t.Fatalf("v6 disabled must skip download, got %d", v6Downloads)
	}
	if _, err := os.Stat(ip2regionV6LivePath); !os.IsNotExist(err) {
		t.Fatalf("v6 disabled must not install v6 file: %v", err)
	}
}

func v6SourceStatus(t *testing.T) (status, message string) {
	t.Helper()
	err := db.DB.QueryRow("SELECT COALESCE(v6_update_status,''), COALESCE(v6_message,'') FROM security_ip2region_version WHERE id=1").Scan(&status, &message)
	if err != nil {
		t.Fatal(err)
	}
	return status, message
}
