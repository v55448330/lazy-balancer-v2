package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 树交换段的 prevTag 必须 fail-visible——读版本行失败时不得用展示
// 口径回落 bundled 继续换树（重载失败回滚会把 bundled 写成真实版本）。
func TestCRSSwap_prevTagReadFailureAbortsBeforeVersionWrite(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule live-v414")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# user setup")

	orig := crsCurrentVersionForRun
	t.Cleanup(func() { crsCurrentVersionForRun = orig })
	calls := 0
	crsCurrentVersionForRun = func() (string, error) {
		calls++
		if calls == 1 { // run 的「已是最新」判定读成功
			return "v4.14.0", nil
		}
		return "", errors.New("注入的版本行读取故障")
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	m.reloader = func() error { return nil }

	m.run("manual", nil)

	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed（版本读取故障应中止更新）", status)
	}
	if !strings.Contains(message, "版本") {
		t.Fatalf("message=%q, want 版本读取失败原因", message)
	}
	// 版本行必须保持旧值（bundled/tag 都不得写入）
	if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.14.0" {
		t.Fatalf("version=%q, want v4.14.0（读故障时不得回落 bundled 写版本行）", version)
	}
	// 规则树已回滚到本运行前
	if data, _ := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile)); string(data) != "SecRule live-v414" {
		t.Fatalf("live rules=%q, want 回滚到更新前", data)
	}
}

// 合法但仅 1 段的 xdb（header StartIndexPtr == EndIndexPtr）不是空库。
func TestIP2Region_singleSegmentXDBIsNotEmpty(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|0|CN"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	// 条目数与在役 searcher 同源：装载该 xdb 后才应报条目数（读 live 路径的旧
	// 语义在只读降级/热换失败形态下会给出与查询不一致的数字）。
	searcher, err := openIP2RegionSearcher(live)
	if err != nil {
		t.Fatalf("open single-segment xdb: %v", err)
	}
	ip2regionMu.Lock()
	swapIP2RegionSearcher(searcher, live)
	ip2regionMu.Unlock()

	if got := GetIP2RegionEntryCount(); got != 1 {
		t.Fatalf("entry count=%d, want 1（单段 xdb 的 end==start 是合法边界）", got)
	}
	if tree := GetIP2RegionRegionTree(); tree == nil || len(tree.Provinces) == 0 {
		t.Fatalf("region tree=%+v, want 非空（单段 xdb 应可扫描）", tree)
	}
}

// 版本行缺失时插入必须沿用 schema 默认（auto_update=TRUE），
// 不得硬编码 0 造成「自动更新默认关闭」。
func TestSetIP2RegionVersion_missingRowKeepsAutoUpdateDefault(t *testing.T) {
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// SetIP2RegionVersion 会写 live+".provinces.json" 与地域树缓存——默认路径
	// 指向容器 /app 目录，容器内跑测试会污染库目录；注入临时路径。
	dir := t.TempDir()
	withIP2RegionPaths(t, filepath.Join(dir, "ip2region.xdb"), filepath.Join(dir, "missing-dist.xdb"))
	if _, err := db.DB.Exec("DELETE FROM security_ip2region_version"); err != nil {
		t.Fatal(err)
	}

	if err := SetIP2RegionVersion("v9.9.9"); err != nil {
		t.Fatal(err)
	}

	var auto int
	if err := db.DB.QueryRow("SELECT auto_update FROM security_ip2region_version WHERE id=1").Scan(&auto); err != nil {
		t.Fatalf("read auto_update: %v", err)
	}
	if auto != 1 {
		t.Fatalf("auto_update=%d, want 1（与 schema DEFAULT TRUE 裁定一致）", auto)
	}
}

// 版本行读取故障（非 ErrNoRows）不得被当作「未写入」而覆盖为
// bundled/unknown——真实版本记录必须保留（fail-visible）。
func TestInitIP2Region_versionReadFailureKeepsStoredVersion(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|0|CN"},
		{startIP: 0x01020400, endIP: 0x010204FF, region: "中国|福建省|厦门市|0|CN"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))

	rec := &versionFailingConn{}
	orig := db.DB
	fake := sql.OpenDB(versionFailingConnector{rec: rec})
	db.DB = fake
	t.Cleanup(func() {
		db.DB = orig
		_ = fake.Close()
	})

	InitIP2Region()

	for _, q := range rec.execs {
		if strings.Contains(q, "security_ip2region_version") {
			t.Fatalf("版本行读取故障时不得写版本行（会把真实版本覆盖为哨兵值）: %q", q)
		}
	}
}

// versionFailingConnector 假 db.DB：版本行读返回真实故障（非 ErrNoRows），
// 其余查询返回空结果，Exec 只记录不执行。
type versionFailingConnector struct{ rec *versionFailingConn }

func (c versionFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return c.rec, nil
}

func (versionFailingConnector) Driver() driver.Driver { return versionFailingDriver{} }

type versionFailingDriver struct{}

func (versionFailingDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type versionFailingConn struct{ execs []string }

func (*versionFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (*versionFailingConn) Close() error { return nil }

func (*versionFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (*versionFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "security_ip2region_version") {
		return nil, errors.New("注入的版本行读取故障")
	}
	return &fakeEmptyRows{columns: []string{"x"}}, nil
}

func (c *versionFailingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.execs = append(c.execs, query)
	return driver.RowsAffected(1), nil
}
