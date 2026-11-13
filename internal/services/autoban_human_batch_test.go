package services

// 人机事件批量喂入钉：IPC 提交点按批喂入挑战证据——配置每批只读一次
//（逐事件 SELECT 是热路径 O(事件) 库查询）；计数语义与单事件口径一致
//（发放/失败按维度成员资格计，通过永不计）；主节点/启用门整批生效。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// autobanConfigReadProbe 计数「global_config 单行配置读」的查询探针：
// 真实驱动包装同一 sqlite 文件（与 autobanEnabledFailConnector 同模式），
// 经 db.DB 全局替换注入——GetAutobanConfig 直读 db.DB，无函数缝。
type autobanConfigReadProbe struct {
	reads atomic.Int64
}

type autobanConfigProbeConnector struct {
	probe *autobanConfigReadProbe
	drv   driver.Driver
	dsn   string
}

func (c autobanConfigProbeConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.drv.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &autobanConfigProbeConn{Conn: conn, probe: c.probe}, nil
}

func (c autobanConfigProbeConnector) Driver() driver.Driver { return c.drv }

type autobanConfigProbeConn struct {
	driver.Conn
	probe *autobanConfigReadProbe
}

func (c *autobanConfigProbeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "FROM global_config WHERE id=1") {
		c.probe.reads.Add(1)
	}
	if qc, ok := c.Conn.(driver.QueryerContext); ok {
		return qc.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *autobanConfigProbeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if ec, ok := c.Conn.(driver.ExecerContext); ok {
		return ec.ExecContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

// installAutobanConfigProbe 把 db.DB 换成计数包装（同库文件）；LIFO 清理
// 顺序保证包装句柄先于 installAutobanFixture 的库句柄还原/关闭。
func installAutobanConfigProbe(t *testing.T) *autobanConfigReadProbe {
	t.Helper()
	var path string
	if err := db.DB.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatalf("读取主库路径: %v", err)
	}
	probe := &autobanConfigReadProbe{}
	wrapped := sql.OpenDB(autobanConfigProbeConnector{
		probe: probe,
		drv:   db.DB.Driver(),
		dsn:   path + "?_txlock=immediate&_pragma=busy_timeout(30000)",
	})
	t.Cleanup(func() { _ = wrapped.Close() })
	old := db.DB
	db.DB = wrapped
	t.Cleanup(func() { db.DB = old })
	return probe
}

func TestObserveHumanEvents_readsConfigOncePerBatch(t *testing.T) {
	installAutobanFixture(t, "2026-11-13 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "challenge_issued,challenge_failed", false)
	probe := installAutobanConfigProbe(t)

	items := make([]HumanObserveItem, 0, 24)
	for range 8 {
		at := autobanNow()
		items = append(items,
			HumanObserveItem{IP: "203.0.113.80", Kind: "challenge", At: at},
			HumanObserveItem{IP: "203.0.113.80", Kind: "fail", At: at},
			HumanObserveItem{IP: "203.0.113.80", Kind: "pass", At: at},
		)
	}
	ObserveHumanEvents(items)

	if got := probe.reads.Load(); got != 1 {
		t.Fatalf("24 条事件一批喂入必须只读一次配置，实际读取 %d 次", got)
	}
	autobanMu.Lock()
	w := autobanWindows["203.0.113.80"]
	autobanMu.Unlock()
	if w == nil || w.Count != 16 {
		t.Fatalf("发放+失败应计 16（通过不计），实际=%+v", w)
	}

	// 第二批再读一次（每批一次，不是进程一次）。
	ObserveHumanEvents(items[:3])
	if got := probe.reads.Load(); got != 2 {
		t.Fatalf("第二批应再读一次配置，累计=%d", got)
	}
}

// 门语义整批生效：非主节点/空批不读配置也不计数；未启用整批跳过；
// 过期事件不计（积压回放口径与单事件一致）。
func TestObserveHumanEvents_batchGates(t *testing.T) {
	installAutobanFixture(t, "2026-11-13 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "challenge_issued,challenge_failed", false)
	probe := installAutobanConfigProbe(t)

	items := []HumanObserveItem{
		{IP: "203.0.113.81", Kind: "challenge", At: autobanNow()},
		{IP: "203.0.113.81", Kind: "fail", At: autobanNow()},
	}

	oldMaster := autobanIsMaster
	autobanIsMaster = func() bool { return false }
	ObserveHumanEvents(items)
	autobanIsMaster = oldMaster
	if got := probe.reads.Load(); got != 0 {
		t.Fatalf("非主节点不得读配置，实际 %d 次", got)
	}
	autobanMu.Lock()
	n := len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("非主节点不得计数，得到 %d 键", n)
	}

	ObserveHumanEvents(nil)
	if got := probe.reads.Load(); got != 0 {
		t.Fatalf("空批不得读配置，实际 %d 次", got)
	}

	setAutobanConfigRaw(t, false, 100, 5, "1h", "challenge_issued,challenge_failed", false)
	ObserveHumanEvents(items)
	autobanMu.Lock()
	n = len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("未启用不得计数，得到 %d 键", n)
	}

	setAutobanConfigRaw(t, true, 100, 5, "1h", "challenge_issued,challenge_failed", false)
	// 积压回放：早于当前窗口的事件不计（与单事件口径一致）。
	stale := []HumanObserveItem{{IP: "203.0.113.82", Kind: "fail", At: autobanNow().Add(-2 * time.Hour)}}
	ObserveHumanEvents(stale)
	autobanMu.Lock()
	_, staleCounted := autobanWindows["203.0.113.82"]
	autobanMu.Unlock()
	if staleCounted {
		t.Fatal("窗口外积压事件不得计数")
	}

	// 启用态正常批：计数恢复（门解除后同批语义不变）。
	ObserveHumanEvents(items)
	autobanMu.Lock()
	w := autobanWindows["203.0.113.81"]
	autobanMu.Unlock()
	if w == nil || w.Count != 2 {
		t.Fatalf("启用态批喂入应计 2，实际=%+v", w)
	}
}
