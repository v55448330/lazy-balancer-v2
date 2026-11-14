package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/config"
)

// 注册确认终止轨道的两条不变量：
//   - 5 连败的终止文案（含次数与人工介入指引）必须最终留在 last_sync_error，
//     不得被随后落库的通用「已被拒绝」文案覆盖；
//   - 计数读取失败是暂时性故障，不得按「已达上限」处理而清空注册态。

func TestSyncService_pollRegistration_terminalMessageOutlivesGenericMessage(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
	}))
	defer master.Close()
	// 第 5 次失败即终止：计数从 4 起，轮询一次写 5。
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url=?, registration_id=7,
		registration_secret='pending-secret', cluster_token='approved-token', registration_confirm_failures=4 WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	service.pollRegistration(context.Background())

	var stored string
	var failures int
	var secret string
	if err := database.QueryRow(`SELECT COALESCE(last_sync_error,''),
		COALESCE(registration_confirm_failures,0), COALESCE(registration_secret,'') FROM global_config WHERE id=1`).
		Scan(&stored, &failures, &secret); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "已停止自动重试") || !strings.Contains(stored, "连续失败 5 次") {
		t.Fatalf("last_sync_error=%q, want terminal guidance preserved", stored)
	}
	if failures != 0 || secret != "" {
		t.Fatalf("terminal track=(failures=%d secret=%q), want cleared", failures, secret)
	}
}

// registrationCountReadFailConn 模拟「失败计数读取失败」：计数查询返回迭代
// 错误，写语句被记录以便断言未执行破坏性清空。
type registrationCountReadFailConn struct {
	mu    sync.Mutex
	execs []string
}

func (c *registrationCountReadFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("未实现 Prepare")
}
func (c *registrationCountReadFailConn) Close() error              { return nil }
func (c *registrationCountReadFailConn) Begin() (driver.Tx, error) { return fakeIterErrTx{}, nil }

func (c *registrationCountReadFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "registration_confirm_failures") {
		return &fakeIterErrRows{columns: []string{"a"}, err: errors.New("注入的计数读取失败")}, nil
	}
	return &fakeEmptyRows{columns: []string{"a"}}, nil
}

func (c *registrationCountReadFailConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execs = append(c.execs, query)
	return driver.RowsAffected(1), nil
}

func (c *registrationCountReadFailConn) executedWrites() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.execs...)
}

type registrationCountReadFailConnector struct {
	conn *registrationCountReadFailConn
}

func (c *registrationCountReadFailConnector) Connect(context.Context) (driver.Conn, error) {
	return c.conn, nil
}
func (c *registrationCountReadFailConnector) Driver() driver.Driver { return fakeIterErrDriver{} }

func TestSyncService_bumpRegistrationConfirmFailure_readFailureKeepsRegistrationState(t *testing.T) {
	conn := &registrationCountReadFailConn{}
	fake := sql.OpenDB(&registrationCountReadFailConnector{conn: conn})
	t.Cleanup(func() { _ = fake.Close() })
	service := &SyncService{db: fake}

	service.bumpRegistrationConfirmFailure(context.Background(), "confirm 端点返回 401")

	for _, query := range conn.executedWrites() {
		// 读失败（未知）时唯一允许的写是计数自增本身；任何清空注册态/
		// 令牌的语句都意味着把瞬时 DB 故障升级为需要人工重新注册。
		if strings.Contains(query, "registration_secret=''") || strings.Contains(query, "cluster_token=''") {
			t.Fatalf("读失败时不得执行破坏性清空，实际执行: %s", query)
		}
	}
}

// 终止轨道的清空必须是一条语句且失败留痕：多语句分步清空会在中途 DB 写失败时
// 留下半清空状态（secret 已清、token 未清），后续 401 以通用文案覆盖终止提示
// 并把循环置 Halted，排障线索与明文令牌生命周期同时失控。
type registrationTerminalClearFailConn struct {
	mu    sync.Mutex
	execs []string
}

func (c *registrationTerminalClearFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("未实现 Prepare")
}
func (c *registrationTerminalClearFailConn) Close() error              { return nil }
func (c *registrationTerminalClearFailConn) Begin() (driver.Tx, error) { return fakeIterErrTx{}, nil }

func (c *registrationTerminalClearFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "registration_confirm_failures") {
		return &singleIntRows{columns: []string{"registration_confirm_failures"}, value: 5}, nil
	}
	return &fakeEmptyRows{columns: []string{"a"}}, nil
}

func (c *registrationTerminalClearFailConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.mu.Lock()
	c.execs = append(c.execs, query)
	c.mu.Unlock()
	if strings.Contains(query, "registration_secret=''") {
		return nil, errors.New("注入的清空失败")
	}
	return driver.RowsAffected(1), nil
}

func (c *registrationTerminalClearFailConn) executedWrites() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.execs...)
}

type registrationTerminalClearFailConnector struct {
	conn *registrationTerminalClearFailConn
}

func (c *registrationTerminalClearFailConnector) Connect(context.Context) (driver.Conn, error) {
	return c.conn, nil
}
func (c *registrationTerminalClearFailConnector) Driver() driver.Driver { return fakeIterErrDriver{} }

type singleIntRows struct {
	columns []string
	value   int64
	done    bool
}

func (r *singleIntRows) Columns() []string { return r.columns }
func (r *singleIntRows) Close() error      { return nil }
func (r *singleIntRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}

func TestSyncService_bumpRegistrationConfirmFailure_terminalClearIsSingleStatementAndWarns(t *testing.T) {
	conn := &registrationTerminalClearFailConn{}
	fake := sql.OpenDB(&registrationTerminalClearFailConnector{conn: conn})
	t.Cleanup(func() { _ = fake.Close() })
	service := &SyncService{db: fake}

	var buffer strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buffer)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	service.bumpRegistrationConfirmFailure(context.Background(), "confirm 端点返回 401")

	var clears []string
	for _, query := range conn.executedWrites() {
		if strings.Contains(query, "registration_secret=''") {
			clears = append(clears, query)
		}
	}
	if len(clears) != 1 {
		t.Fatalf("终止清空语句数=%d, want 1（分步清空会留下半清空状态）: %v", len(clears), conn.executedWrites())
	}
	for _, fragment := range []string{"registration_secret=''", "registration_id=NULL", "registration_confirm_failures=0", "cluster_token=''"} {
		if !strings.Contains(clears[0], fragment) {
			t.Fatalf("终止清空语句缺 %q，无法一次收敛: %s", fragment, clears[0])
		}
	}
	if !strings.Contains(buffer.String(), "注入的清空失败") {
		t.Fatalf("清空失败必须留痕（否则排障只剩通用 401）: %q", buffer.String())
	}
}

// 复位计数失败同样必须留痕：静默失败会在「secret 清空也失败」的组合下让陈旧
// 计数继续推进终止轨道而无可解释信号。
func TestSyncService_resetRegistrationConfirmFailure_warnsOnWriteFailure(t *testing.T) {
	var buffer strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buffer)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// 该假连接对任何 UPDATE 返回成功；用已关闭连接制造真实驱动写失败。
	closed, err := sql.Open("sqlite", t.TempDir()+"/closed.db")
	if err != nil {
		t.Fatalf("open closed database: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	(&SyncService{db: closed}).resetRegistrationConfirmFailure(context.Background())

	if !strings.Contains(buffer.String(), "复位注册确认失败计数失败") {
		t.Fatalf("复位失败必须留痕: %q", buffer.String())
	}
}
