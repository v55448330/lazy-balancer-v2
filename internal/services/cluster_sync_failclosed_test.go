package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// markerReadFailConn 模拟「global_config.last_sync_error 读失败」的真实库
// 故障形态（SQLITE_BUSY/连接重建/磁盘抖动）：查询返回迭代错误，写侧记录
// 以便断言「未知标记态下不得执行清空/覆盖写」。
type markerReadFailConn struct {
	mu    sync.Mutex
	execs []string
}

func (c *markerReadFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("未实现 Prepare")
}
func (c *markerReadFailConn) Close() error              { return nil }
func (c *markerReadFailConn) Begin() (driver.Tx, error) { return fakeIterErrTx{}, nil }

func (c *markerReadFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "last_sync_error") {
		return &fakeIterErrRows{columns: []string{"a"}, err: errors.New("注入的读取失败")}, nil
	}
	return &fakeEmptyRows{columns: []string{"a"}}, nil
}

func (c *markerReadFailConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execs = append(c.execs, query)
	return driver.RowsAffected(0), nil
}

func (c *markerReadFailConn) executedWrites() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.execs...)
}

type markerReadFailConnector struct{ conn *markerReadFailConn }

func (c *markerReadFailConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (c *markerReadFailConnector) Driver() driver.Driver                        { return fakeIterErrDriver{} }

// 标记存在性读取失败必须按「存在」处理（fail-closed）：成功路径据此跳过
// 清空，否则瞬时读错误会把 apply_ok_reload_failed 标记静默销毁，304 补偿
// 重拉通道失明——库=新版本、Caddy=旧运行配置的分叉存活到下次真实变更/重启。
func TestRecordSyncError_unknownMarkerStateDoesNotClearMarker(t *testing.T) {
	conn := &markerReadFailConn{}
	fake := sql.OpenDB(&markerReadFailConnector{conn: conn})
	t.Cleanup(func() { _ = fake.Close() })
	service := &SyncService{db: fake}

	service.recordSyncError(context.Background(), nil, nil)

	if writes := conn.executedWrites(); len(writes) != 0 {
		t.Fatalf("标记态未知时不得写 last_sync_error（实际 %d 次写：%v）", len(writes), writes)
	}
}

// 组合写同理：读失败=标记存在性未知，不得覆盖（否则仍存活的标记被普通
// 错误消息替换）。
func TestCombineSyncError_unknownMarkerStateDoesNotOverwrite(t *testing.T) {
	conn := &markerReadFailConn{}
	fake := sql.OpenDB(&markerReadFailConnector{conn: conn})
	t.Cleanup(func() { _ = fake.Close() })
	service := &SyncService{db: fake}

	service.combineOrReplaceSyncError(context.Background(), "同步拉取失败: 注入", models.SyncErrorCodeTransportError)

	if writes := conn.executedWrites(); len(writes) != 0 {
		t.Fatalf("标记态未知时不得覆盖 last_sync_error（实际 %d 次写：%v）", len(writes), writes)
	}
}

// 查询助手直接暴露 fail-closed 语义：读失败时 present=true。
func TestSyncMarkerPresent_readFailureTreatedAsPresent(t *testing.T) {
	conn := &markerReadFailConn{}
	fake := sql.OpenDB(&markerReadFailConnector{conn: conn})
	t.Cleanup(func() { _ = fake.Close() })
	service := &SyncService{db: fake}

	if !service.syncMarkerPresent(context.Background(), syncReloadFailureMarkerPrefix) {
		t.Fatal("读失败必须按标记存在处理（fail-closed）")
	}
	if !service.syncPostCommitFailureMarkerPresent(context.Background()) {
		t.Fatal("读失败必须让后置副作用标记判定为存在（fail-closed）")
	}
}

// 回归：真实库中标记存活时成功路径不清空；可恢复类错误与标记组合保留，
// 计数递增且首个失败原因不变。
func TestRecordSyncError_realDBPreservesMarkerAndCombinesRecoverableError(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false) // 同步状态写只属于从节点语境
	syncService := &SyncService{db: database}
	ctx := context.Background()

	syncService.persistSyncError(ctx, syncReloadFailureMarkerPrefix+": Caddy /load 失败", models.SyncErrorCodeApplyFailed)
	// persistSyncError 无返回值；直接断言写后可读。
	if !syncService.syncMarkerPresent(ctx, syncReloadFailureMarkerPrefix) {
		t.Fatal("前置：标记未落库")
	}

	syncService.recordSyncError(ctx, nil, nil)
	if !syncService.syncMarkerPresent(ctx, syncReloadFailureMarkerPrefix) {
		t.Fatal("成功路径不得清除后置副作用标记")
	}

	syncService.combineOrReplaceSyncError(ctx, "同步拉取失败: 连接超时", models.SyncErrorCodeTransportError)
	var stored string
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ := decodeSyncError(stored)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("可恢复类错误必须组合保留标记，got %q", msg)
	}
	if !strings.Contains(msg, "已连续 1 次") {
		t.Fatalf("组合消息必须携带失败计数，got %q", msg)
	}
}

// 可自愈类拉取错误不得覆盖 apply_ok_reload_failed 标记：标记是 304 全量重拉
// 补偿的唯一触发器，覆盖后主节点恢复（反代正常/地址改回/对方重新升主）的
// 每个周期都是 304，无标记、无漂移即返回 no-change——库=新版本而 Caddy 停在
// 旧运行配置，直到下次真实变更或进程重启。
func TestSyncService_Pull_transientFetchErrorsPreserveReloadMarker(t *testing.T) {
	cases := []struct {
		name    string
		respond http.HandlerFunc
	}{
		{
			// 反代错误页/响应截断：下一周期自然恢复。
			name: "快照体截断",
			respond: func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(`{"code":0,"data":`))
			},
		},
		{
			// 目标主节点已降级：对方重新升主即恢复。
			name: "主节点已降级",
			respond: func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("X-LB-Error-Code", "master_required")
				response.WriteHeader(http.StatusForbidden)
				_, _ = response.Write([]byte("该操作仅允许在主节点执行"))
			},
		},
		{
			// 未跟随的跨主机重定向：运维改回主节点地址即恢复。
			name: "跨主机重定向",
			respond: func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Location", "http://elsewhere.invalid/api/v1/cluster/sync/snapshot")
				response.WriteHeader(http.StatusFound)
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			master := httptest.NewServer(testCase.respond)
			defer master.Close()
			if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=7, sync_fingerprint='fp', last_sync_error=? WHERE id=1",
				master.URL, encodeSyncError("apply_ok_reload_failed: Caddy /load 失败", models.SyncErrorCodeApplyFailed)); err != nil {
				t.Fatal(err)
			}
			syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

			_, err := syncService.Pull(context.Background())
			if err == nil {
				t.Fatal("want 拉取失败")
			}
			if code := syncErrorCode(err); code != models.SyncErrorCodeTransportError {
				t.Fatalf("code=%q, want transport_error（自愈类错误必须归传输域）", code)
			}
			var stored string
			if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatal(err)
			}
			msg, _ := decodeSyncError(stored)
			if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
				t.Fatalf("last_sync_error=%q, want 以重载失败标记开头（304 补偿通道已失明）", msg)
			}
			if !strings.Contains(msg, testCase.name) && !strings.Contains(msg, "解析集群快照") &&
				!strings.Contains(msg, "已降级为从节点") && !strings.Contains(msg, "重定向") {
				t.Fatalf("last_sync_error=%q, want 携带本次失败原因", msg)
			}
		})
	}
}
