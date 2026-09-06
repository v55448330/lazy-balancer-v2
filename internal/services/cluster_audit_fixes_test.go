package services

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// 2026-09-05 集群审计 C-1：补偿重拉窗口内的应用瞬时失败（ApplyFailed）不得覆盖
// apply_ok_reload_failed 标记——该场景下 applied_version/指纹已与主节点对齐，标记是
// 304 全量重拉补偿的唯一残留触发器；覆盖后下周期 304 无标记，DB=新版本而 Caddy=
// 旧运行配置的分叉静默存活到下次真实变更。应用失败与传输错误同属「标记存活期间
// 期望自动重试」的自愈类；终止类仍仅 schema 过新/令牌撤销/校验类。
func TestSyncService_recordSyncError_applyFailurePreservesReloadMarker(t *testing.T) {
	// Given：重载失败标记已存在（apply 已提交版本 V，Caddy 重载失败）
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=?", encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService("http://127.0.0.1:1"))

	// When：补偿重拉的应用瞬时失败（SQLITE_BUSY 等回滚路径）经 recordSyncError 落库
	service.recordSyncError(context.Background(), newSyncFailure(models.SyncErrorCodeApplyFailed, errors.New("开始快照事务: database is locked")), nil)

	// Then：标记保留，应用失败组合进消息并带计数，代码为 apply_failed
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, code := decodeSyncError(stored)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("last_sync_error=%q, want reload failure marker preserved", msg)
	}
	if !strings.Contains(msg, "database is locked") {
		t.Fatalf("last_sync_error=%q, want combined message containing apply failure detail", msg)
	}
	if !strings.Contains(msg, syncFailureCountPrefix+"1"+syncFailureCountSuffix) {
		t.Fatalf("last_sync_error=%q, want failure count 1", msg)
	}
	if code != models.SyncErrorCodeApplyFailed {
		t.Fatalf("code=%q, want apply_failed", code)
	}

	// When：再次应用失败（补偿重拉仍未成功）
	service.recordSyncError(context.Background(), newSyncFailure(models.SyncErrorCodeApplyFailed, errors.New("备份本地快照: 磁盘已满")), nil)

	// Then：组合消息语义不回归——标记段保留首个失败原因（caddy down）、计数递增为
	// 2、消息长度有界，且代码不再回退为传输类
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, code = decodeSyncError(stored)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("last_sync_error=%q, want marker prefix after second apply failure", msg)
	}
	markerSegment := msg
	if idx := strings.Index(msg, " | "); idx >= 0 {
		markerSegment = msg[:idx]
	}
	if !strings.Contains(markerSegment, "caddy down") {
		t.Fatalf("last_sync_error=%q, want marker segment to keep first failure reason", msg)
	}
	if !strings.Contains(msg, syncFailureCountPrefix+"2"+syncFailureCountSuffix) {
		t.Fatalf("last_sync_error=%q, want failure count 2", msg)
	}
	if len(stored) > 512 {
		t.Fatalf("last_sync_error=%d bytes, want bounded under 512", len(stored))
	}
	if code != models.SyncErrorCodeApplyFailed {
		t.Fatalf("code=%q, want apply_failed preserved", code)
	}
}

// 2026-09-05 集群审计 SC-4：login_failed_attempts/login_locked_until 是从节点登录
// 端点写入的本地记账（不随快照同步）。users 节重放（清表+回插）不得把从节点被锁
// 账户意外解锁；主节点已删除的用户不得因回写复活。
func TestSyncService_applySnapshot_preservesLocalLoginLockoutState(t *testing.T) {
	// Given：本地（从节点）两个用户带登录锁定记账
	cluster, database := newClusterTestService(t)
	seed := `INSERT INTO users (id,username,password_hash,role,login_failed_attempts,login_locked_until) VALUES (?,?,'hash','user',?,?)`
	if _, err := database.Exec(seed, 1, "root", 3, "2099-01-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(seed, 2, "ghost", 2, "2099-01-02 00:00:00"); err != nil {
		t.Fatal(err)
	}
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When：应用含 users 节的快照（全量重放）
	if err := syncService.applySnapshot(context.Background(), incoming); err != nil {
		t.Fatal(err)
	}

	// Then：本地登录失败计数与锁定时间保留（不被重放重置）
	var attempts int
	var lockedUntil any
	if err := database.QueryRow("SELECT COALESCE(login_failed_attempts,0), login_locked_until FROM users WHERE username='root'").Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || lockedUntil == nil || lockedUntil.(string) != "2099-01-01 00:00:00" {
		t.Fatalf("root login lockout after replay: attempts=%d locked_until=%v, want 3/2099-01-01 00:00:00", attempts, lockedUntil)
	}

	// When：主节点删除 ghost 后再次下发（users 节哈希变化触发重放）
	if _, err := database.Exec("DELETE FROM users WHERE username='ghost'"); err != nil {
		t.Fatal(err)
	}
	second, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := syncService.applySnapshot(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	// Then：ghost 不复活，root 计数仍保留
	var ghostCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM users WHERE username='ghost'").Scan(&ghostCount); err != nil {
		t.Fatal(err)
	}
	if ghostCount != 0 {
		t.Fatalf("ghost users after master-side deletion: count=%d, want 0 (deleted user must not resurrect)", ghostCount)
	}
	if err := database.QueryRow("SELECT COALESCE(login_failed_attempts,0), login_locked_until FROM users WHERE username='root'").Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || lockedUntil == nil || lockedUntil.(string) != "2099-01-01 00:00:00" {
		t.Fatalf("root login lockout after second replay: attempts=%d locked_until=%v, want 3/2099-01-01 00:00:00", attempts, lockedUntil)
	}
}

// 2026-09-06 二轮 C-7（W10 复核结论）：IsMaster 对历史 NULL 行的口径必须与
// readonly 写闸（COALESCE(is_master,1) fail-open）一致——NULL 视为主节点。
// A5-N2 迁移（db.go）已回填存量 NULL 使稳态不可达，此处为纵深防御一致性。
func TestClusterService_IsMaster_nullIsMasterFailsOpenAsMaster(t *testing.T) {
	// Given：历史脏数据 is_master=NULL
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	service := NewClusterService(database, nil)

	// When
	isMaster, err := service.IsMaster(context.Background())

	// Then：NULL 按主节点处理（fail-open），不产生读取错误
	if err != nil {
		t.Fatalf("IsMaster err=%v, want nil（NULL 应回退为主节点而非 Scan 失败）", err)
	}
	if !isMaster {
		t.Fatalf("IsMaster=false, want true（与 readonly.go COALESCE(is_master,1) 口径一致）")
	}
}

// 2026-09-06 二轮 C-3：主节点侧按节点的 TOFU 指纹钉重置——按
// IssueServiceControlTicket 同一口径（access_url 优先，回退 protocol://ip:port）
// 定位 pin 文件，只删除目标节点的钉，不影响其他节点与无关主机。
func TestClusterService_ForgetNodePin_removesOnlyTargetNodePin(t *testing.T) {
	// Given：两个从节点各有一个 pin 文件，另有本节点作为从节点时代的旧主节点钉
	cluster, database := newClusterTestService(t)
	seed := `INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,is_approved) VALUES (?,?,'172.18.0.2',8000,'http',?,1)`
	if _, err := database.Exec(seed, 21, "slave-a", "https://node-a.example:8443"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(seed, 22, "slave-b", "https://node-b.example:8443"); err != nil {
		t.Fatal(err)
	}
	writePin := func(host string) string {
		pinPath, err := clusterPinPathForDatabase(database, host)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(pinPath), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pinPath, []byte("sha256-fingerprint\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return pinPath
	}
	pinA := writePin("node-a.example:8443")
	pinB := writePin("node-b.example:8443")
	pinOld := writePin("old-master.example:443")

	// When：重置节点 21 的钉
	host, err := cluster.ForgetNodePin(context.Background(), 21)

	// Then：仅目标 pin 文件被删除，返回定位到的地址
	if err != nil {
		t.Fatalf("ForgetNodePin err=%v", err)
	}
	if host != "node-a.example:8443" {
		t.Fatalf("host=%q, want node-a.example:8443", host)
	}
	if _, err := os.Stat(pinA); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("node-a pin still exists: %v", err)
	}
	for _, pin := range []string{pinB, pinOld} {
		if _, err := os.Stat(pin); err != nil {
			t.Fatalf("unrelated pin removed: %s: %v", pin, err)
		}
	}

	// When：节点不存在
	if _, err := cluster.ForgetNodePin(context.Background(), 99); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node err=%v, want ErrNodeNotFound", err)
	}

	// When：重复重置（钉已不存在）
	if _, err := cluster.ForgetNodePin(context.Background(), 21); !errors.Is(err, ErrNoClusterPin) {
		t.Fatalf("repeat reset err=%v, want ErrNoClusterPin（幂等信号）", err)
	}
}

// 2026-09-06 LB-04 连带：集群快照的 health_check_timeout NULL 回退口径必须与
// 渲染/写侧（rule_features/caddy.go、UpdateRule 存量读取，已统一为 2）一致——
// 快照仍导 5 会让主节点实际行为（2）与下发值（5）分叉，且从节点回放后把 5
// 物化为非 NULL 值，永久固化错误口径。
func TestSnapshot_rulesNullHealthCheckTimeout_fallsBackToTwo(t *testing.T) {
	// Given：一条 health_check_timeout=NULL 的存量规则
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,health_check_timeout) VALUES ('lb_hc_null','hc-null','http',80,NULL)`); err != nil {
		t.Fatal(err)
	}

	// When
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：快照导出 NULL 回退为 2（与渲染/写侧口径一致）
	if len(incoming.Rules) != 1 {
		t.Fatalf("rules=%d, want 1", len(incoming.Rules))
	}
	if incoming.Rules[0].HealthCheckTimeout != 2 {
		t.Fatalf("health_check_timeout=%d, want 2（与渲染/写侧 NULL 回退口径一致）", incoming.Rules[0].HealthCheckTimeout)
	}
}

// loginLockTimestamp 按 users 表存储口径（auth recordLoginFailure 的写入格式）
// 生成 UTC 时间串。
func loginLockTimestamp(offset time.Duration) string {
	return time.Now().UTC().Add(offset).Format("2006-01-02 15:04:05")
}

// SC-4 修订：主节点活跃登录锁经快照独立顶层载荷 locked_users 下发——只带
// 未来时间的活跃锁（与 loginLockedNow 同口径的字符串比较），自然过期后条目
// 自动消失；不进 users 节列/节哈希（避免每次登录失败触发全量重放与漂移循环）。
func TestSnapshot_lockedUsers_carriesActiveLocksOnly(t *testing.T) {
	// Given：三个用户——活跃锁（未来 30 分钟）、已过期锁（1 小时前）、无锁
	cluster, database := newClusterTestService(t)
	active := loginLockTimestamp(30 * time.Minute)
	expired := loginLockTimestamp(-time.Hour)
	seed := `INSERT INTO users (id,username,password_hash,role,login_locked_until) VALUES (?,?,'hash','user',NULLIF(?,''))`
	if _, err := database.Exec(seed, 1, "locked-active", active); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(seed, 2, "locked-expired", expired); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(seed, 3, "unlocked", ""); err != nil {
		t.Fatal(err)
	}

	// When
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：仅活跃锁一条，用户名与时间串按存储原样携带
	if len(incoming.LockedUsers) != 1 {
		t.Fatalf("locked_users=%v, want exactly the active lock", incoming.LockedUsers)
	}
	if incoming.LockedUsers[0].Username != "locked-active" || incoming.LockedUsers[0].LockedUntil != active {
		t.Fatalf("locked_users entry=%+v, want {locked-active %s}", incoming.LockedUsers[0], active)
	}
}

// SC-4 修订：从端应用 locked_users——空锁延长、更早本地锁延长、更晚本地锁
// 不缩短、login_failed_attempts 不被触碰、载荷中的陌生用户名安全落空。
func TestSyncService_applySnapshot_lockedUsersExtendButNeverShorten(t *testing.T) {
	// Given：本地（从节点）三个用户——a 无锁、b 本地锁更早、c 本地锁更晚
	cluster, database := newClusterTestService(t)
	localLater := loginLockTimestamp(2 * time.Hour)
	earlier := loginLockTimestamp(5 * time.Minute)
	masterLock := loginLockTimestamp(1 * time.Hour)
	seed := `INSERT INTO users (id,username,password_hash,role,login_failed_attempts,login_locked_until) VALUES (?,?,'hash','user',?,NULLIF(?,''))`
	if _, err := database.Exec(seed, 1, "a", 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(seed, 2, "b", 2, earlier); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(seed, 3, "c", 3, localLater); err != nil {
		t.Fatal(err)
	}
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	incoming.LockedUsers = []models.ClusterLockedUser{
		{Username: "a", LockedUntil: masterLock},
		{Username: "b", LockedUntil: masterLock},
		{Username: "c", LockedUntil: masterLock},
		{Username: "ghost", LockedUntil: masterLock},
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When：应用快照（users 节重放 + SC-4 本地记账回写后应用 locked_users）
	if err := syncService.applySnapshot(context.Background(), incoming); err != nil {
		t.Fatal(err)
	}

	// Then：a/b 延长到主端锁，c 保留更晚的本地锁；计数全部保留；ghost 不复活
	assertLock := func(username, wantLock string, wantAttempts int) {
		t.Helper()
		var lockedUntil sql.NullString
		var attempts int
		if err := database.QueryRow("SELECT COALESCE(login_failed_attempts,0), login_locked_until FROM users WHERE username=?", username).Scan(&attempts, &lockedUntil); err != nil {
			t.Fatalf("user %s: %v", username, err)
		}
		if !lockedUntil.Valid || lockedUntil.String != wantLock {
			t.Fatalf("user %s lock=%v, want %s", username, lockedUntil, wantLock)
		}
		if attempts != wantAttempts {
			t.Fatalf("user %s attempts=%d, want %d（locked_users 应用不得触碰本地计数）", username, attempts, wantAttempts)
		}
	}
	assertLock("a", masterLock, 1)
	assertLock("b", masterLock, 2)
	assertLock("c", localLater, 3)
	var ghostCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM users WHERE username='ghost'").Scan(&ghostCount); err != nil {
		t.Fatal(err)
	}
	if ghostCount != 0 {
		t.Fatalf("ghost users=%d, want 0（陌生用户名落空，不复活）", ghostCount)
	}

	// When：再次应用同一版本快照（users 节哈希一致 → 跳过重放），仅 locked_users
	// 变化（主端延长了 a 的锁）——应用不得受 users 节跳过门控
	laterLock := loginLockTimestamp(3 * time.Hour)
	incoming.LockedUsers = []models.ClusterLockedUser{{Username: "a", LockedUntil: laterLock}}
	if err := syncService.applySnapshot(context.Background(), incoming); err != nil {
		t.Fatal(err)
	}

	// Then：users 节被跳过（本地计数保留证明未重放），锁仍被延长
	assertLock("a", laterLock, 1)
}

// SC-4 修订：旧主端形态（载荷缺失/nil）必须 no-op——不得清从节点本地锁与计数。
func TestSyncService_applySnapshot_nilLockedUsersPayloadIsNoOp(t *testing.T) {
	// Given：本地用户带活跃锁与失败计数；快照不带 locked_users（模拟旧主端）
	cluster, database := newClusterTestService(t)
	localLock := loginLockTimestamp(30 * time.Minute)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,login_failed_attempts,login_locked_until) VALUES (1,'keep','hash','user',2,?)`, localLock); err != nil {
		t.Fatal(err)
	}
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	incoming.LockedUsers = nil
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	if err := syncService.applySnapshot(context.Background(), incoming); err != nil {
		t.Fatal(err)
	}

	// Then：本地锁与计数原样保留（不清锁、不重置计数）
	var lockedUntil sql.NullString
	var attempts int
	if err := database.QueryRow("SELECT COALESCE(login_failed_attempts,0), login_locked_until FROM users WHERE username='keep'").Scan(&attempts, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || !lockedUntil.Valid || lockedUntil.String != localLock {
		t.Fatalf("after nil payload: attempts=%d lock=%v, want 2/%s（no-op 不得清本地锁）", attempts, lockedUntil, localLock)
	}
}
