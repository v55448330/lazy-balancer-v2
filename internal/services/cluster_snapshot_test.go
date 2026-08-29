package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// seedDriftGuardData 为漂移守卫哈希测试写入 rules/users/security 三节的种子数据。
func seedDriftGuardData(t *testing.T, database *sql.DB) {
	t.Helper()
	stmts := []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_dg','dg','http','dg.example',80,1)`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_dg','127.0.0.1',8080,1,1)`,
		`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_dg',0,'prefix','/api')`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
		`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,last_used) VALUES ('k','kh','kp',1,1,datetime('now'))`,
		`INSERT INTO security_policies (id,name,mode,enabled) VALUES (1,'policy-dg','block',1)`,
		`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_dg',1)`,
		`INSERT INTO security_custom_rules (name,action,score,enabled) VALUES ('cr-dg','block',5,1)`,
		`INSERT INTO security_crs_version (id,version) VALUES (1,'v4.0.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
		`INSERT INTO security_ip2region_version (id,version) VALUES (1,'v3.17.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
	}
	for _, stmt := range stmts {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
}

func TestDriftGuardSectionHashes_matchesFullSnapshotHashes(t *testing.T) {
	// 哈希奇偶不变式：漂移守卫哈希对 rules/users/security 三键必须等于全量
	// 快照路径 ComputeSnapshotSectionHashes 的结果，否则漂移比对口径不一致。
	service, database := newClusterTestService(t)
	seedDriftGuardData(t, database)

	full, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("full snapshot: %v", err)
	}
	guard, err := service.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatalf("drift guard hashes: %v", err)
	}

	for _, key := range driftGuardSections {
		want := full.SectionHashes[key]
		if want == "" {
			t.Fatalf("full snapshot hash for %q is empty", key)
		}
		if got := guard[key]; got != want {
			t.Fatalf("drift guard hash mismatch for %q: guard=%q full=%q", key, got, want)
		}
	}
}

func TestDriftGuardSectionHashes_detectsMutation(t *testing.T) {
	// 种子后记录基线，再分别改动三节（删上游→rules、改用户名→users、
	// 改策略 mode→security），漂移守卫哈希必须全部改变。
	service, database := newClusterTestService(t)
	seedDriftGuardData(t, database)

	baseline, err := service.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatalf("baseline hashes: %v", err)
	}

	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id='lb_dg'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE users SET username='admin2' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_policies SET mode='off' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	after, err := service.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatalf("after-mutation hashes: %v", err)
	}

	if after["rules"] == baseline["rules"] {
		t.Fatal("rules hash must change after upstream deletion")
	}
	if after["users"] == baseline["users"] {
		t.Fatal("users hash must change after username change")
	}
	if after["security"] == baseline["security"] {
		t.Fatal("security hash must change after policy mode change")
	}
}

// TestSnapshotSecurityPolicies_nullEnabledDumpsAsDisabled 锁定 R-I1：主节点读路径
// 一律把 NULL enabled 当禁用（WHERE ... AND enabled=1），dump 却 COALESCE(enabled,1)
// 落成启用——主节点不执行的策略经快照在从节点变成启用，且提升后永久分叉。
// dump 必须与读路径同构：NULL → 禁用（0）。
func TestSnapshotSecurityPolicies_nullEnabledDumpsAsDisabled(t *testing.T) {
	// Given：一条 enabled 为 NULL 的策略（带外编辑/restoreTable 透传可产生）
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (name, enabled) VALUES ('null-enabled', NULL)`); err != nil {
		t.Fatalf("seed null-enabled policy: %v", err)
	}

	// When：主节点快照 dump
	payload, err := service.snapshotSecurityPolicies(context.Background(), database)

	// Then：enabled 键存在且为禁用表示（dump 整数列经 JSON 序列化为数字 0，
	// 解码为 float64(0)——与 rate_limit_enabled 等 COALESCE(...,0) 列同形）
	if err != nil {
		t.Fatalf("snapshotSecurityPolicies: %v", err)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(payload, &rows); err != nil {
		t.Fatalf("parse dump payload %s: %v", string(payload), err)
	}
	if len(rows) != 1 {
		t.Fatalf("dump rows=%d, want 1: %s", len(rows), string(payload))
	}
	enabled, ok := rows[0]["enabled"]
	if !ok {
		t.Fatalf("dump 缺少 enabled 键: %s", string(payload))
	}
	if enabled != float64(0) {
		t.Fatalf("enabled = %#v, want 0（NULL enabled 必须与读路径 WHERE enabled=1 同构落禁用）: %s", enabled, string(payload))
	}
}

// TestSnapshotSecurityCustomRules_toleratesNullTimestamps 锁定 R-I7：
// security_custom_rules.created_at/updated_at 可空（DEFAULT datetime('now')，
// 无 NOT NULL），一行 NULL 即让快照 scan 失败——主节点快照端点与每个从节点
// 拉取全挂，漂移守卫哈希每 304 周期丢失漂移检测。必须 COALESCE 归一化为空串。
func TestSnapshotSecurityCustomRules_toleratesNullTimestamps(t *testing.T) {
	// Given：一条 created_at/updated_at 为 NULL 的自定义规则
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_custom_rules (name, created_at, updated_at) VALUES ('cr-null-ts', NULL, NULL)`); err != nil {
		t.Fatalf("seed null-ts custom rule: %v", err)
	}

	// When：快照读取
	rules, err := service.snapshotSecurityCustomRules(context.Background(), database)

	// Then：不得 scan 失败；两时间列归一化为 ''
	if err != nil {
		t.Fatalf("snapshotSecurityCustomRules 不得因 NULL 时间列报错: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d, want 1", len(rules))
	}
	if rules[0].CreatedAt != "" {
		t.Fatalf("CreatedAt = %q, want COALESCE 归一化后的 %q", rules[0].CreatedAt, "")
	}
	if rules[0].UpdatedAt != "" {
		t.Fatalf("UpdatedAt = %q, want COALESCE 归一化后的 %q", rules[0].UpdatedAt, "")
	}
}

// TestSnapshotSecurityBlockPages_toleratesNullTimestamps 锁定 R-I7：
// security_block_pages.created_at/updated_at 同样可空，与 custom_rules 同缺陷。
func TestSnapshotSecurityBlockPages_toleratesNullTimestamps(t *testing.T) {
	// Given：一条 created_at/updated_at 为 NULL 的拦截页面
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_block_pages (name, created_at, updated_at) VALUES ('bp-null-ts', NULL, NULL)`); err != nil {
		t.Fatalf("seed null-ts block page: %v", err)
	}

	// When：快照读取
	pages, err := service.snapshotSecurityBlockPages(context.Background(), database)

	// Then：不得 scan 失败；两时间列归一化为 ''
	if err != nil {
		t.Fatalf("snapshotSecurityBlockPages 不得因 NULL 时间列报错: %v", err)
	}
	if len(pages) == 0 {
		t.Fatal("pages 为空，种子行未读出")
	}
	var seeded *models.SecurityBlockPage
	for i := range pages {
		if pages[i].Name == "bp-null-ts" {
			seeded = &pages[i]
			break
		}
	}
	if seeded == nil {
		t.Fatal("找不到种子行 bp-null-ts")
	}
	if seeded.CreatedAt != "" {
		t.Fatalf("CreatedAt = %q, want COALESCE 归一化后的 %q", seeded.CreatedAt, "")
	}
	if seeded.UpdatedAt != "" {
		t.Fatalf("UpdatedAt = %q, want COALESCE 归一化后的 %q", seeded.UpdatedAt, "")
	}
}

func TestNearestSnapshotCertificateExpiry_missingExpiryDoesNotMaskNearerRealExpiry(t *testing.T) {
	// Given
	now := time.Now().UTC().Truncate(time.Second)
	near := now.Add(5 * time.Second).Format(time.RFC3339)

	// When
	got := nearestSnapshotCertificateExpiry([]models.ClusterCertificate{
		{RuleID: "lb_near", Domain: "near.example.com", CertPEM: "pem", ExpiresAt: near},
		{RuleID: "lb_acme_missing", Domain: "missing.example.com", CertPEM: "pem", ExpiresAt: ""},
	}, now)

	// Then：缺失证书的重建窗口（30s）不得覆盖更近的 5s 真实到期时间
	if want := now.Add(5 * time.Second); !got.Equal(want) {
		t.Fatalf("expiry=%v, want %v (missing-expiry window must not mask nearer expiry)", got, want)
	}
}

// D2-F1：expires_at 列落在过去的 ACME 证书（status<>'disabled' 且 pem 非空、
// 叶证书仍有效，但列值是续期回写失败/带外导入的过期残留）不得把缓存失效点
// 钉在过去——否则 now.Before(expiresAt) 恒 false，每次快照都全量重建。
func TestNearestSnapshotCertificateExpiry_pastExpiryClampedToRebuildWindow(t *testing.T) {
	// Given
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-time.Hour).Format(time.RFC3339)

	// When
	got := nearestSnapshotCertificateExpiry([]models.ClusterCertificate{
		{RuleID: "lb_stale", Domain: "stale.example.com", CertPEM: "pem", ExpiresAt: past},
	}, now)

	// Then：钳制到缺失窗口，失效点必须落在未来
	if want := now.Add(snapshotCertMissingExpiryWindow); !got.Equal(want) {
		t.Fatalf("expiry=%v, want clamped %v（过去到期不得把缓存钉死在过去）", got, want)
	}
}

// D2-F1 集成：叶证书有效但 expires_at 列过期的种子 → 首次快照后缓存失效点
// 必须在未来（缺失窗口），保证下一次同版本同指纹 Pull 命中缓存而非全量重建。
func TestClusterService_Snapshot_stalePastExpiryColumnKeepsCacheHitWindow(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	base := time.Now().UTC()
	service.snapshotNow = func() time.Time { return base }
	certPEM, keyPEM := certificatePairForDomains(t, base.Add(-time.Hour), base.Add(2*time.Hour), "stale.example.com")
	seedSnapshotCertificate(t, database, "lb_stale_expiry", "stale.example.com", "stale.example.com", certPEM, keyPEM, base.Add(-time.Hour), 1)
	initial, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || len(initial.Certs) != 1 {
		t.Fatalf("initial certs=%d error=%v", len(initial.Certs), err)
	}

	// When：检视缓存条目的失效点
	value, loaded := clusterSnapshotCaches.Load(database)
	if !loaded {
		t.Fatal("snapshot cache entry missing")
	}
	cache := value.(*clusterSnapshotCache)

	// Then：10s 后的缓存命中条件（now.Before(expiresAt)）必须仍成立
	if next := base.Add(10 * time.Second); !next.Before(cache.expiresAt) {
		t.Fatalf("cache expiresAt=%v 落在过去（stale expires_at 未钳制），base=%v", cache.expiresAt, base)
	}
}

// D2-F2：结果集迭代错误（driver Rows.Next 返回非 io.EOF 错误）只能经
// rows.Err() 观测——Close() 只回报关闭错误。以下假驱动注入首迭代即失败
// 的结果集，SQL 按 needle 路由，其余查询返回正常空集。
type fakeIterErrRows struct {
	columns []string
	err     error
}

func (r *fakeIterErrRows) Columns() []string { return r.columns }
func (r *fakeIterErrRows) Close() error      { return nil }
func (r *fakeIterErrRows) Next([]driver.Value) error {
	return r.err
}

type fakeEmptyRows struct{ columns []string }

func (r *fakeEmptyRows) Columns() []string { return r.columns }
func (r *fakeEmptyRows) Close() error      { return nil }
func (r *fakeEmptyRows) Next([]driver.Value) error {
	return io.EOF
}

type fakeIterErrConn struct{ failNeedle string }

func (c *fakeIterErrConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("未实现 Prepare")
}
func (c *fakeIterErrConn) Close() error              { return nil }
func (c *fakeIterErrConn) Begin() (driver.Tx, error) { return nil, errors.New("未实现 Begin") }
func (c *fakeIterErrConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	columns := []string{"a"}
	if strings.Contains(query, c.failNeedle) {
		return &fakeIterErrRows{columns: columns, err: errors.New("注入的迭代失败")}, nil
	}
	return &fakeEmptyRows{columns: columns}, nil
}

type fakeIterErrDriver struct{}

func (fakeIterErrDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("未实现直连")
}

type fakeIterErrConnector struct{ failNeedle string }

func (c *fakeIterErrConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeIterErrConn{failNeedle: c.failNeedle}, nil
}
func (c *fakeIterErrConnector) Driver() driver.Driver { return fakeIterErrDriver{} }

func TestDumpTableAsJSON_propagatesRowsIterationError(t *testing.T) {
	// Given：security_policies 迭代中途驱动失败
	service, _ := newClusterTestService(t)
	fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: "FROM security_policies"})

	// When
	_, err := service.dumpTableAsJSON(context.Background(), fake, "security_policies", "id", "id")

	// Then：必须报错——静默截断的节会被签名+发布，从节点 DELETE+INSERT
	// 把部分节放大为集群级静默删行
	if err == nil || !strings.Contains(err.Error(), "security_policies") {
		t.Fatalf("dumpTableAsJSON err=%v, want 迭代错误按表名传播", err)
	}
}

func TestSnapshotACME_propagatesCAProviderRowsIterationError(t *testing.T) {
	// Given：ca_providers 迭代中途驱动失败（该循环是手工 Close 形态，历史上
	// 只检查了 Close 错误）
	service, _ := newClusterTestService(t)
	fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: "FROM ca_providers"})

	// When
	_, err := service.snapshotACME(context.Background(), fake)

	// Then：错误必须来自 CA 提供商循环本身，而非后续所有权读取的错位错误
	if err == nil || !strings.Contains(err.Error(), "CA 提供商") {
		t.Fatalf("snapshotACME err=%v, want CA 提供商迭代错误传播", err)
	}
}

func TestSnapshotCertificates_propagatesManualCertRowsIterationError(t *testing.T) {
	// Given：手工证书（tls_source='manual'）迭代中途驱动失败
	service, _ := newClusterTestService(t)
	fake := sql.OpenDB(&fakeIterErrConnector{failNeedle: "tls_source='manual'"})

	// When
	_, err := service.snapshotCertificates(context.Background(), fake)

	// Then：手工证书循环缺 rows.Err() 时会静默吞掉迭代错误并返回空证书集
	if err == nil || !strings.Contains(err.Error(), "手工证书") {
		t.Fatalf("snapshotCertificates err=%v, want 手工证书迭代错误传播", err)
	}
}

// D2-S1：304 路径不得执行交付前置——canonical 拷贝、HMAC 签名与「确认旧协议
// 集群令牌交付」的 nodes UPDATE 只属于真正下发的快照（304 响应体为空，全部
// 是纯浪费；清 registration_secret 语义见 cluster_sync.go 注册轮询侧注释）。
func TestClusterService_Snapshot_304PathSkipsSigningPrework(t *testing.T) {
	// Given：从节点已交付过一次（缓存与指纹就绪），节点表挂一条未消费的
	// registration_secret（模拟新注册待确认）
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO nodes (name,mode,ip_address,cluster_token_hash,registration_secret,registration_secret_expires_at,is_approved,status)
		VALUES ('s1','slave','10.0.0.2',?, 'pending-secret', datetime('now','+30 minutes'),1,'online')`, tokenHash("slave-token")); err != nil {
		t.Fatal(err)
	}
	initial, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// When：指纹与版本都未变 → 304 路径（携带令牌）
	_, changed, err := service.Snapshot(context.Background(), initial.Version, initial.Fingerprint, "slave-token")

	// Then：304 且未执行签名前置
	if err != nil {
		t.Fatalf("304 snapshot: %v", err)
	}
	if changed {
		t.Fatal("unchanged fingerprint must 304")
	}
	var secret sql.NullString
	if err := database.QueryRow(`SELECT registration_secret FROM nodes WHERE cluster_token_hash=?`, tokenHash("slave-token")).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	if !secret.Valid || secret.String != "pending-secret" {
		t.Fatalf("registration_secret=%v, want 保留（304 路径不得执行交付前置 UPDATE）", secret)
	}

	// 交付语义保持：指纹失配 → changed → 签名并清除旧协议令牌
	if _, changed, err = service.Snapshot(context.Background(), initial.Version, "", "slave-token"); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("fingerprint mismatch must deliver full snapshot")
	}
	if err := database.QueryRow(`SELECT registration_secret FROM nodes WHERE cluster_token_hash=?`, tokenHash("slave-token")).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	if secret.Valid {
		t.Fatalf("registration_secret=%v, want 交付签名快照后清除", secret)
	}
}

// D2-S2：同步开关读取失败必须让快照构建报错——吞错会发布 nil 开关快照，
// 从节点 computeSectionSkips 回退全开默认值，主节点 sync_users=0 等关闭
// 保护在该份快照内被绕过且无自愈。 BOOLEAN 列驻留不可扫描文本（SQLite
// 动态类型）即可只打断 readSyncSwitches 而不打断其余快照读取。
func TestClusterService_Snapshot_syncSwitchesReadFailureErrors(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET sync_waf_files='banana' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When：缓存路径（Snapshot）与绕过路径（apply 的 previous 备份）各自构建
	_, _, snapshotErr := service.Snapshot(context.Background(), 0, "", "")
	_, bypassErr := service.clusterSnapshotBypassingCache(context.Background())

	// Then：两条路径都必须报错，不得发布快照
	if snapshotErr == nil {
		t.Fatal("Snapshot must error when sync switches cannot be read (not publish a snapshot with nil switches)")
	}
	if bypassErr == nil {
		t.Fatal("clusterSnapshotBypassingCache must error when sync switches cannot be read")
	}
}
