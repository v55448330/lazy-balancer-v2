package services

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
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

// TestSnapshotSecurityPolicies_nullEnabledDumpsAsDisabled 锁定：主节点读路径
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

// TestSnapshotSecurityCustomRules_toleratesNullTimestamps 锁定
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

// TestSnapshotSecurityBlockPages_toleratesNullTimestamps 锁定
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

// expires_at 列落在过去的 ACME 证书（status<>'disabled' 且 pem 非空、
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

// 集成：叶证书有效但 expires_at 列过期的种子 → 首次快照后缓存失效点
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

// 结果集迭代错误（driver Rows.Next 返回非 io.EOF 错误）只能经
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

// fakeScanErrRows 首行返回驱动无法转换的值（channel）→ rows.Scan 失败，
// 第二次 Next 返回 io.EOF。用于钉「逐行 Scan 失败必须与行遍历错误同口径」：
// 这两列在正常形态下（TEXT）不可能失败，只有驱动/连接异常可达。
type fakeScanErrRows struct {
	columns []string
	first   bool
}

func (r *fakeScanErrRows) Columns() []string { return r.columns }
func (r *fakeScanErrRows) Close() error      { return nil }
func (r *fakeScanErrRows) Next(dest []driver.Value) error {
	if r.first {
		return io.EOF
	}
	r.first = true
	for i := range dest {
		dest[i] = make(chan int)
	}
	return nil
}

// fakePartialScanRows 首行可扫描、次行返回驱动无法转换的值：模拟「读到一半
// 扫描失败」。静默跳过失败行会让聚合建立在残缺行集上——被跳过的行可能是
// 更大的版本，结果既不是真实最大值也不是「未知」。
type fakePartialScanRows struct{ step int }

func (r *fakePartialScanRows) Columns() []string { return []string{"version"} }
func (r *fakePartialScanRows) Close() error      { return nil }
func (r *fakePartialScanRows) Next(dest []driver.Value) error {
	switch r.step {
	case 0:
		r.step++
		dest[0] = "2026.01.01"
		return nil
	case 1:
		r.step++
		dest[0] = make(chan int)
		return nil
	}
	return io.EOF
}

type fakeIterErrTx struct{}

func (fakeIterErrTx) Commit() error   { return nil }
func (fakeIterErrTx) Rollback() error { return nil }

type fakeIterErrConn struct {
	failNeedle string
	// scanFailNeedle 命中时返回「首行值不可扫描」的结果集（钉逐行 Scan 失败）。
	scanFailNeedle string
	// partialScanNeedle 命中时返回「首行可扫描、次行不可扫描」的结果集
	// （钉部分扫描失败不得产出部分聚合结果）。
	partialScanNeedle string
}

func (c *fakeIterErrConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("未实现 Prepare")
}
func (c *fakeIterErrConn) Close() error              { return nil }
func (c *fakeIterErrConn) Begin() (driver.Tx, error) { return fakeIterErrTx{}, nil }
func (c *fakeIterErrConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	columns := []string{"a"}
	if c.partialScanNeedle != "" && strings.Contains(query, c.partialScanNeedle) {
		return &fakePartialScanRows{}, nil
	}
	if c.scanFailNeedle != "" && strings.Contains(query, c.scanFailNeedle) {
		// 两列结果集：与 readAppliedSectionHashes 的 SELECT section, hash 同形，
		// 但首行的值不可 Scan（驱动级异常形态）。
		return &fakeScanErrRows{columns: []string{"section", "hash"}}, nil
	}
	if strings.Contains(query, c.failNeedle) {
		return &fakeIterErrRows{columns: columns, err: errors.New("注入的迭代失败")}, nil
	}
	return &fakeEmptyRows{columns: columns}, nil
}

type fakeIterErrDriver struct{}

func (fakeIterErrDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("未实现直连")
}

type fakeIterErrConnector struct {
	failNeedle        string
	scanFailNeedle    string
	partialScanNeedle string
}

func (c *fakeIterErrConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeIterErrConn{failNeedle: c.failNeedle, scanFailNeedle: c.scanFailNeedle, partialScanNeedle: c.partialScanNeedle}, nil
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

// 304 路径不得执行交付前置——canonical 拷贝、HMAC 签名与「确认旧协议
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

func TestClusterService_Snapshot_304RechecksRoleAfterCacheBuild(t *testing.T) {
	service, database := newClusterTestService(t)
	initial, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	_, changed, err := service.Snapshot(context.Background(), initial.Version, initial.Fingerprint, "")
	if !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("cached 304 after demote err=%v, want ErrNotMasterNode", err)
	}
	if changed {
		t.Fatal("demoted node must not report a deliverable snapshot")
	}
}

// 同步开关读取失败必须让快照构建报错——吞错会发布 nil 开关快照，
// 从节点 computeSectionSkips 回退全开默认值，主节点 sync_users=0 等关闭
// 保护在该份快照内被绕过且无自愈。 BOOLEAN 列驻留不可扫描文本（SQLite
// 动态类型）即可只打断 readSyncSwitches 而不打断其余快照读取。
func TestClusterService_Snapshot_syncSwitchesReadFailureErrors(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET sync_security='banana' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When：缓存路径（Snapshot）与绕过路径（apply 的 previous 备份）各自构建
	_, _, snapshotErr := service.Snapshot(context.Background(), 0, "", "")
	_, 绕过Err := service.clusterSnapshotBypassingCache(context.Background())

	// Then：两条路径都必须报错，不得发布快照
	if snapshotErr == nil {
		t.Fatal("Snapshot must error when sync switches cannot be read (not publish a snapshot with nil switches)")
	}
	if 绕过Err == nil {
		t.Fatal("clusterSnapshotBypassingCache must error when sync switches cannot be read")
	}
}

// 单条 acme_dns 规则的域名串损坏（>2 域名，导入残留/直改库形态）
// 只能跳过该规则的证书候选并限频告警——整包报错会让主节点对所有从节点
// Pull 持续 500 且无自愈路径（同循环坏证书候选 :881/:887/:899 的
// fail-open 裁定家族）。
func TestClusterService_Snapshot_badRuleDomainSkipsCandidateInsteadOfFailing(t *testing.T) {
	// Given：域名串 'a.com,b.com,c.com'（3 域名 → CanonicalACMEDomains 报错）
	// 挂在一条已签发有效证书的 acme_dns 规则上——证书本身有效，唯一坏点
	// 是规则域名规范化。
	service, database := newClusterTestService(t)
	now := time.Now().UTC()
	service.snapshotNow = func() time.Time { return now }
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "a.com")
	seedSnapshotCertificate(t, database, "lb_bad_domain", "a.com,b.com,c.com", "a.com", certPEM, keyPEM, now.Add(24*time.Hour), 993)
	previousLevel := CurrentLogLevel()
	if err := ConfigureLogLevel("warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureLogLevel(previousLevel) })
	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	// When
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "")

	// Then：快照必须成功发布；坏域名规则的证书不在快照中；限频告警恰好一次
	if err != nil {
		t.Fatalf("单条坏域名规则不得让整个快照失败: %v", err)
	}
	for _, cert := range snapshot.Certs {
		if cert.RuleID == "lb_bad_domain" {
			t.Fatal("坏域名规则的证书必须被跳过，不得进入快照")
		}
	}
	message := logs.String()
	if strings.Count(message, "lb_bad_domain") != 1 || !strings.Contains(message, "993") {
		t.Fatalf("warning output=%q, want 恰好一次包含规则与 job ID 的限频告警", message)
	}
}

// apply 基线只装载消费面——无 WafFiles（不再全树 tar.gz+sha256），
// 三节哈希与漂移守卫同口径，证书轴/ACME ownership 齐全。
func TestClusterSnapshotForApply_skipsWafFileTreeHash(t *testing.T) {
	service, _ := newClusterTestService(t)
	ctx := context.Background()

	previous, err := service.clusterSnapshotForApply(ctx)
	if err != nil {
		t.Fatalf("build apply baseline: %v", err)
	}
	if previous.WafFiles != nil {
		t.Fatal("apply baseline must not build WafFiles (BuildWafFileRef is not consumed by apply)")
	}
	if previous.LockedUsers != nil || previous.NodeSites != nil {
		t.Fatal("apply baseline must not load locked users / node sites")
	}
	if previous.ACME == nil {
		t.Fatal("apply baseline must carry ACME ownership for restore")
	}
	if previous.Certs == nil {
		t.Fatal("apply baseline must carry certificate axis")
	}
	hashes, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatalf("drift guard hashes: %v", err)
	}
	for _, key := range driftGuardSections {
		if previous.SectionHashes[key] != hashes[key] {
			t.Fatalf("section %s hash parity broken: apply=%q drift=%q", key, previous.SectionHashes[key], hashes[key])
		}
	}
}

// （verify，契约钉死）：证书轴只镜像启用规则的 ACME 证书。
func TestSnapshotCertificates_mirrorsOnlyEnabledRules(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "enabled.example.com")
	disabledCertPEM, disabledKeyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "disabled.example.com")
	seedSnapshotCertificate(t, database, "lb_enabled", "enabled.example.com", "enabled.example.com", certPEM, keyPEM, now.Add(24*time.Hour), 501)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled) VALUES ('lb_disabled','lb_disabled','http','disabled.example.com',443,1,'acme_dns',11,7,0)`); err != nil {
		t.Fatal(err)
	}
	seedSnapshotCertificateJob(t, database, "lb_disabled", "disabled.example.com", disabledCertPEM, disabledKeyPEM, now.Add(24*time.Hour), 502)

	certs, err := service.snapshotCertificates(ctx, database)
	if err != nil {
		t.Fatalf("snapshot certificates: %v", err)
	}
	seen := map[string]bool{}
	for _, cert := range certs {
		seen[cert.RuleID] = true
	}
	if !seen["lb_enabled"] {
		t.Fatalf("enabled rule certificate missing: %#v", seen)
	}
	if seen["lb_disabled"] {
		t.Fatal("disabled rule certificate must not be mirrored (mirror contract)")
	}
}

// 证书轴必须携带源 cert_jobs 行的时间轴（平面 UTC 归一）：否则从端镜像行
// created_at 落为同步时刻、updated_at 为空，任务行时间线归零，升主后历史
// 时间与日志时间错位。
func TestSnapshotCertificates_carriesSourceJobTimestamps(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "ts.example.com")
	seedSnapshotCertificate(t, database, "lb_ts", "ts.example.com", "ts.example.com", certPEM, keyPEM, now.Add(24*time.Hour), 701)
	// 混合布局：平面串 + RFC3339（带偏移）都必须归一到平面 UTC。
	if _, err := database.Exec(`UPDATE cert_jobs SET created_at='2025-01-02 03:04:05', updated_at='2025-06-07T18:09:10+08:00' WHERE id=701`); err != nil {
		t.Fatal(err)
	}

	certs, err := service.snapshotCertificates(ctx, database)
	if err != nil {
		t.Fatalf("snapshot certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("certs=%d, want 1", len(certs))
	}
	if got := certs[0].CreatedAt; got != "2025-01-02 03:04:05" {
		t.Fatalf("created_at=%q, want 源行原值平面串", got)
	}
	if got := certs[0].UpdatedAt; got != "2025-06-07 10:09:10" {
		t.Fatalf("updated_at=%q, want RFC3339 归一到平面 UTC", got)
	}
}

// clusterSnapshotBypassingCache 绕过共享快照缓存，直接从数据库全量重建快照
// （含 BuildWafFileRef 与证书解析）。缓存键为 cluster_version/所有权/开关，
// 本地写入（如 users.last_login）不会递增 cluster_version——测试需要真实库
// 状态时必须走本函数，不能命中 cachedSnapshot。
func (s *ClusterService) clusterSnapshotBypassingCache(ctx context.Context) (models.ClusterSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("开启集群快照事务: %w", err)
	}
	defer tx.Rollback()
	snapshot, err := s.buildFullSnapshot(ctx, tx)
	if err != nil {
		return models.ClusterSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("提交集群快照事务: %w", err)
	}
	return snapshot, nil
}

// jwt_expire_minutes / cert_expiry_days 的装载侧归一必须与 apply 侧同口径：
// 带外直改库写入越上限值时，主端若按脏值算 users 节哈希，从端 apply 归一后
// 落库，两边哈希恒不等——每次版本递增整节重放，并额外触发一次 304 漂移全量
// 重拉。断言装载结果已归一到治理默认，且漂移守卫与全量快照哈希相等（单源）。
func TestSnapshotGlobalSettings_normalizesJWTAndCertExpiryOnLoad(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE global_config SET jwt_expire_minutes=1441, cert_expiry_days=999 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	snapshot, err := service.clusterSnapshotBypassingCache(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.BasicSettings.JWTExpireMinutes == nil || *snapshot.BasicSettings.JWTExpireMinutes != db.DefaultJWTExpireMinutes {
		t.Fatalf("jwt_expire_minutes=%v, want 装载侧归一到默认 %d", snapshot.BasicSettings.JWTExpireMinutes, db.DefaultJWTExpireMinutes)
	}
	if snapshot.BasicSettings.CertExpiryDays == nil || *snapshot.BasicSettings.CertExpiryDays != db.DefaultCertExpiryDays {
		t.Fatalf("cert_expiry_days=%v, want 装载侧归一到默认 %d", snapshot.BasicSettings.CertExpiryDays, db.DefaultCertExpiryDays)
	}

	guard, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := ComputeSnapshotSectionHashes(&snapshot)["users"]; guard["users"] != want {
		t.Fatalf("漂移守卫 users 哈希=%s, want 与全量快照同口径 %s（归一必须单源）", guard["users"], want)
	}
}

// 只读事务视图在第一条 SELECT 时冻结：起点复核之后的降级对 buildFullSnapshot
// 不可见。构建返回后必须再做一次事务外角色复核，否则降级瞬间仍会向已授权从
// 节点下发一份完整快照（用户 hash/证书私钥/云凭据）。
func TestClusterService_Snapshot_rejectsDemotionCommittedDuringBuild(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	base := time.Now()
	demoted := false
	service.snapshotNow = func() time.Time {
		if !demoted {
			demoted = true
			// 事务视图已建立（角色读取先于本钩子）：此提交对该只读事务不可见。
			if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
				t.Errorf("提交构建期降级失败: %v", err)
			}
		}
		return base
	}

	if _, _, err := service.Snapshot(ctx, 0, "", ""); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("构建期降级仍下发了完整快照: err=%v, want ErrNotMasterNode(403 语义)", err)
	}
}

// ca_providers.enabled 带外 NULL（列可空，正常写路径恒写 0/1）的读语义必须
// 主从一致：本地读侧 fail-closed（COALESCE(enabled,0)，与所有 WHERE enabled=1
// 取用门一致），集群快照导出必须同值——导出「启用」会让从节点把同一行落成
// 启用，主从切换后该提供商「自己启用」，与主节点此前的失败归因相反。
func TestClusterSnapshot_caProviderEnabledNullMatchesLocalRead(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES (41,'null-enabled','letsencrypt',?,'{}',1,2000,NULL),(42,'explicit-enabled','letsencrypt',?,'{}',1,2000,1)`,
		LetsEncryptDirectoryURL, LetsEncryptDirectoryURL); err != nil {
		t.Fatalf("seed CA providers: %v", err)
	}

	// 主节点本地读口径：NULL 行按禁用。
	masterRead, err := NewCAProviderService().GetCAProvider(41)
	if err != nil {
		t.Fatalf("master read CA provider: %v", err)
	}
	if masterRead.Enabled {
		t.Fatal("本地读口径：enabled IS NULL 必须读成禁用（fail-closed）")
	}

	// 快照导出必须同口径。
	state, err := service.snapshotACME(context.Background(), database)
	if err != nil {
		t.Fatalf("snapshot ACME: %v", err)
	}
	exported := make(map[int]models.CAProvider, len(state.CAProviders))
	for _, provider := range state.CAProviders {
		exported[provider.ID] = provider
	}
	if exported[41].Enabled {
		t.Fatal("快照导出把 enabled IS NULL 导成启用：从节点会自行启用主节点读成禁用的提供商")
	}
	if !exported[42].Enabled {
		t.Fatal("显式启用行必须导出启用")
	}

	// 从节点落库：同一快照经 apply 事务层写入另一实例，读值必须仍为禁用。
	slaveDB := setupIsolatedDB(t)
	snapshot := models.ClusterSnapshot{SchemaVersion: CurrentSnapshotSchema, ACME: state}
	if err := replaceSnapshotDB(context.Background(), slaveDB, snapshot); err != nil {
		t.Fatalf("apply ACME section: %v", err)
	}
	slaveRead, err := NewCAProviderService().GetCAProvider(41)
	if err != nil {
		t.Fatalf("slave read CA provider: %v", err)
	}
	if slaveRead.Enabled != masterRead.Enabled {
		t.Fatalf("主从读值分叉：master=%v slave=%v（同一行 enabled IS NULL）", masterRead.Enabled, slaveRead.Enabled)
	}
	if slaveRead.Enabled {
		t.Fatal("从节点读成启用：快照导出与本地读口径分叉")
	}
}
