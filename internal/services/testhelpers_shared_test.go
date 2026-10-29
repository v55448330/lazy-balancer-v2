package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

const snapshotSchemaV2 = 2

type snapshotV2Fixture struct {
	SchemaVersion    int                         `json:"schema_version"`
	MinReaderVersion int                         `json:"min_reader_version"`
	Version          int                         `json:"version"`
	Fingerprint      string                      `json:"fingerprint"`
	Signature        string                      `json:"signature,omitempty"`
	CanonicalPayload json.RawMessage             `json:"canonical_payload,omitempty"`
	Rules            []models.LbRule             `json:"rules"`
	Users            []models.ClusterUser        `json:"users"`
	APIKeys          []models.ClusterAPIKey      `json:"api_keys"`
	BasicSettings    models.ClusterBasicSettings `json:"basic_settings"`
	CaddyConfig      *string                     `json:"caddy_config,omitempty"`
	Certs            []models.ClusterCertificate `json:"certs"`
}

func (snapshot snapshotV2Fixture) canonicalBytes() ([]byte, error) {
	snapshot.Fingerprint = ""
	snapshot.Signature = ""
	snapshot.CanonicalPayload = nil
	return json.Marshal(snapshot)
}

type clusterLifecycleHooks interface {
	StartACME()
	StopACME()
	StartSync()
	StopSync()
}

// lifecycleRecorder 是 clusterLifecycleHooks 的可组合测试基类：各回调计数
// （原子——生命周期回调在引擎 daemon goroutine 上异步执行，非原子计数既会被
// race detector 报数据竞争，也会把断言变成调度竞猜）+ 可选钩子（nil=仅计数）。
// 具体夹具按视图组合：布尔观测位用 XxxStarted() 布尔视图，计数断言直用
// 内嵌字段；需要真实行为（如拉起/排空 SyncService）的夹具覆写方法并显式调用
// 内嵌实现。
type lifecycleRecorder struct {
	acmeStarts atomic.Int32
	acmeStops  atomic.Int32
	syncStarts atomic.Int32
	syncStops  atomic.Int32
}

func (r *lifecycleRecorder) StartACME() {
	r.acmeStarts.Add(1)
}

func (r *lifecycleRecorder) StopACME() {
	r.acmeStops.Add(1)
}

func (r *lifecycleRecorder) StartSync() {
	r.syncStarts.Add(1)
}

func (r *lifecycleRecorder) StopSync() {
	r.syncStops.Add(1)
}

type spaceFillReader struct{ remaining int64 }

func (r *spaceFillReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	for i := range n {
		p[i] = ' '
	}
	r.remaining -= n
	return int(n), nil
}

func initServicesDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 后台循环读的是 currentDB 句柄（db.GetDB），Close 已置 nil——只恢复
		// db.DB 会让后续用例的刷新链在 nil 句柄上空转。
		db.SetDB(oldCurrent)
	})
}

func findRouteByID(t *testing.T, routes []interface{}, id string) map[string]interface{} {
	t.Helper()
	for _, routeValue := range routes {
		route := mustMap(t, routeValue, "route")
		if routeID, _ := route["@id"].(string); routeID == id {
			return route
		}
	}
	return nil
}

func seedSnapshotCertificate(t *testing.T, database *sql.DB, ruleID, ruleDomain, jobDomain, certPEM, keyPEM string, expiresAt time.Time, jobID int) {
	t.Helper()
	if _, err := database.Exec(`INSERT OR IGNORE INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'snapshot CA','letsencrypt','https://acme.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO certificate_configs (id,name,dns_provider,enabled) VALUES (11,'snapshot DNS','dnspod',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled) VALUES (?,?,'http',?,443,1,'acme_dns',11,7,1)`, ruleID, ruleID, ruleDomain); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES (?,'127.0.0.1',8080,1)`, ruleID); err != nil {
		t.Fatal(err)
	}
	seedSnapshotCertificateJob(t, database, ruleID, jobDomain, certPEM, keyPEM, expiresAt, jobID)
}

func seedSnapshotCertificateJob(t *testing.T, database *sql.DB, ruleID, jobDomain, certPEM, keyPEM string, expiresAt time.Time, jobID int) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at) VALUES (?, ?, ?, 'issued', ?, ?, ?, 7, ?)`, jobID, ruleID, jobDomain, expiresAt, certPEM, keyPEM, expiresAt.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func signedSnapshotV2Fixture(version int, token string) snapshotV2Fixture {
	snapshot := snapshotV2Fixture{
		SchemaVersion:    snapshotSchemaV2,
		MinReaderVersion: snapshotSchemaV2,
		Version:          version,
		Rules:            []models.LbRule{},
		Users:            []models.ClusterUser{},
		APIKeys:          []models.ClusterAPIKey{},
		Certs:            []models.ClusterCertificate{},
	}
	canonical, err := snapshot.canonicalBytes()
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(canonical)
	snapshot.Fingerprint = hex.EncodeToString(hash[:])
	snapshot.CanonicalPayload = canonical
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(canonical)
	snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
	return snapshot
}

func wireClusterLifecycleEngineForTest(t *testing.T, lifecycle clusterLifecycleHooks, master bool) *taskengine.Engine {
	t.Helper()
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	SetTaskEngineForTest(te)
	SetCertIssuanceLifecycleHooks(lifecycle.StartACME, lifecycle.StopACME)
	SetSyncLifecycleHooks(lifecycle.StartSync, lifecycle.StopSync)
	t.Cleanup(func() {
		StopTaskEngine()
		SetCertIssuanceLifecycleHooks(nil, nil)
		SetSyncLifecycleHooks(nil, nil)
	})
	te.SetRole(master)
	mustRegisterTask(te, taskengine.Descriptor{
		ID: "cert-issuance", Family: "certificates", Name: "证书签发", Kind: taskengine.KindDaemon, RunsOn: taskengine.RoleMasterOnly,
		Run: func(rc taskengine.RunContext) error {
			return daemonLifecycleRun(rc, certIssuanceLifecycleStart, certIssuanceLifecycleStop)
		},
	})
	mustRegisterTask(te, taskengine.Descriptor{
		ID: "cluster-sync", Family: "cluster", Name: "集群同步", Kind: taskengine.KindDaemon, RunsOn: taskengine.RoleAny, RestartOnRoleFlip: true,
		Run: func(rc taskengine.RunContext) error {
			if te.IsMaster() {
				return daemonLifecycleRun(rc, nil, nil)
			}
			return daemonLifecycleRun(rc, syncLifecycleStart, syncLifecycleStop)
		},
	})
	te.StartLoop("cert-issuance")
	te.StartLoop("cluster-sync")
	return te
}

func certificatePairForDomains(t *testing.T, notBefore, notAfter time.Time, domains ...string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(notAfter.UnixNano()), Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func captureApplicationLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	previousLevel := CurrentLogLevel()
	if err := ConfigureLogLevel("info"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureLogLevel(previousLevel) })
	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	return &logs
}

// —— test-only 入口（生产文件只保留主路径）——
//
// 以下函数仅测试消费，原寄居 logrotate.go / services.go 生产文件；生产文件
// 承载 test-only 符号会让「生产调用面」判断失真（误复用即把旧形态拉回主链），
// 故搬到同包测试文件（编译进测试二进制，不进产品符号表）。

// logCleanupSummaryLine log-cleanup 任务单轮摘要行——对「摘要行口径 = 实际
// 清理口径」直接钉测。
func logCleanupSummaryLine(logFile string) string {
	_, line := logCleanupRound(context.Background(), logFile)
	return line
}

// taskLogsHousekeeping 任务日志清理（保留月数自行读取）——测试/独立调用
// 入口；生产链走 RuntimeLogCleanupOnce（复用已读取口径，避免一轮两次查库）。
func taskLogsHousekeeping(logFile string) TaskLogHousekeepingResult {
	months, monthsErr := auditRetentionMonths(context.Background())
	return taskLogsHousekeepingWithRetention(logFile, months, monthsErr)
}

// parseRuleLabelMetrics 解析 lazybalancer_* 指标按 rule label 聚合
// （caddy_id 直接匹配）：单趟扫描，供文本入口测试使用；采集主路径在同一趟
// 聚合里与全局样本共用一次遍历。
func parseRuleLabelMetrics(text string) (map[string]*ruleLabelAggregate, error) {
	res := aggregatePrometheusText(text, prometheusScanRules)
	if res.rulesErr != nil {
		return nil, res.rulesErr
	}
	return res.rules, nil
}

// storeRuleMetricsText 按 rule label（lazybalancer_*）写规则级历史行——
// 文本入口测试专用；生产链持有已聚合结果，直接走 storePerRuleMetrics。
func (m *MetricsService) storeRuleMetricsText(text string) error {
	byRule, err := parseRuleLabelMetrics(text)
	if err != nil {
		return err
	}
	return m.storePerRuleMetrics(byRule)
}

// updateOverview 整包入口（测试专用）：DB 派生三项 + 流量样本一次覆盖。
// 生产采集链走 collect（每周期只刷新一次 DB 派生项）——复用本入口会把旧形态
// 「每周期两次 DB 刷新」重新拉回。
func (m *MetricsService) updateOverview(metrics parsedMetrics) {
	m.refreshDBOverviewMetrics()
	m.applyTrafficSample(metrics)
}
