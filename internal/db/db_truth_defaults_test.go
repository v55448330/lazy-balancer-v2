package db

// 库值唯一真相（批 1+2）DB 侧钉测：
// ① fresh DDL DEFAULT 与治理常量一致（写死兜底废除后，DEFAULT 是默认值唯一入口）；
// ② 启动迁移幂等回填 NULL/<=0 行，用户已设有效值保留。

import (
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestFreshSchemaDefaults_MatchGovernedConstants(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	cases := []struct {
		table   string
		column  string
		want    string
		notNull int
	}{
		{"global_config", "request_body_max_size_mb", fmt.Sprint(DefaultRequestBodyMaxSizeMB), 1},
		{"global_config", "http_read_timeout", fmt.Sprint(DefaultHTTPReadTimeout), 1},
		{"global_config", "http_write_timeout", fmt.Sprint(DefaultHTTPWriteTimeout), 1},
		{"global_config", "http_idle_timeout", fmt.Sprint(DefaultHTTPIdleTimeout), 1},
		{"global_config", "caddy_log_size_mb", fmt.Sprint(DefaultCaddyLogSizeMB), 1},
		{"global_config", "caddy_log_level", "'" + DefaultCaddyLogLevel + "'", 0},
		{"global_config", "sync_interval", fmt.Sprint(DefaultSyncInterval), 0},
		{"global_config", "jwt_expire_minutes", fmt.Sprint(DefaultJWTExpireMinutes), 0},
		{"lb_rules", "health_check_interval", fmt.Sprint(DefaultHealthCheckInterval), 1},
		{"lb_rules", "health_check_timeout", fmt.Sprint(DefaultHealthCheckTimeout), 1},
		{"lb_rules", "health_check_unhealthy_threshold", fmt.Sprint(DefaultHealthCheckUnhealthyThreshold), 1},
		{"lb_rules", "health_check_healthy_threshold", fmt.Sprint(DefaultHealthCheckHealthyThreshold), 1},
		{"lb_rules", "tcp_try_interval", fmt.Sprint(DefaultTCPTryInterval), 1},
		// 双向钉补齐——批 3 治理列此前只有消费侧 fail-visible 钉
		//（render_db_truth_test.go），DDL DEFAULT 与治理常量未双向钉。
		{"global_config", "cert_expiry_days", fmt.Sprint(DefaultCertExpiryDays), 0},
		// 续期天数/次数与 cert_expiry_days 同族，DDL DEFAULT
		// 与常量双向钉死。
		{"global_config", "cert_renewal_days", fmt.Sprint(DefaultCertRenewalDays), 0},
		{"global_config", "cert_renewal_attempts", fmt.Sprint(DefaultCertRenewalAttempts), 0},
		{"security_policies", "anomaly_threshold", fmt.Sprint(DefaultAnomalyThreshold), 0},
		// CA 提供商并发/间隔：DDL DEFAULT 与写侧归一/读侧 COALESCE/导入回填
		// 同一常量（此前默认间隔在归一实现里是 1000，与 DDL/COALESCE 的 2000
		// 相差一倍，按来源不同节流不同）。
		{"ca_providers", "max_concurrent", fmt.Sprint(DefaultCAProviderMaxConcurrent), 0},
		{"ca_providers", "min_interval_ms", fmt.Sprint(DefaultCAProviderMinIntervalMS), 0},
		// 时区：fresh DDL DEFAULT 与读侧兜底单源（空串非法库值，启动归一收敛）。
		{"global_config", "timezone", "'" + DefaultTimezone + "'", 0},
		// 任务级排程：fresh DDL DEFAULT 与 services 读失败兜底同源。
		{"security_crs_version", "schedule_days", "'" + DefaultScheduleDays + "'", 1},
		{"security_crs_version", "schedule_time", "'" + DefaultScheduleTime + "'", 1},
		{"security_ip2region_version", "schedule_days", "'" + DefaultScheduleDays + "'", 1},
		{"security_ip2region_version", "schedule_time", "'" + DefaultScheduleTime + "'", 1},
		// 日志体量/保留期：fresh DDL DEFAULT 与读侧 COALESCE 绑定参数同源。
		{"global_config", "task_log_size_mb", fmt.Sprint(DefaultTaskLogSizeMB), 0},
		{"global_config", "audit_log_size_mb", fmt.Sprint(DefaultAuditLogSizeMB), 0},
		{"global_config", "runtime_log_size_mb", fmt.Sprint(DefaultRuntimeLogSizeMB), 0},
		{"global_config", "audit_retention_months", fmt.Sprint(DefaultAuditRetentionMonths), 0},
		// 自动备份五列治理默认（读侧 COALESCE/导入回退同源）。
		{"global_config", "auto_backup_enabled", fmt.Sprint(DefaultAutoBackupEnabled), 0},
		{"global_config", "auto_backup_frequency", "'" + DefaultAutoBackupFrequency + "'", 0},
		{"global_config", "auto_backup_time", "'" + DefaultAutoBackupTime + "'", 0},
		{"global_config", "auto_backup_day", fmt.Sprint(DefaultAutoBackupDay), 0},
		{"global_config", "auto_backup_keep", fmt.Sprint(DefaultAutoBackupKeep), 0},
		// 应用日志级别：fresh DDL DEFAULT 与面板读侧 COALESCE 绑定参数同源。
		{"global_config", "log_level", "'" + DefaultLogLevel + "'", 0},
	}
	for _, tc := range cases {
		var dflt *string
		var notNull int
		if err := database.QueryRow(`SELECT dflt_value, "notnull" FROM pragma_table_info(?) WHERE name=?`, tc.table, tc.column).Scan(&dflt, &notNull); err != nil {
			t.Fatalf("%s.%s: %v", tc.table, tc.column, err)
		}
		if dflt == nil || *dflt != tc.want {
			t.Fatalf("%s.%s DEFAULT=%v, want %s", tc.table, tc.column, dflt, tc.want)
		}
		// 值型族钉测补 notnull——只比 dflt_value 会放过
		// 「DEFAULT 对但可空」的重建退化。
		if notNull != tc.notNull {
			t.Fatalf("%s.%s notnull=%d, want %d", tc.table, tc.column, notNull, tc.notNull)
		}
	}
}

// 安全事件保留/大屏四列只存在于 newColumns 补列通道
// （fresh CREATE 无此四列），其 DDL 形状必须在真实启动迁移后与 db.Default*
// 常量一致——默认值曾是 4 处字面量副本（DDL/回填/读侧/导入），漏改即漂移。
func TestRunMigrationsColumnDefaults_MatchGovernedConstants(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	cases := []struct {
		column  string
		want    string
		notNull int
	}{
		{"security_events_retention_days", fmt.Sprint(DefaultSecurityEventsRetentionDays), 1},
		{"security_events_row_cap", fmt.Sprint(DefaultSecurityEventsRowCap), 1},
		{"threat_traffic_sample_n", fmt.Sprint(DefaultThreatTrafficSampleN), 1},
		{"threat_screen_mode", "'" + DefaultThreatScreenMode + "'", 1},
		// 威胁/爬虫任务级排程（newColumns 补列）：DDL DEFAULT 与 services 兜底同源。
		{"threat_schedule_days", "'" + DefaultScheduleDays + "'", 1},
		{"threat_schedule_time", "'" + DefaultScheduleTime + "'", 1},
		{"crawler_schedule_days", "'" + DefaultScheduleDays + "'", 1},
		{"crawler_schedule_time", "'" + DefaultScheduleTime + "'", 1},
		// 自动封禁六列（newColumns 补列）与读侧 COALESCE/启动回填同源。
		{"autoban_enabled", fmt.Sprint(DefaultAutobanEnabled), 1},
		{"autoban_threshold", fmt.Sprint(DefaultAutobanThreshold), 1},
		{"autoban_window_minutes", fmt.Sprint(DefaultAutobanWindowMinutes), 1},
		{"autoban_duration", "'" + DefaultAutobanDuration + "'", 1},
		{"autoban_scope", "'" + DefaultAutobanScope + "'", 1},
		{"autoban_dry_run", fmt.Sprint(DefaultAutobanDryRun), 1},
	}
	for _, tc := range cases {
		var dflt *string
		var notNull int
		if err := database.QueryRow(`SELECT dflt_value, "notnull" FROM pragma_table_info('global_config') WHERE name=?`, tc.column).Scan(&dflt, &notNull); err != nil {
			t.Fatalf("global_config.%s: %v", tc.column, err)
		}
		if dflt == nil || *dflt != tc.want {
			t.Fatalf("global_config.%s DEFAULT=%v, want %s", tc.column, dflt, tc.want)
		}
		if notNull != tc.notNull {
			t.Fatalf("global_config.%s notnull=%d, want %d", tc.column, notNull, tc.notNull)
		}
	}
}

// newColumnsRegistryDefaultDrift 对账登记通道治理值列：返回登记 dtype 与
// 常量期望不符（含登记键缺失）的键清单，完全一致时返回空切片。
func newColumnsRegistryDefaultDrift(registry, expected map[string]string) []string {
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var drifted []string
	for _, key := range keys {
		got, ok := registry[key]
		if !ok {
			drifted = append(drifted, fmt.Sprintf("%s: 登记缺失", key))
			continue
		}
		if got != expected[key] {
			drifted = append(drifted, fmt.Sprintf("%s: 登记 %q 与常量期望 %q 不符", key, got, expected[key]))
		}
	}
	return drifted
}

// 登记通道（newColumns）的治理值列字面量必须与治理常量逐键一致。
// fresh DDL 侧由 TestFreshSchemaDefaults 钉死，双通道形状门
// （TestNewColumnsDualRegistered_matchFreshColumnShape）把登记文本对齐
// fresh DDL；但该门的「有意分叉」白名单（allowedNewColumnDivergence）
// 登记即豁免——豁免键的登记字面量随即脱离常量对账，升级库补列默认值
// 会与 fresh 库/读侧/启动回填静默分叉。本对账直读登记文本、不经白名单，
// 堵住豁免路径；判别力以漂移/缺失/一致三探针自证（与 forbidden 通道
// 判别力钉测同构：通道可红可绿双向实证）。
func TestNewColumnsRegistryDefaults_matchGovernedConstants(t *testing.T) {
	expected := map[string]string{
		"global_config.cert_renewal_days":        "INTEGER DEFAULT " + fmt.Sprint(DefaultCertRenewalDays),
		"global_config.cert_renewal_attempts":    "INTEGER DEFAULT " + fmt.Sprint(DefaultCertRenewalAttempts),
		"global_config.cert_expiry_days":         "INTEGER DEFAULT " + fmt.Sprint(DefaultCertExpiryDays),
		"global_config.task_log_size_mb":         "INTEGER DEFAULT " + fmt.Sprint(DefaultTaskLogSizeMB),
		"global_config.audit_log_size_mb":        "INTEGER DEFAULT " + fmt.Sprint(DefaultAuditLogSizeMB),
		"global_config.runtime_log_size_mb":      "INTEGER DEFAULT " + fmt.Sprint(DefaultRuntimeLogSizeMB),
		"global_config.audit_retention_months":   "INTEGER DEFAULT " + fmt.Sprint(DefaultAuditRetentionMonths),
		"global_config.caddy_log_level":          "VARCHAR(10) DEFAULT '" + DefaultCaddyLogLevel + "'",
		"global_config.caddy_log_size_mb":        "INTEGER NOT NULL DEFAULT " + fmt.Sprint(DefaultCaddyLogSizeMB),
		"global_config.request_body_max_size_mb": "INTEGER NOT NULL DEFAULT " + fmt.Sprint(DefaultRequestBodyMaxSizeMB),
		"global_config.http_read_timeout":        "INTEGER NOT NULL DEFAULT " + fmt.Sprint(DefaultHTTPReadTimeout),
		"global_config.http_write_timeout":       "INTEGER NOT NULL DEFAULT " + fmt.Sprint(DefaultHTTPWriteTimeout),
		"global_config.http_idle_timeout":        "INTEGER NOT NULL DEFAULT " + fmt.Sprint(DefaultHTTPIdleTimeout),
		"global_config.timezone":                 "VARCHAR(50) DEFAULT '" + DefaultTimezone + "'",
	}
	if drifted := newColumnsRegistryDefaultDrift(newColumnsRegistry, expected); len(drifted) > 0 {
		t.Fatalf("newColumns 登记字面量与治理常量漂移：%s", strings.Join(drifted, "; "))
	}

	// 漂移探针：常量调整未同步登记文本的形态必须被通道命中。
	drifted := newColumnsRegistryDefaultDrift(newColumnsRegistry, map[string]string{
		"global_config.cert_renewal_days": "INTEGER DEFAULT 999",
	})
	if len(drifted) != 1 || !strings.Contains(drifted[0], "global_config.cert_renewal_days") {
		t.Fatalf("漂移登记探针未被通道命中：%v", drifted)
	}
	// 缺失探针：登记键被删除的形态必须被通道命中。
	drifted = newColumnsRegistryDefaultDrift(newColumnsRegistry, map[string]string{
		"global_config.probe_absent_column": "INTEGER DEFAULT 1",
	})
	if len(drifted) != 1 || !strings.Contains(drifted[0], "global_config.probe_absent_column") {
		t.Fatalf("登记缺失探针未被通道命中：%v", drifted)
	}
	// 一致探针：完全一致的登记不得误报（匹配谓词不失真）。
	drifted = newColumnsRegistryDefaultDrift(newColumnsRegistry, map[string]string{
		"global_config.cert_renewal_days": newColumnsRegistry["global_config.cert_renewal_days"],
	})
	if len(drifted) != 0 {
		t.Fatalf("一致登记误报漂移：%v", drifted)
	}
}

// 升级路径的 lb_rules 重建 DDL 必须与 fresh CREATE 同形
// ——健康检查族五列曾退化为可空（health_check_timeout 默认还是陈旧的 5），
// 重建后的库形状与新建库分叉且无后续收敛路径。断言重建后 pragma_table_info
// 与 fresh 逐列相等（name/type/notnull/dflt_value/pk 全字段）。
func TestLbRulesRebuildSchema_matchesFreshDDL(t *testing.T) {
	// Given：fresh 库在完整启动（createTables + runMigrations）后的稳态形状
	preserveDatabaseHandles(t)
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	freshShape := lbRulesPragmaShape(t, DB)
	if err := Close(); err != nil {
		t.Fatalf("close fresh database: %v", err)
	}

	// And：旧 PK 库（id 主键）走真实升级路径
	legacyDir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(legacyDir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	createLegacyLbRulesTables(t, legacy, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsLegacyOrigin})
	if _, err := legacy.Exec(`INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'http', 8080, 'lb_ddl_parity')`); err != nil {
		t.Fatalf("seed legacy rule: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	// When
	if err := Initialize(legacyDir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then：重建后的 notnull/dflt_value 逐列与 fresh 相等（列集合一致；
	// 列序不参与比较——fresh 的 newColumns 通道以 ALTER 追加列，顺序天然不同）
	rebuiltShape := lbRulesPragmaShape(t, DB)
	freshColumns := make(map[string]pragmaColumn, len(freshShape))
	for _, column := range freshShape {
		freshColumns[column.Name] = column
	}
	if len(rebuiltShape) != len(freshColumns) {
		t.Fatalf("rebuilt column count=%d, fresh=%d", len(rebuiltShape), len(freshColumns))
	}
	for _, rebuilt := range rebuiltShape {
		fresh, ok := freshColumns[rebuilt.Name]
		if !ok {
			t.Fatalf("rebuilt column %q missing from fresh schema", rebuilt.Name)
		}
		if rebuilt.NotNull != fresh.NotNull || rebuilt.Default != fresh.Default {
			t.Fatalf("column %q rebuilt={notnull:%d default:%v}, fresh={notnull:%d default:%v}（升级重建 DDL 必须与 fresh 同形）",
				rebuilt.Name, rebuilt.NotNull, rebuilt.Default, fresh.NotNull, fresh.Default)
		}
	}
}

func TestCertJobsRebuildSchema_matchesFreshDDL(t *testing.T) {
	// Given fresh DDL 的列形，以及同库模拟的旧约束 cert_jobs 表。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create fresh tables: %v", err)
	}
	freshShape := tablePragmaShape(t, database, "cert_jobs")
	if _, err := database.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop fresh cert_jobs for legacy fixture: %v", err)
	}
	createLegacyCertJobs(t, database, "'queued'", "'queued','disabled','waiting_order_ready'")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_parity','parity.example','waiting_order_ready')`); err != nil {
		t.Fatalf("seed legacy certificate job: %v", err)
	}

	// When 旧约束触发生成真实重建表。
	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("rebuild cert_jobs: %v", err)
	}

	// Then 重建列集合及 name/type/notnull/default/pk 与 fresh 逐列一致。
	rebuiltShape := tablePragmaShape(t, database, "cert_jobs")
	freshColumns := make(map[string]pragmaColumn, len(freshShape))
	for _, column := range freshShape {
		freshColumns[column.Name] = column
	}
	if len(rebuiltShape) != len(freshColumns) {
		t.Fatalf("cert_jobs rebuilt column count=%d, fresh=%d", len(rebuiltShape), len(freshColumns))
	}
	for _, rebuilt := range rebuiltShape {
		fresh, ok := freshColumns[rebuilt.Name]
		if !ok {
			t.Fatalf("cert_jobs rebuilt column %q missing from fresh schema", rebuilt.Name)
		}
		if rebuilt != fresh {
			t.Fatalf("cert_jobs column %q rebuilt=%+v, fresh=%+v", rebuilt.Name, rebuilt, fresh)
		}
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE rule_id='lb_parity'`).Scan(&status); err != nil {
		t.Fatalf("read rebuilt certificate job: %v", err)
	}
	if status != "waiting_order_ready" {
		t.Fatalf("rebuilt certificate job status=%q, want preserved waiting_order_ready", status)
	}
}

type pragmaColumn struct {
	Name    string
	Type    string
	NotNull int
	Default sql.NullString
	PK      int
}

func lbRulesPragmaShape(t *testing.T, database *sql.DB) []pragmaColumn {
	t.Helper()
	return tablePragmaShape(t, database, "lb_rules")
}

func tablePragmaShape(t *testing.T, database *sql.DB, table string) []pragmaColumn {
	t.Helper()
	rows, err := database.Query(`SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatalf("read %s pragma: %v", table, err)
	}
	defer rows.Close()
	var shape []pragmaColumn
	for rows.Next() {
		var column pragmaColumn
		if err := rows.Scan(&column.Name, &column.Type, &column.NotNull, &column.Default, &column.PK); err != nil {
			t.Fatalf("scan %s pragma: %v", table, err)
		}
		shape = append(shape, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s pragma: %v", table, err)
	}
	return shape
}

func TestRunMigrationsBackfillsInvalidValueColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// cert_expiry_days 回填钉（defaultUpdates 已含该列——
	// NULL/<=0 归 DefaultCertExpiryDays；用户已设有效值保留）。
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=0, cert_renewal_days=0, cert_renewal_attempts=0"); err != nil {
		t.Fatalf("zero cert expiry/renewal columns: %v", err)
	}
	// 存量脏形态：0 值行 + 用户已设有效值行（fresh DDL 对本批列 NOT NULL，
	// NULL 形态仅存在于存量库的可空列——由迁移 WHERE IS NULL 分支覆盖，
	// fresh 库结构上不可达）。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb-backfill-a','a','http',9101,1)`); err != nil {
		t.Fatalf("seed rule a: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET request_body_max_size_mb=0, http_read_timeout=0, http_write_timeout=0, http_idle_timeout=0, caddy_log_size_mb=0`); err != nil {
		t.Fatalf("zero globals: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET health_check_interval=0, health_check_timeout=0, health_check_unhealthy_threshold=0, health_check_healthy_threshold=0, tcp_try_interval=0, strategy=NULL WHERE caddy_id='lb-backfill-a'`); err != nil {
		t.Fatalf("zero rule columns: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,tcp_try_interval)
		VALUES ('lb-backfill-b','b','http',9102,1,37,13,5,4,777)`); err != nil {
		t.Fatalf("seed rule b: %v", err)
	}
	if _, err := database.Exec("UPDATE lb_rules SET strategy='least_conn' WHERE caddy_id='lb-backfill-b'"); err != nil {
		t.Fatalf("seed explicit strategy: %v", err)
	}

	// When：迁移两轮——幂等且不覆盖用户已设值。
	for round := range 2 {
		if err := runMigrations(); err != nil {
			t.Fatalf("run migrations round %d: %v", round, err)
		}
	}

	// Then：NULL/<=0 行全部归默认；用户已设值原样保留。
	assertScalar := func(query string, want any) {
		t.Helper()
		var got any
		if err := database.QueryRow(query).Scan(&got); err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		switch w := want.(type) {
		case int:
			if int(got.(int64)) != w {
				t.Fatalf("query %q = %v, want %d", query, got, w)
			}
		case string:
			if got.(string) != w {
				t.Fatalf("query %q = %v, want %q", query, got, w)
			}
		}
	}
	assertScalar("SELECT request_body_max_size_mb FROM global_config WHERE id=1", DefaultRequestBodyMaxSizeMB)
	assertScalar("SELECT http_read_timeout FROM global_config WHERE id=1", DefaultHTTPReadTimeout)
	assertScalar("SELECT http_write_timeout FROM global_config WHERE id=1", DefaultHTTPWriteTimeout)
	assertScalar("SELECT http_idle_timeout FROM global_config WHERE id=1", DefaultHTTPIdleTimeout)
	assertScalar("SELECT caddy_log_size_mb FROM global_config WHERE id=1", DefaultCaddyLogSizeMB)
	// cert_expiry_days 回填归 DefaultCertExpiryDays。
	assertScalar("SELECT cert_expiry_days FROM global_config WHERE id=1", DefaultCertExpiryDays)
	// 续期天数/次数同批回填（此前只有 DDL DEFAULT）。
	assertScalar("SELECT cert_renewal_days FROM global_config WHERE id=1", DefaultCertRenewalDays)
	assertScalar("SELECT cert_renewal_attempts FROM global_config WHERE id=1", DefaultCertRenewalAttempts)
	assertScalar("SELECT health_check_interval FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckInterval)
	assertScalar("SELECT health_check_timeout FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckTimeout)
	assertScalar("SELECT health_check_unhealthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckUnhealthyThreshold)
	assertScalar("SELECT health_check_healthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckHealthyThreshold)
	assertScalar("SELECT tcp_try_interval FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultTCPTryInterval)
	assertScalar("SELECT COALESCE(strategy,'') FROM lb_rules WHERE caddy_id='lb-backfill-a'", "weighted_round_robin")
	// 用户已设值保留（幂等第二轮后仍原样）。
	assertScalar("SELECT health_check_interval FROM lb_rules WHERE caddy_id='lb-backfill-b'", 37)
	assertScalar("SELECT health_check_timeout FROM lb_rules WHERE caddy_id='lb-backfill-b'", 13)
	assertScalar("SELECT health_check_unhealthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-b'", 5)
	assertScalar("SELECT health_check_healthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-b'", 4)
	assertScalar("SELECT tcp_try_interval FROM lb_rules WHERE caddy_id='lb-backfill-b'", 777)
	assertScalar("SELECT strategy FROM lb_rules WHERE caddy_id='lb-backfill-b'", "least_conn")
}

// 6 张整表重建表此前只有 lb_rules/cert_jobs 有
// 「重建 DDL ≡ fresh DDL 全列 name/type/notnull/default/pk」钉测；users /
// security_policies / nodes（nodes 见 db_nodes_rebuild_parity_test.go）缺回归
// 形状——新增列只改 fresh 不改正重建时，二次 ensureNewColumns 会以默认值补回
// 列，用户值静默丢失（OIDC / 三次先例）。
func assertShapeMatchesFresh(t *testing.T, table string, fresh []pragmaColumn, rebuilt []pragmaColumn) {
	t.Helper()
	freshColumns := make(map[string]pragmaColumn, len(fresh))
	for _, column := range fresh {
		freshColumns[column.Name] = column
	}
	if len(rebuilt) != len(freshColumns) {
		t.Fatalf("%s rebuilt column count=%d, fresh=%d", table, len(rebuilt), len(freshColumns))
	}
	for _, column := range rebuilt {
		want, ok := freshColumns[column.Name]
		if !ok {
			t.Fatalf("%s rebuilt column %q missing from fresh schema", table, column.Name)
		}
		if column != want {
			t.Fatalf("%s column %q rebuilt=%+v, fresh=%+v（升级重建 DDL 必须与 fresh 同形）", table, column.Name, column, want)
		}
	}
}

func TestUsersRebuildSchema_matchesFreshDDL(t *testing.T) {
	preserveDatabaseHandles(t)

	// Given fresh 稳态形状
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	freshShape := tablePragmaShape(t, DB, "users")
	if err := Close(); err != nil {
		t.Fatalf("close fresh database: %v", err)
	}

	// And 旧库：users 只有初始列（is_enabled 可空，触发 is_enabled NOT NULL 重建）
	legacyDir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(legacyDir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		display_name TEXT,
		is_enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	)`); err != nil {
		t.Fatalf("create legacy users table: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('legacy-parity','hash','admin',NULL)`); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	// When 真实升级路径
	if err := Initialize(legacyDir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then 重建形状与 fresh 逐列一致，且 NULL is_enabled 归 1 保留行。
	assertShapeMatchesFresh(t, "users", freshShape, tablePragmaShape(t, DB, "users"))
	var enabled int
	if err := DB.QueryRow(`SELECT is_enabled FROM users WHERE username='legacy-parity'`).Scan(&enabled); err != nil {
		t.Fatalf("read migrated user: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("is_enabled=%d, want 1", enabled)
	}
}

func TestSecurityPoliciesRebuildSchema_matchesFreshDDL(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create fresh tables: %v", err)
	}
	freshShape := tablePragmaShape(t, database, "security_policies")
	if _, err := database.Exec(`DROP TABLE security_policies`); err != nil {
		t.Fatalf("drop fresh security_policies for legacy fixture: %v", err)
	}
	// 历史 NOT-NULL 窗口期形态：fresh 全列，四列恢复 NOT NULL。
	if _, err := database.Exec(`CREATE TABLE security_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		mode TEXT DEFAULT 'off',
		anomaly_threshold INTEGER DEFAULT 5,
		ip_acl_mode TEXT DEFAULT '',
		ip_acl_list TEXT DEFAULT '[]',
		ip_acl_enabled BOOLEAN DEFAULT FALSE,
		ip_whitelist TEXT DEFAULT '[]',
		ip_whitelist_enabled INTEGER DEFAULT 1,
		ip_blacklist TEXT DEFAULT '[]',
		rate_limit_enabled BOOLEAN DEFAULT FALSE,
		rate_limit_rps INTEGER DEFAULT 0,
		rate_limit_burst INTEGER DEFAULT 0,
		crs_rule_groups TEXT DEFAULT '[]',
		crs_excluded_rules TEXT DEFAULT '[]',
		custom_rules TEXT DEFAULT '[]',
		block_page_id INTEGER DEFAULT 0,
		block_status_code INTEGER NOT NULL DEFAULT 0,
		enabled BOOLEAN DEFAULT TRUE,
		updated_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now')),
		geoip_countries TEXT NOT NULL DEFAULT '[]',
		geoip_mode TEXT NOT NULL DEFAULT 'deny',
		waf_check_response INTEGER NOT NULL DEFAULT 0,
		log_request_body INTEGER DEFAULT 0,
		ip_acl_list_refs TEXT DEFAULT '[]',
		ip_whitelist_refs TEXT DEFAULT '[]',
		policy_type TEXT NOT NULL DEFAULT '',
		trust_detection BOOLEAN NOT NULL DEFAULT 0,
		geoip_crawler_exempt INTEGER NOT NULL DEFAULT 0,
		geoip_crawler_engines TEXT NOT NULL DEFAULT '[]'
	)`); err != nil {
		t.Fatalf("create legacy security_policies table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,geoip_countries,geoip_mode,waf_check_response,block_status_code)
		VALUES ('legacy-policy','blocking','["CN"]','allow',1,403)`); err != nil {
		t.Fatalf("seed legacy policy: %v", err)
	}

	// When 旧 NOT NULL 触发生成真实重建表。
	if err := migrateSecurityPoliciesNullable(); err != nil {
		t.Fatalf("rebuild security_policies: %v", err)
	}

	// Then 形状与 fresh 逐列一致（四列收敛可空），且行数据保留。
	assertShapeMatchesFresh(t, "security_policies", freshShape, tablePragmaShape(t, database, "security_policies"))
	var countries, geoMode string
	var wafCheck, blockStatus int
	if err := database.QueryRow(`SELECT geoip_countries, geoip_mode, waf_check_response, block_status_code FROM security_policies WHERE name='legacy-policy'`).
		Scan(&countries, &geoMode, &wafCheck, &blockStatus); err != nil {
		t.Fatalf("read rebuilt policy: %v", err)
	}
	if countries != `["CN"]` || geoMode != "allow" || wafCheck != 1 || blockStatus != 403 {
		t.Fatalf("rebuilt policy values=(%q,%q,%d,%d), want preserved", countries, geoMode, wafCheck, blockStatus)
	}
}

// upstreams 与 lb_rules 在 migrateLbRulesPrimaryKey 同事务重建——其余 5 张
// 重建表均有「重建 DDL ≡ fresh DDL」全列钉测，upstreams 此前只有零散断言。
// 缺门时给 upstreams 加列只改 fresh DDL + newColumns，重建丢列后二次
// ensureNewColumns 以默认值补回、用户值静默丢失（server_map_lat/lon 先例）。
func TestUpstreamsRebuildSchema_matchesFreshDDL(t *testing.T) {
	// Given fresh 稳态形状
	freshDB := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create fresh tables: %v", err)
	}
	freshShape := tablePragmaShape(t, freshDB, "upstreams")

	// And 旧 PK 库形态（lb_rules id 主键 + upstreams 整型 rule_id + 历史死列）
	legacyDB := openMigrationTestDB(t)
	createLegacyLbRulesTables(t, legacyDB, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsLegacyOrigin})
	if _, err := legacyDB.Exec(`
		INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'http', 8080, 'lb_upstreams_parity');
		INSERT INTO upstreams (id, rule_id, host, port, max_connections, origin_domain) VALUES (9, 7, '127.0.0.1', 8443, 37, 'origin.example');
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	// When 真实重建路径
	if err := migrateLbRulesPrimaryKey(); err != nil {
		t.Fatalf("migrate load-balancer primary key: %v", err)
	}

	// Then upstreams 重建形状与 fresh 逐列一致，行数据保留
	assertShapeMatchesFresh(t, "upstreams", freshShape, tablePragmaShape(t, legacyDB, "upstreams"))
	var maxConnections int
	var originDomain string
	if err := legacyDB.QueryRow(`SELECT max_connections, origin_domain FROM upstreams WHERE id=9`).Scan(&maxConnections, &originDomain); err != nil {
		t.Fatalf("read rebuilt upstream: %v", err)
	}
	if maxConnections != 37 || originDomain != "origin.example" {
		t.Fatalf("rebuilt upstream=(%d,%q), want (37,origin.example)（用户值必须随重建保留）", maxConnections, originDomain)
	}
}

// global_config.timezone 的空串不是合法库值：time.LoadLocation("") 是 Go 的
// 特殊值（返回 UTC）→ ConfigureLocation("") 静默把全站时区切成 UTC，而读侧
// COALESCE(timezone,'Asia/Shanghai') 只兜 NULL。写侧已拒绝空串（设置保存/
// 备份导入同一 services.ValidateLocationName），启动迁移负责收敛带外写入或
// 旧备份恢复的存量空串/空白串。
func TestRunMigrationsBackfillsEmptyTimezone(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET timezone='' WHERE id=1"); err != nil {
		t.Fatalf("empty timezone: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	var tz string
	if err := database.QueryRow("SELECT timezone FROM global_config WHERE id=1").Scan(&tz); err != nil {
		t.Fatalf("read timezone: %v", err)
	}
	if tz != DefaultTimezone {
		t.Fatalf("timezone=%q, want %q（空串必须启动归一）", tz, DefaultTimezone)
	}

	// 用户显式设置的合法时区恒不被触碰。
	if _, err := database.Exec("UPDATE global_config SET timezone='America/New_York' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations second round: %v", err)
	}
	if err := database.QueryRow("SELECT timezone FROM global_config WHERE id=1").Scan(&tz); err != nil {
		t.Fatalf("read timezone: %v", err)
	}
	if tz != "America/New_York" {
		t.Fatalf("timezone=%q, want America/New_York（已设值不得被归一抹掉）", tz)
	}
}

// fresh DDL 与 newColumns 双通道登记同一列时，两份定义的 type/notnull/default
// 必须逐字段相等——否则 fresh 库（CREATE）与升级库（ALTER）schema 静默分叉
// （health_check_timeout 旧默认 5、request_body 兜底失效的事故形态）。
// 机械门：交集列在 fresh 库取 pragma_table_info，再用登记 dtype 在探针表
// ALTER 补列取 pragma，逐字段比对。有意分叉列登记白名单并携理由。
// allowedNewColumnDivergence 是「fresh DDL 与 newColumns 双通道有意分叉」的
// 白名单（键 → 理由），供 shape 相等门登记例外。当前为空（无已知有意分叉：
// ALTER 不支持的非常量 DEFAULT 列本就不在交集内）；登记即生效，无需改判定
// 逻辑——删掉分支留待「真正出现分叉」再写会让门失去现成的登记点。
var allowedNewColumnDivergence = map[string]string{}

func TestNewColumnsDualRegistered_matchFreshColumnShape(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 有意双通道分叉白名单见 allowedNewColumnDivergence（包级 var + 理由）。
	if _, err := database.Exec(`CREATE TABLE shape_probe (id INTEGER)`); err != nil {
		t.Fatalf("create shape probe: %v", err)
	}
	keys := make([]string, 0, len(newColumnsRegistry))
	for key := range newColumnsRegistry {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	dualRegistered := 0
	for _, key := range keys {
		parts := strings.SplitN(key, ".", 2)
		table, column := parts[0], parts[1]
		var freshType string
		var freshNotNull int
		var freshDefault sql.NullString
		err := database.QueryRow(`SELECT type, "notnull", dflt_value FROM pragma_table_info(?) WHERE name=?`, table, column).Scan(&freshType, &freshNotNull, &freshDefault)
		if errors.Is(err, sql.ErrNoRows) {
			continue // 仅 newColumns 通道列（fresh CREATE 不携带）不参与本门
		}
		if err != nil {
			t.Fatalf("read fresh %s: %v", key, err)
		}
		dualRegistered++
		if _, err := database.Exec(`ALTER TABLE shape_probe ADD COLUMN ` + column + ` ` + newColumnsRegistry[key]); err != nil {
			if reason, ok := allowedNewColumnDivergence[key]; ok {
				t.Logf("%s: ALTER 不支持登记形状（白名单：%s）：%v", key, reason, err)
				continue
			}
			t.Errorf("%s: 登记 dtype %q 无法 ALTER 补列（非常量 DEFAULT 等有意分叉须登记白名单）: %v", key, newColumnsRegistry[key], err)
			continue
		}
		var alterType string
		var alterNotNull int
		var alterDefault sql.NullString
		if err := database.QueryRow(`SELECT type, "notnull", dflt_value FROM pragma_table_info('shape_probe') WHERE name=?`, column).Scan(&alterType, &alterNotNull, &alterDefault); err != nil {
			t.Fatalf("read probe %s: %v", key, err)
		}
		if _, err := database.Exec(`ALTER TABLE shape_probe DROP COLUMN ` + column); err != nil {
			t.Fatalf("reset probe %s: %v", key, err)
		}
		diverged := !strings.EqualFold(strings.TrimSpace(freshType), strings.TrimSpace(alterType)) ||
			freshNotNull != alterNotNull ||
			freshDefault.Valid != alterDefault.Valid ||
			(freshDefault.Valid && freshDefault.String != alterDefault.String)
		if !diverged {
			continue
		}
		if reason, ok := allowedNewColumnDivergence[key]; ok {
			t.Logf("%s: 白名单分叉（%s）：fresh={%s,%d,%v} alter={%s,%d,%v}", key, reason, freshType, freshNotNull, freshDefault, alterType, alterNotNull, alterDefault)
			continue
		}
		t.Errorf("%s 双通道形状分叉：fresh={type:%s notnull:%d default:%v} newColumns={type:%s notnull:%d default:%v}",
			key, freshType, freshNotNull, freshDefault, alterType, alterNotNull, alterDefault)
	}
	if dualRegistered == 0 {
		t.Fatal("双登记交集为空（登记或 fresh DDL 结构漂移，门失效）")
	}
	t.Logf("双登记交集 %d 列全部通过相等门", dualRegistered)
}

// freshOriginalColumns 是「fresh CREATE 首发列（未登记进 newColumnsRegistry）」
// 的冻结基线。反方向门的理由：`newColumnsRegistry` 只对登记过的列补列，fresh
// DDL 单独新增而未登记的列在存量库上永不被补——升级安装启动即 no such column
// （schedule_days 事故形态，旧门只有 registry→fresh 一个方向，漏掉的正是这个
// 方向）。断言：fresh 每张表的每一列 ∈ newColumnsRegistry ∪ 本基线。
// 新增列时二选一：加入 newColumnsRegistry（升级库需要补列，推荐）或加入本基线
// 并在下方说明「首发即存在、无需迁移」。基线中登记而 fresh 已不存在的列同属
// 漂移（陈旧基线），一并报错。
var freshOriginalColumns = map[string][]string{
	"api_keys":                   {"id", "name", "key_hash", "key_prefix", "created_by", "last_used", "expires_at", "created_at"},
	"auto_backups":               {"id", "filename", "created_at", "status", "size_bytes", "sections", "trigger_type", "message"},
	"ca_providers":               {"id", "name", "provider", "directory_url", "credentials", "max_concurrent", "min_interval_ms", "enabled", "created_at", "updated_at"},
	"cert_jobs":                  {"id", "rule_id", "domain", "status", "message", "expires_at", "cert_pem", "key_pem", "created_at", "updated_at"},
	"certificate_configs":        {"id", "name", "dns_provider", "dns_credentials", "enabled", "created_at", "updated_at"},
	"cluster_register_tokens":    {"id", "token_hash", "expires_at", "used_at", "created_by", "created_at"},
	"global_config":              {"id", "caddy_config", "log_level", "is_master", "master_url", "sync_interval", "last_sync", "updated_at"},
	"lb_rules":                   {"id", "name", "description", "protocol", "listen_port", "strategy", "enable_dns_server", "dns_server", "health_check_path", "health_check_interval", "health_check_timeout", "health_check_unhealthy_threshold", "health_check_healthy_threshold", "host_header", "enable_tls", "enable_compress", "compress_types", "enabled", "created_by", "created_at", "updated_at"},
	"mfa_challenges":             {"token", "user_id", "expires_at", "consumed", "created_at"},
	"nodes":                      {"id", "name", "mode", "ip_address", "port", "is_approved", "sync_interval", "status", "last_seen", "created_at"},
	"path_rules":                 {"id", "rule_id", "sort_order", "match_type", "path", "upstreams_json", "created_at", "updated_at"},
	"revoked_jti":                {"jti_hash", "expires_at"},
	"security_block_pages":       {"id", "name", "description", "content", "is_default", "created_at", "updated_at"},
	"security_crawler_sources":   {"id", "name", "display_name", "url", "format", "update_enabled", "entry_count", "version", "update_status", "message", "last_checked", "next_update", "trigger", "started_at", "finished_at", "consecutive_failures", "created_at", "updated_at"},
	"security_crs_version":       {"id", "version", "updated_at", "auto_update"},
	"security_custom_rules":      {"id", "name", "description", "conditions", "action", "score", "enabled", "created_at", "updated_at"},
	"security_ip2region_version": {"id", "version", "updated_at", "auto_update"},
	"security_ip_lists":          {"id", "name", "description", "category", "entries", "created_by", "created_at", "updated_by", "updated_at"},
	"security_policies":          {"id", "name", "description", "mode", "anomaly_threshold", "ip_whitelist", "ip_blacklist", "rate_limit_enabled", "rate_limit_rps", "rate_limit_burst", "crs_rule_groups", "custom_rules", "enabled", "created_at", "updated_at"},
	"security_policy_bindings":   {"rule_caddy_id", "policy_id", "rank"},
	"security_threat_sources":    {"id", "name", "display_name", "url", "format", "update_enabled", "apply_enabled", "entry_count", "version", "update_status", "message", "last_checked", "next_update", "trigger", "started_at", "finished_at", "consecutive_failures", "created_at", "updated_at"},
	"task_loop_prefs":            {"task_id", "enabled", "updated_at"},
	"task_runs":                  {"id", "task_id", "family", "trigger", "status", "started_at", "finished_at", "duration_ms", "message"},
	"upstreams":                  {"id", "rule_id", "host", "port", "weight", "dynamic_dns", "enabled", "protocol"},
	"used_login_tickets":         {"jti_hash", "expires_at"},
	"users":                      {"id", "username", "password_hash", "role", "created_at", "last_login"},
}

func TestFreshDDLColumns_registeredOrBaseline(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	registered := func(table, column string) bool {
		_, ok := newColumnsRegistry[table+"."+column]
		return ok
	}
	baselined := func(table, column string) bool {
		for _, candidate := range freshOriginalColumns[table] {
			if candidate == column {
				return true
			}
		}
		return false
	}

	tableRows, err := database.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("list fresh tables: %v", err)
	}
	var tables []string
	for tableRows.Next() {
		var name string
		if err := tableRows.Scan(&name); err != nil {
			t.Fatalf("scan fresh table: %v", err)
		}
		tables = append(tables, name)
	}
	if err := tableRows.Err(); err != nil {
		t.Fatalf("iterate fresh tables: %v", err)
	}
	tableRows.Close()

	seen := map[string]map[string]bool{}
	for _, table := range tables {
		columnRows, err := database.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatalf("list fresh columns of %s: %v", table, err)
		}
		columns := map[string]bool{}
		for columnRows.Next() {
			var column string
			if err := columnRows.Scan(&column); err != nil {
				t.Fatalf("scan fresh column of %s: %v", table, err)
			}
			columns[column] = true
			if registered(table, column) || baselined(table, column) {
				continue
			}
			t.Errorf("fresh DDL 列 %s.%s 既未登记 newColumnsRegistry（存量库不会补列）也未登记 freshOriginalColumns 基线——升级库将以 no such column 失败", table, column)
		}
		if err := columnRows.Err(); err != nil {
			t.Fatalf("iterate fresh columns of %s: %v", table, err)
		}
		columnRows.Close()
		seen[table] = columns
	}

	// 反向：基线陈旧登记（列已从 fresh DDL 删除或改名）。
	baselineTables := make([]string, 0, len(freshOriginalColumns))
	for table := range freshOriginalColumns {
		baselineTables = append(baselineTables, table)
	}
	sort.Strings(baselineTables)
	for _, table := range baselineTables {
		columns, ok := seen[table]
		if !ok {
			t.Errorf("freshOriginalColumns 登记了不存在的表 %s（陈旧基线）", table)
			continue
		}
		for _, column := range freshOriginalColumns[table] {
			if !columns[column] {
				t.Errorf("freshOriginalColumns 登记了 %s.%s，但 fresh DDL 已无该列（陈旧基线）", table, column)
			}
		}
	}
}

// 治理默认值消费侧单源：时区/安全策略异常评分/健康检查与重试间隔的库读兜底
// 必须绑定 db.Default* 常量。此前这些读侧 SQL 各写一份字面量，DDL DEFAULT 改
// 值后消费侧静默分叉（request_body 同族事故形态）。本钉测按 AST 双向断言：
// 字面量不得回流（只扫字符串字面量，注释里的同款文本不再假红）+
// 常量引用必须是真实选择器表达式（注释/文本提及不再假绿）。
// 豁免声明（audit_vocabulary_migration_test.go 同形态）：本测试断言的是
// 「字面量内容+选择器引用」契约而非源码排版，属「禁止断言源码文本」约定
// 的 AST 登记豁免。
func TestGovernedDefaultLiteralsBoundInConsumers(t *testing.T) {
	cases := []struct {
		file string
		// forbidden 是不得回流的字符串字面量片段（SQL 兜底形态）。
		forbidden []string
		// forbiddenIntConversions 是不得回流的整数字面量换算形态，写成
		// int64(<n>)——快照行归一/导入门用 int64 写入 map，数值默认值不会
		// 出现在字符串字面量里，只扫字符串会漏掉这一族。
		forbiddenIntConversions []string
		required                []string
	}{
		{
			file:      "../handlers/caddy.go",
			forbidden: []string{`COALESCE(timezone,'Asia/Shanghai')`, `COALESCE(caddy_log_level,'info')`, `COALESCE(github_proxy_url,'https://v4.gh-proxy.org/')`},
			required:  []string{"db.DefaultTimezone", "db.DefaultCaddyLogLevel", "db.DefaultGitHubProxyURL"},
		},
		{
			file:      "../handlers/auditlog.go",
			forbidden: []string{`COALESCE(timezone,'Asia/Shanghai')`},
			required:  []string{"db.DefaultTimezone"},
		},
		{
			file:      "../handlers/config_changes.go",
			forbidden: []string{`COALESCE(timezone,'Asia/Shanghai')`, `COALESCE(log_level,'info')`, `COALESCE(caddy_log_level,'info')`, `COALESCE(github_proxy_url,'https://v4.gh-proxy.org/')`},
			required:  []string{"db.DefaultTimezone", "db.DefaultLogLevel", "db.DefaultCaddyLogLevel", "db.DefaultGitHubProxyURL"},
		},
		{
			file:      "../services/cluster_snapshot.go",
			forbidden: []string{`COALESCE(timezone,'Asia/Shanghai')`, `COALESCE(log_level,'info')`},
			required:  []string{"db.DefaultTimezone", "db.DefaultLogLevel"},
		},
		{
			file:      "../services/tz.go",
			forbidden: []string{`COALESCE(timezone,'Asia/Shanghai')`, `COALESCE(log_level,'info')`},
			required:  []string{"db.DefaultTimezone", "db.DefaultLogLevel"},
		},
		// 启动期时区读侧（进程时区基准）同属消费侧：漏登记时 DDL 默认值变更
		// 后运行期时间轴与面板展示时间轴静默分叉。
		{
			file:      "../../cmd/server/main.go",
			forbidden: []string{`COALESCE(timezone,'Asia/Shanghai')`},
			required:  []string{"db.DefaultTimezone"},
		},
		{
			file:                    "../handlers/config_backup.go",
			forbidden:               []string{`"anomaly_threshold": int64(5)`, `policy["anomaly_threshold"] = int64(5)`},
			forbiddenIntConversions: []string{"int64(403)"},
			required: []string{
				"db.DefaultAnomalyThreshold", "db.DefaultBlockStatusCode",
				"db.DefaultHumanVerifyType", "db.DefaultHumanVerifyTTL",
				"db.DefaultCCRPSLimit", "db.DefaultCCRPSWindow",
				"db.DefaultCC4xxRatio", "db.DefaultCCSessionUAThreshold",
			},
		},
		{
			// 快照策略行归一（apply 写侧与 security 节哈希输入共用）是治理
			// 默认值的第三份副本：此前写死 int64(5)/int64(403)，常量调整后
			// 创建侧默认与从端归一静默分叉。
			file:                    "../services/cluster_apply.go",
			forbiddenIntConversions: []string{"int64(5)", "int64(403)"},
			required: []string{
				"db.DefaultAnomalyThreshold", "db.DefaultBlockStatusCode",
				// 五阶段模型（2026-11-12）：阶段 3 人机验证 / CC 触发的快照归一默认值同族
				"db.DefaultHumanVerifyType", "db.DefaultHumanVerifyTTL",
				"db.DefaultCCRPSLimit", "db.DefaultCCRPSWindow",
				"db.DefaultCC4xxRatio", "db.DefaultCCSessionUAThreshold",
			},
		},
		{
			// 启动归一 SQL 的 block_status_code 回退值同样绑定常量。
			file:     "../services/security_normalize.go",
			required: []string{"db.DefaultBlockStatusCode"},
		},
		{
			// CA 提供商并发/间隔的读侧 COALESCE 与写侧归一同一对常量：
			// 默认间隔曾在归一实现里写死 1000（DDL/读侧 2000），按来源不同
			// 节流差一倍。
			file:      "../services/caproviders.go",
			forbidden: []string{"COALESCE(min_interval_ms,2000)", "COALESCE(max_concurrent,1)"},
			required:  []string{"db.DefaultCAProviderMinIntervalMS", "db.DefaultCAProviderMaxConcurrent"},
		},
		{
			// 集群快照的 CA 行读侧 COALESCE 与从端落库门同源。
			file:      "../services/cluster_snapshot.go",
			forbidden: []string{"COALESCE(min_interval_ms,2000)", "COALESCE(max_concurrent,1)"},
			required:  []string{"db.DefaultCAProviderMinIntervalMS", "db.DefaultCAProviderMaxConcurrent"},
		},
		{
			// 导入的 NULL 回填 + 行级归一必须与 DDL 默认/写侧同源；数值写入
			// map 用 int64(...) 形态，字符串扫描覆盖不到。lb_rules 行的健康
			// 检查四列与 tcp_try_interval 同批绑定治理常量。
			file: "../handlers/config_backup.go",
			forbiddenIntConversions: []string{
				"int64(2000)", "int64(10)", "int64(2)", "int64(3)", "int64(250)",
			},
			required: []string{
				"db.DefaultCAProviderMinIntervalMS", "db.DefaultCAProviderMaxConcurrent",
				"db.DefaultHealthCheckInterval", "db.DefaultHealthCheckTimeout",
				"db.DefaultHealthCheckUnhealthyThreshold", "db.DefaultHealthCheckHealthyThreshold",
				"db.DefaultTCPTryInterval",
			},
		},
		{
			file: "../handlers/config_import_v1.go",
			forbidden: []string{
				"rule.HealthFails = 3", "rule.HealthInt = 10", ", 2, ?, 0, 0, 250,",
			},
			required: []string{
				"db.DefaultHealthCheckUnhealthyThreshold", "db.DefaultHealthCheckInterval",
				"db.DefaultHealthCheckHealthyThreshold", "db.DefaultTCPTryInterval",
			},
		},
		{
			// 任务日志阈值读侧：字面量兜底会让保存的默认值调整后面板阈值、
			// 真实滚动阈值与导入钳制默认值静默分叉。
			file:      "../services/tasklog.go",
			forbidden: []string{`COALESCE(task_log_size_mb, 10)`, "sizeMB = 10", "10 * 1024 * 1024"},
			required:  []string{"db.DefaultTaskLogSizeMB"},
		},
		{
			// 审计保留月数（不可逆删除的截止口径）：读侧 COALESCE 兜底、
			// 无配置行/migration 窗口的回退值必须与 DDL DEFAULT 同源。
			file:      "../services/auditlog.go",
			forbidden: []string{`COALESCE(audit_retention_months, 3)`},
			required:  []string{"db.DefaultAuditRetentionMonths"},
		},
		{
			// 审计日志轮转阈值（waf-audit 兜底/轮转判据同源）。
			file:      "../services/auditlog_rotation.go",
			forbidden: []string{`COALESCE(audit_log_size_mb, 10)`},
			required:  []string{"db.DefaultAuditLogSizeMB"},
		},
		{
			// 运行日志滚动阈值：init 兜底与 30s 刷新读侧同一默认值。
			file:      "../services/logrotate.go",
			forbidden: []string{`COALESCE(runtime_log_size_mb,100)`},
			required:  []string{"db.DefaultRuntimeLogSizeMB"},
		},
		{
			// 日志统计面板的阈值/保留月数展示：四个大小默认值 + 保留期默认值
			// 按面板口径展示，必须与实际滚动/清理口径同源（此处读点是
			// 列名+数字实参，AST 只扫字符串字面量，故以选择器引用为判据）。
			file: "../handlers/logstats.go",
			required: []string{
				"db.DefaultAuditLogSizeMB", "db.DefaultRuntimeLogSizeMB",
				"db.DefaultCaddyLogSizeMB", "db.DefaultTaskLogSizeMB",
				"db.DefaultAuditRetentionMonths",
			},
		},
		{
			// 自动封禁读侧六列 COALESCE 与无库默认结构体必须同源：调整
			// 窗口/阈值/封禁时长时，运行期读取与迁移回填不得分叉。
			file: "../services/autoban.go",
			forbidden: []string{
				"COALESCE(autoban_threshold,100)",
				"COALESCE(autoban_window_minutes,5)",
				"COALESCE(autoban_duration,'1h')",
				"COALESCE(autoban_scope,'all')",
				"COALESCE(autoban_dry_run,1)",
			},
			required: []string{
				"db.DefaultAutobanEnabled", "db.DefaultAutobanThreshold",
				"db.DefaultAutobanWindowMinutes", "db.DefaultAutobanDuration",
				"db.DefaultAutobanScope", "db.DefaultAutobanDryRun",
			},
		},
		{
			// 集群快照装载的自动备份/自动封禁默认值必须与 DDL、启动回填和
			// 运行期读侧同源：主从 canonical 依赖同一 COALESCE 兜底。
			file: "../services/cluster_snapshot.go",
			forbidden: []string{
				"COALESCE(auto_backup_enabled,0)", "COALESCE(auto_backup_frequency,'daily')",
				"COALESCE(auto_backup_time,'03:00')", "COALESCE(auto_backup_day,1)",
				"COALESCE(auto_backup_keep,7)",
				"COALESCE(autoban_enabled,0)", "COALESCE(autoban_threshold,100)",
				"COALESCE(autoban_window_minutes,5)", "COALESCE(autoban_duration,'1h')",
				"COALESCE(autoban_scope,'all')", "COALESCE(autoban_dry_run,1)",
			},
			required: []string{
				"db.DefaultAutoBackupEnabled", "db.DefaultAutoBackupFrequency", "db.DefaultAutoBackupTime",
				"db.DefaultAutoBackupDay", "db.DefaultAutoBackupKeep", "db.DefaultAutoBackupSections",
				"db.DefaultAutobanEnabled", "db.DefaultAutobanThreshold", "db.DefaultAutobanWindowMinutes",
				"db.DefaultAutobanDuration", "db.DefaultAutobanScope", "db.DefaultAutobanDryRun",
			},
		},
		{
			// 备份导入的回退排程/开关必须与 DDL 默认和自动备份读侧同源；
			// 任务级排程回填与导入整型钳制表的默认值（Def 列）同理——字面量
			// 副本会让 DDL/设置页常量调整后导入产物静默漂移。
			file: "../handlers/config_backup.go",
			forbidden: []string{
				"COALESCE(auto_backup_frequency,'daily')",
				"COALESCE(auto_backup_day,1)",
				"COALESCE(auto_backup_enabled,0)",
				"1,2,3,4,5,6,7", "04:00",
			},
			required: []string{
				"db.DefaultAutoBackupEnabled", "db.DefaultAutoBackupFrequency",
				"db.DefaultAutoBackupDay",
				"db.DefaultScheduleDays", "db.DefaultScheduleTime",
				"db.DefaultJWTExpireMinutes", "db.DefaultAuditRetentionMonths",
				"db.DefaultCaddyLogSizeMB", "db.DefaultAuditLogSizeMB",
				"db.DefaultTaskLogSizeMB", "db.DefaultRuntimeLogSizeMB",
				"db.DefaultCertRenewalDays", "db.DefaultCertRenewalAttempts",
				"db.DefaultCertExpiryDays",
				"db.DefaultHTTPReadTimeout", "db.DefaultHTTPWriteTimeout",
				"db.DefaultHTTPIdleTimeout",
			},
		},
		{
			// 调度读侧（EnabledFn/NextSlotFn/写开关读旧值）的 COALESCE 兜底
			// 必须绑定治理常量：字面量第二参数是 DDL/启动回填之外的第二份
			// 副本，改默认值后调度行为与设置页静默分叉。
			file: "../services/autobackup.go",
			forbidden: []string{
				"COALESCE(auto_backup_enabled,0)", "COALESCE(auto_backup_frequency,'daily')",
				"COALESCE(auto_backup_time,'03:00')", "COALESCE(auto_backup_day,1)",
			},
			required: []string{
				"db.DefaultAutoBackupEnabled", "db.DefaultAutoBackupFrequency",
				"db.DefaultAutoBackupTime", "db.DefaultAutoBackupDay",
			},
		},
		{
			// 设置页读侧与 keep/day 归一口径的默认值同一常量族：handlers 局部
			// 常量只允许「引用 db 治理常量」，不得再持数字字面量。
			file: "../handlers/autobackup.go",
			forbidden: []string{
				"COALESCE(auto_backup_enabled,0)", "COALESCE(auto_backup_frequency,'daily')",
				"COALESCE(auto_backup_time,'03:00')", "COALESCE(auto_backup_day,1)",
				"COALESCE(auto_backup_keep,7)",
			},
			required: []string{
				"db.DefaultAutoBackupEnabled", "db.DefaultAutoBackupFrequency",
				"db.DefaultAutoBackupTime", "db.DefaultAutoBackupDay", "db.DefaultAutoBackupKeep",
			},
		},
		{
			// 集群快照装载的日志体量/保留期/JWT/同步间隔与 Caddy 日志轴/
			// 三类 HTTP 超时兜底必须绑定治理常量：与 handlers/caddy.go
			// GetConfig 读点同口径，DDL/常量调整默认值后快照下发（主端
			// canonical 与从端 apply）不得与面板读侧静默分叉。
			file: "../services/cluster_snapshot.go",
			forbidden: []string{
				"COALESCE(task_log_size_mb,10)", "COALESCE(audit_log_size_mb,10)",
				"COALESCE(runtime_log_size_mb,100)", "COALESCE(audit_retention_months,3)",
				"COALESCE(jwt_expire_minutes,20)", "COALESCE(sync_interval,60)",
				"COALESCE(caddy_log_level,'info')", "COALESCE(caddy_log_size_mb,100)",
				"COALESCE(http_read_timeout,60)", "COALESCE(http_write_timeout,60)",
				"COALESCE(http_idle_timeout,120)",
			},
			required: []string{
				"db.DefaultTaskLogSizeMB", "db.DefaultAuditLogSizeMB", "db.DefaultRuntimeLogSizeMB",
				"db.DefaultAuditRetentionMonths", "db.DefaultJWTExpireMinutes", "db.DefaultSyncInterval",
				"db.DefaultCaddyLogLevel", "db.DefaultCaddyLogSizeMB",
				"db.DefaultHTTPReadTimeout", "db.DefaultHTTPWriteTimeout", "db.DefaultHTTPIdleTimeout",
			},
		},
		{
			// 登录会话有效期读侧与 DDL DEFAULT/启动回填同一常量：兜底字面量
			// 会让常量调整后签发口径与面板读侧静默分叉。
			file:      "../handlers/auth.go",
			forbidden: []string{"COALESCE(jwt_expire_minutes,20)"},
			required:  []string{"db.DefaultJWTExpireMinutes"},
		},
		{
			// 集群读侧 sync_interval COALESCE 兜底（状态展示/节点列表/同步
			// 循环/票据在线判定/主端巡检）与 DDL、启动回填、快照装载同源：
			// 默认间隔调整后各读点不得与设置页分叉。
			file:      "../services/cluster_status.go",
			forbidden: []string{"COALESCE(sync_interval,60)"},
			required:  []string{"db.DefaultSyncInterval"},
		},
		{
			file:      "../services/cluster_sync.go",
			forbidden: []string{"COALESCE(sync_interval,60)"},
			required:  []string{"db.DefaultSyncInterval"},
		},
		{
			file:      "../services/cluster_ticket.go",
			forbidden: []string{"COALESCE(sync_interval,60)"},
			required:  []string{"db.DefaultSyncInterval"},
		},
		{
			file:      "../services/cluster_masterserving.go",
			forbidden: []string{"COALESCE(sync_interval,60)"},
			required:  []string{"db.DefaultSyncInterval"},
		},
		{
			// 运行期 sync_interval 归一（normalizeSyncInterval）与面板展示钳位
			// 同界：边界数字以 db 常量为唯一事实源，services 私有常量只允许
			// 引用治理常量，不得另持一份 10/60/86400。
			file: "../services/cluster.go",
			required: []string{
				"db.MinSyncIntervalSeconds", "db.MaxSyncIntervalSeconds", "db.DefaultSyncInterval",
			},
		},
		{
			// GetConfig 展示侧的 sync_interval 钳位（低于下限归默认、高于上限
			// 钳顶）与运行期归一同一组边界：展示与运行期各持一份边界数字时，
			// 常量调整后节点状态判定与面板展示静默分叉。
			file: "../handlers/caddy.go",
			required: []string{
				"db.MinSyncIntervalSeconds", "db.MaxSyncIntervalSeconds", "db.DefaultSyncInterval",
			},
		},
		{
			// 启动钳位读侧的审计保留月数兜底与 DDL/设置页读侧同源：兜底字面量
			// 会在常量调整后让钳位读错基准值。
			file:      "../handlers/handlers.go",
			forbidden: []string{"COALESCE(audit_retention_months,3)"},
			required:  []string{"db.DefaultAuditRetentionMonths"},
		},
		{
			// Caddy 渲染侧的运行日志级别兜底与面板读侧/快照装载同源。
			file:      "../services/caddy.go",
			forbidden: []string{"COALESCE(caddy_log_level,'info')"},
			required:  []string{"db.DefaultCaddyLogLevel"},
		},
		{
			// 威胁/爬虫任务级排程列为 NOT NULL DEFAULT，COALESCE 第二参数
			// 本不可达，纯字面量副本只会漂移：与 DDL/迁移补列/services 读
			// 失败兜底同一对常量。CRS/IP2Region 版本表列清单单源
			// （clusterRuleLibVersionColumns）的 schedule_days/schedule_time
			// 同族逃逸形态一并登记（按实际列名，无表前缀）。
			file: "../services/cluster_snapshot.go",
			forbidden: []string{
				"COALESCE(threat_schedule_days,'1,2,3,4,5,6,7')", "COALESCE(threat_schedule_time,'04:00')",
				"COALESCE(crawler_schedule_days,'1,2,3,4,5,6,7')", "COALESCE(crawler_schedule_time,'04:00')",
				"COALESCE(schedule_days,'1,2,3,4,5,6,7')", "COALESCE(schedule_time,'04:00')",
			},
			required: []string{"db.DefaultScheduleDays", "db.DefaultScheduleTime"},
		},
		{
			// 集群快照装载的 github_proxy_url COALESCE 兜底与 fresh DDL
			// DEFAULT、面板读侧（caddy.go/config_changes.go）同源。
			file:      "../services/cluster_snapshot.go",
			forbidden: []string{`COALESCE(github_proxy_url,'https://v4.gh-proxy.org/')`},
			required:  []string{"db.DefaultGitHubProxyURL"},
		},
		{
			// GitHub 下载代理读侧（读库失败回退日志与返回值、白名单首项
			// =默认项）绑定同一常量；白名单另两项是非默认枚举选项，保留
			// 字面量不属治理默认值逃逸。
			file:      "../services/crshttp.go",
			forbidden: []string{"https://v4.gh-proxy.org/"},
			required:  []string{"db.DefaultGitHubProxyURL"},
		},
		{
			// MCP update_config schema 的 github_proxy_url enum 首项=默认项
			// （与 services 白名单同序）绑定同一常量，其余 enum 项为非默认
			// 枚举选项保留字面量。
			file:      "../mcpserver/server.go",
			forbidden: []string{"https://v4.gh-proxy.org/"},
			required:  []string{"db.DefaultGitHubProxyURL"},
		},
		{
			// db 包内 DDL DEFAULT 与真值表两处（同包引用是裸标识符而非
			// 选择器，required 选择器断言不适用；值级钉测由 fresh DDL/
			// migration 测试承担，此处只钉字面量不得回流）。常量定义本身
			// 是裸 URL 字面量，不含「DEFAULT '」前缀故不被本条命中。
			file:      "db.go",
			forbidden: []string{"DEFAULT 'https://v4.gh-proxy.org/'"},
		},
		{
			// 规则写路径列清单单源的健康检查四列与 tcp_try_interval COALESCE
			// 兜底：字面量副本会让 DDL/启动回填/导入默认调整后快照导出投影
			// 静默漂移。
			file: "../services/rule_write_columns.go",
			forbidden: []string{
				"COALESCE(health_check_interval,10)", "COALESCE(health_check_timeout,2)",
				"COALESCE(health_check_unhealthy_threshold,3)", "COALESCE(health_check_healthy_threshold,2)",
				"COALESCE(tcp_try_interval,250)",
			},
			required: []string{
				"db.DefaultHealthCheckInterval", "db.DefaultHealthCheckTimeout",
				"db.DefaultHealthCheckUnhealthyThreshold", "db.DefaultHealthCheckHealthyThreshold",
				"db.DefaultTCPTryInterval",
			},
		},
		{
			// GetConfig 读侧的 request_body_max_size_mb/威胁大屏两列/安全事件
			// 保留两列 COALESCE 绑定参数与保存写侧的保留/行数上限校验边界
			// 同源：面板展示与保存校验各持字面量副本时，常量调整后静默分叉。
			file: "../handlers/caddy.go",
			forbidden: []string{
				"COALESCE(request_body_max_size_mb,128)", "COALESCE(threat_screen_mode,'map')",
				"COALESCE(threat_traffic_sample_n,-1)",
				"COALESCE(security_events_retention_days,90)", "COALESCE(security_events_row_cap,1000000)",
			},
			required: []string{
				"db.DefaultRequestBodyMaxSizeMB",
				"db.DefaultThreatScreenMode", "db.DefaultThreatTrafficSampleN",
				"db.DefaultSecurityEventsRetentionDays", "db.DefaultSecurityEventsRowCap",
				"db.MaxSecurityEventsRetentionDays", "db.MaxSecurityEventsRowCap",
			},
		},
		{
			// 配置变更对比读侧（threat_screen_mode/threat_traffic_sample_n/
			// security_events_retention_days/security_events_row_cap）与
			// GetConfig 读侧同一组绑定参数：对比基线与面板展示持两份字面量
			// 时，改默认值后变更检测基线静默漂移。
			file: "../handlers/config_changes.go",
			forbidden: []string{
				"COALESCE(threat_screen_mode,'map')", "COALESCE(threat_traffic_sample_n,-1)",
				"COALESCE(security_events_retention_days,90)", "COALESCE(security_events_row_cap,1000000)",
			},
			required: []string{
				"db.DefaultThreatScreenMode", "db.DefaultThreatTrafficSampleN",
				"db.DefaultSecurityEventsRetentionDays", "db.DefaultSecurityEventsRowCap",
			},
		},
		{
			// 备份导入的威胁大屏采样归一、安全事件保留/行数上限钳制与
			// forward_auth uri/身份头清单默认回填：钳制 def/max 与回填默认
			// 必须绑定治理常量，导入产物才与 DDL/读侧同口径。
			file:      "../handlers/config_backup.go",
			forbidden: []string{"/api/authz/forward-auth", "Remote-User,Remote-Groups,Remote-Email,Remote-Name"},
			required: []string{
				"db.DefaultThreatTrafficSampleN",
				"db.DefaultSecurityEventsRetentionDays", "db.DefaultSecurityEventsRowCap",
				"db.MaxSecurityEventsRetentionDays", "db.MaxSecurityEventsRowCap",
				"db.DefaultForwardAuthURI", "db.DefaultForwardAuthCopyHeaders",
			},
		},
		{
			// 集群快照装载（users 节 COALESCE 四列）与 request_body/保留边界/
			// 大屏采样归一函数：主端装载与从端 apply 归一的默认值持有第二份
			// 字面量时，节哈希主从恒不等（每同步周期强制全量重放）。
			file: "../services/cluster_snapshot.go",
			forbidden: []string{
				"COALESCE(request_body_max_size_mb,128)",
				"COALESCE(threat_screen_mode,'map')", "COALESCE(threat_traffic_sample_n,-1)",
				"COALESCE(security_events_retention_days,90)", "COALESCE(security_events_row_cap,1000000)",
			},
			required: []string{
				"db.DefaultRequestBodyMaxSizeMB",
				"db.DefaultSecurityEventsRetentionDays", "db.DefaultSecurityEventsRowCap",
				"db.MaxSecurityEventsRetentionDays", "db.MaxSecurityEventsRowCap",
				"db.DefaultThreatTrafficSampleN", "db.DefaultThreatScreenMode",
			},
		},
		{
			// 从端 apply 的大屏视觉模式归一（非法枚举归默认）与写侧白名单
			// 同源；落库用占位符参数，'map' 字面量只允许以枚举白名单形态
			// 存在于 models 校验器，不得回流为归一/写库默认。
			file:      "../services/cluster_apply.go",
			forbidden: []string{"COALESCE(threat_screen_mode,'map')", "threat_screen_mode='map'"},
			required:  []string{"db.DefaultThreatScreenMode"},
		},
		{
			// 安全事件保留任务的读失败/0 值兜底：包内别名必须引用治理常量，
			// 别名另持一份数字会让保留裁剪口径与 DDL/读侧静默分叉。
			file: "../services/securityevents_retention.go",
			required: []string{
				"db.DefaultSecurityEventsRetentionDays", "db.DefaultSecurityEventsRowCap",
			},
		},
		{
			// 认证网关 uri/身份头清单的传输面归一空值回填与启动回填迁移
			// 同构：默认值持有字面量副本时，改常量后新旧规则渲染分叉。
			file:      "../services/rule_transport_normalize.go",
			forbidden: []string{"/api/authz/forward-auth", "Remote-User,Remote-Groups,Remote-Email,Remote-Name"},
			required:  []string{"db.DefaultForwardAuthURI", "db.DefaultForwardAuthCopyHeaders"},
		},
		{
			// 规则特征归一的 forward_auth 空值回填：与传输面归一/导入回填
			// 同一对待常量。
			file:      "../handlers/rule_features.go",
			forbidden: []string{"/api/authz/forward-auth", "Remote-User,Remote-Groups,Remote-Email,Remote-Name"},
			required:  []string{"db.DefaultForwardAuthURI", "db.DefaultForwardAuthCopyHeaders"},
		},
		{
			// 导入链的 request_body_max_size_mb 归一带值回显：归一默认与
			// 读侧 COALESCE/DDL 同源。
			file:      "../handlers/config_import_chain.go",
			forbidden: []string{"COALESCE(request_body_max_size_mb,128)"},
			required:  []string{"db.DefaultRequestBodyMaxSizeMB"},
		},
		{
			// MCP update_config schema 的安全事件保留/行数上限边界由 db.Max*
			// 常量注入（与保存写侧校验同源）：schema 边界另持数字时，MCP
			// 更新入口与面板保存入口的合法域静默分叉。
			file: "../mcpserver/server.go",
			required: []string{
				"db.MaxSecurityEventsRetentionDays", "db.MaxSecurityEventsRowCap",
			},
		},
	}
	for _, tc := range cases {
		path := filepath.FromSlash(tc.file)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.file, err)
		}
		literals, intConversions, selectors := governedDefaultSurface(fset, file)
		for _, pattern := range tc.forbidden {
			if forbiddenLiteralHit(literals, pattern) {
				t.Errorf("%s 字符串字面量仍含写死治理默认值 %q（应绑定 db.Default* 常量）", tc.file, pattern)
			}
		}
		for _, conversion := range tc.forbiddenIntConversions {
			if forbiddenIntConversionHit(intConversions, conversion) {
				t.Errorf("%s 仍有写死数值默认值 %q（应绑定 db.Default* 常量）", tc.file, conversion)
			}
		}
		for _, binding := range tc.required {
			if !selectors[binding] {
				t.Errorf("%s 缺少治理常量选择器引用 %s", tc.file, binding)
			}
		}
	}
}

// governedDefaultSurface 一次 AST 遍历收集契约表三通道判据：字符串字面量
// （strconv.Unquote 后值）、int64(<整数字面量>) 换算形态（快照/导入侧写
// map 的数值默认值形态）与 db.X 选择器引用。TestGovernedDefaultLiterals-
// BoundInConsumers 与 forbidden 通道判别力钉测共用同一扫描口径。
func governedDefaultSurface(fset *token.FileSet, file *ast.File) (literals []string, intConversions []string, selectors map[string]bool) {
	selectors = map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				if value, err := strconv.Unquote(n.Value); err == nil {
					literals = append(literals, value)
				}
			}
		case *ast.CallExpr:
			if ident, ok := n.Fun.(*ast.Ident); ok && ident.Name == "int64" && len(n.Args) == 1 {
				if lit, ok := n.Args[0].(*ast.BasicLit); ok && lit.Kind == token.INT {
					intConversions = append(intConversions, "int64("+lit.Value+")")
				}
			}
		case *ast.SelectorExpr:
			if x, ok := n.X.(*ast.Ident); ok {
				selectors[x.Name+"."+n.Sel.Name] = true
			}
		}
		return true
	})
	return literals, intConversions, selectors
}

// forbiddenLiteralHit 报告任一字面量是否包含 forbidden 片段（契约表
// forbidden 字符串通道的匹配谓词，与逐条目报错一一对应）。
func forbiddenLiteralHit(literals []string, pattern string) bool {
	for _, lit := range literals {
		if strings.Contains(lit, pattern) {
			return true
		}
	}
	return false
}

// forbiddenIntConversionHit 报告是否出现与 forbidden 形态完全相同的
// int64(<整数字面量>) 换算（数值通道无子串语义，按形态精确相等判定）。
func forbiddenIntConversionHit(intConversions []string, conversion string) bool {
	for _, got := range intConversions {
		if got == conversion {
			return true
		}
	}
	return false
}

// contractTableStringValues 从契约登记表（TestGovernedDefaultLiterals-
// BoundInConsumers 的 cases 表）按字段键提取全部字符串字面量值：集合
// 相等断言读 required，forbidden 通道判别力钉测读 forbidden 与
// forbiddenIntConversions。登记表结构变化（字段名/载体类型）导致提取
// 为空时显性报错，不得静默按空集合放行。
func contractTableStringValues(t *testing.T, key string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "db_truth_defaults_test.go", nil, 0)
	if err != nil {
		t.Fatalf("parse db_truth_defaults_test.go: %v", err)
	}
	var values []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestGovernedDefaultLiteralsBoundInConsumers" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			entry, ok := node.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			ident, ok := entry.Key.(*ast.Ident)
			if !ok || ident.Name != key {
				return true
			}
			list, ok := entry.Value.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range list.Elts {
				literal, ok := elt.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("契约表 %s 条目 %s 解析失败: %v", key, literal.Value, err)
				}
				values = append(values, value)
			}
			return true
		})
	}
	if len(values) == 0 {
		t.Fatalf("契约表 %s 字段提取为空——登记表结构变化后须同步本提取", key)
	}
	return values
}

// 治理常量契约登记的集合相等机械断言：db.go 治理常量块（块注释
// 「库值唯一真相」锚定）与契约登记表 required 选择器集合双向相等——
// 新增治理常量不登记即红（字面量回流防护成同族敞口），登记表出现
// 悬空选择器（常量已删/已改名）同样红。新增治理常量必须加入锚定块
// 并按既有条目形态补登记，两步缺一即被本用例拦下；散落到 db.go 其他
// const 块的常量不在治理口径内，本对账不覆盖。
func TestGovernedDefaultContractRegistrations_parityWithConstantSet(t *testing.T) {
	governedConstants := func(tb *testing.T) map[string]struct{} {
		tb.Helper()
		fset := token.NewFileSet()
		// ParseComments 必带：治理块以块注释「库值唯一真相」锚定，无注释
		// 模式下 Doc 不挂载，锚点判据恒失守。
		file, err := parser.ParseFile(fset, "db.go", nil, parser.ParseComments)
		if err != nil {
			tb.Fatalf("parse db.go: %v", err)
		}
		names := map[string]struct{}{}
		found := false
		ast.Inspect(file, func(node ast.Node) bool {
			decl, ok := node.(*ast.GenDecl)
			if !ok || decl.Tok != token.CONST || decl.Doc == nil ||
				!strings.Contains(decl.Doc.Text(), "库值唯一真相") {
				return true
			}
			found = true
			for _, spec := range decl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range valueSpec.Names {
					names[name.Name] = struct{}{}
				}
			}
			return false
		})
		if !found {
			tb.Fatal("db.go 治理常量块（块注释锚「库值唯一真相」）未找到——块注释改写后须同步本锚点")
		}
		return names
	}
	registeredNames := func(tb *testing.T) map[string]struct{} {
		tb.Helper()
		names := map[string]struct{}{}
		for _, value := range contractTableStringValues(tb, "required") {
			names[strings.TrimPrefix(value, "db.")] = struct{}{}
		}
		return names
	}
	parityErr := func(governed, registered map[string]struct{}) error {
		var missing, stale []string
		for name := range governed {
			if _, ok := registered[name]; !ok {
				missing = append(missing, name)
			}
		}
		for name := range registered {
			if _, ok := governed[name]; !ok {
				stale = append(stale, name)
			}
		}
		if len(missing)+len(stale) == 0 {
			return nil
		}
		sort.Strings(missing)
		sort.Strings(stale)
		return fmt.Errorf("契约登记与治理常量全集集合不等：未登记常量 %v；悬空登记 %v", missing, stale)
	}
	withExtra := func(set map[string]struct{}, name string) map[string]struct{} {
		cloned := make(map[string]struct{}, len(set)+1)
		for key := range set {
			cloned[key] = struct{}{}
		}
		cloned[name] = struct{}{}
		return cloned
	}

	governedSet, registeredSet := governedConstants(t), registeredNames(t)
	if err := parityErr(governedSet, registeredSet); err != nil {
		t.Fatalf("生产契约必须对账相等: %v", err)
	}

	// 单侧注入假常量（新增治理常量未登记形态）必须红——对账不得自证。
	if err := parityErr(withExtra(governedSet, "DefaultProbeFutureColumn"), registeredSet); err == nil {
		t.Fatal("注入未登记假常量必须红——集合对账不得自证")
	}
	// 单侧注入假登记（登记表悬空条目形态）必须红。
	if err := parityErr(governedSet, withExtra(registeredSet, "DefaultProbeRetiredColumn")); err == nil {
		t.Fatal("注入悬空假登记必须红——集合对账不得自证")
	}
}

// forbidden 通道判别力钉测：forbidden 模式拼错=恒假绿（模式对不中任何
// 字面量即永不报错），通道自身必须可红可绿实证——把契约表全部 forbidden
// 字符串片段与 int64 换算形态逐枚注入合成源文件，经与主测试同一条扫描/
// 匹配通道（governedDefaultSurface + 两匹配谓词）实跑，逐一断言命中；
// 再以无关片段断言不误命中（判别力=双向，通道不得恒真恒假）。本用例
// 钉住通道机械失守（扫描节点类型/Unquote/匹配谓词被改坏）即红；片段与
// 真实文件的对应关系无法在测试内证明（片段描述的是禁止回流形态而非现
// 文件内容），改动既有片段仍须以临时探针（注入形态→跑主测试→还原）
// 复核可红。
func TestGovernedDefaultForbiddenScan_detectsInjectedShapes(t *testing.T) {
	patterns := contractTableStringValues(t, "forbidden")
	conversions := contractTableStringValues(t, "forbiddenIntConversions")

	// 合成回归源文件：每个片段各嵌一枚字符串字面量、每个 int64 形态各一枚
	// 换算，与真实消费文件同构地过扫描通道。
	var literalElements, conversionElements []string
	for _, pattern := range patterns {
		literalElements = append(literalElements, strconv.Quote(pattern))
	}
	for _, conversion := range conversions {
		inner := strings.TrimSuffix(strings.TrimPrefix(conversion, "int64("), ")")
		if inner == conversion {
			t.Fatalf("契约表 int64 形态 %q 不是 int64(<字面量>) 形状", conversion)
		}
		conversionElements = append(conversionElements, "int64("+inner+")")
	}
	source := "package probe\n\nvar probeLiterals = []string{" + strings.Join(literalElements, ",") + "}\n" +
		"var probeInts = []int64{" + strings.Join(conversionElements, ",") + "}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "governed_default_probe.go", source, 0)
	if err != nil {
		t.Fatalf("parse 合成探针源文件: %v", err)
	}
	literals, intConversions, _ := governedDefaultSurface(fset, file)

	for _, pattern := range patterns {
		if !forbiddenLiteralHit(literals, pattern) {
			t.Errorf("forbidden 片段 %q 注入合成字面量后未被扫描通道命中——通道机械失守", pattern)
		}
	}
	for _, conversion := range conversions {
		if !forbiddenIntConversionHit(intConversions, conversion) {
			t.Errorf("int64 形态 %q 注入合成换算后未被扫描通道命中——通道机械失守", conversion)
		}
	}

	// 反向：无关片段不得误命中。
	if forbiddenLiteralHit(literals, "COALESCE(未登记列,0)") {
		t.Error("无关片段命中扫描通道——匹配谓词失真")
	}
}
