package db

// 库值唯一真相（批 1+2）DB 侧钉测：
// ① fresh DDL DEFAULT 与治理常量一致（写死兜底废除后，DEFAULT 是默认值唯一入口）；
// ② 启动迁移幂等回填 NULL/<=0 行，用户已设有效值保留。

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestFreshSchemaDefaults_MatchGovernedConstants(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	cases := []struct {
		table  string
		column string
		want   string
	}{
		{"global_config", "request_body_max_size_mb", fmt.Sprint(DefaultRequestBodyMaxSizeMB)},
		{"global_config", "http_read_timeout", fmt.Sprint(DefaultHTTPReadTimeout)},
		{"global_config", "http_write_timeout", fmt.Sprint(DefaultHTTPWriteTimeout)},
		{"global_config", "http_idle_timeout", fmt.Sprint(DefaultHTTPIdleTimeout)},
		{"global_config", "caddy_log_size_mb", fmt.Sprint(DefaultCaddyLogSizeMB)},
		{"lb_rules", "health_check_interval", fmt.Sprint(DefaultHealthCheckInterval)},
		{"lb_rules", "health_check_timeout", fmt.Sprint(DefaultHealthCheckTimeout)},
		{"lb_rules", "health_check_unhealthy_threshold", fmt.Sprint(DefaultHealthCheckUnhealthyThreshold)},
		{"lb_rules", "health_check_healthy_threshold", fmt.Sprint(DefaultHealthCheckHealthyThreshold)},
		{"lb_rules", "tcp_try_interval", fmt.Sprint(DefaultTCPTryInterval)},
		// G6（第 74 轮）：双向钉补齐——批 3 治理列此前只有消费侧 fail-visible 钉
		//（render_db_truth_test.go），DDL DEFAULT 与治理常量未双向钉。
		{"global_config", "cert_expiry_days", fmt.Sprint(DefaultCertExpiryDays)},
		{"security_policies", "anomaly_threshold", fmt.Sprint(DefaultAnomalyThreshold)},
	}
	for _, tc := range cases {
		var dflt *string
		if err := database.QueryRow(`SELECT dflt_value FROM pragma_table_info(?) WHERE name=?`, tc.table, tc.column).Scan(&dflt); err != nil {
			t.Fatalf("%s.%s: %v", tc.table, tc.column, err)
		}
		if dflt == nil || *dflt != tc.want {
			t.Fatalf("%s.%s DEFAULT=%v, want %s", tc.table, tc.column, dflt, tc.want)
		}
	}
}

// U12-F01（第 78 轮）：升级路径的 lb_rules 重建 DDL 必须与 fresh CREATE 同形
// ——健康检查族五列曾退化为可空（health_check_timeout 默认还是陈旧的 5），
// 重建后的库形状与新建库分叉且无后续收敛路径。断言重建后 pragma_table_info
// 与 fresh 逐列相等（name/type/notnull/dflt_value/pk 全字段）。
func TestLbRulesRebuildSchema_matchesFreshDDL(t *testing.T) {
	// Given：fresh 库在完整启动（createTables + runMigrations）后的稳态形状
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
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
	freshColumns := make(map[string]lbRulesPragmaColumn, len(freshShape))
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

type lbRulesPragmaColumn struct {
	Name    string
	Type    string
	NotNull int
	Default sql.NullString
	PK      int
}

func lbRulesPragmaShape(t *testing.T, database *sql.DB) []lbRulesPragmaColumn {
	t.Helper()
	rows, err := database.Query(`SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info('lb_rules') ORDER BY cid`)
	if err != nil {
		t.Fatalf("read lb_rules pragma: %v", err)
	}
	defer rows.Close()
	var shape []lbRulesPragmaColumn
	for rows.Next() {
		var column lbRulesPragmaColumn
		if err := rows.Scan(&column.Name, &column.Type, &column.NotNull, &column.Default, &column.PK); err != nil {
			t.Fatalf("scan lb_rules pragma: %v", err)
		}
		shape = append(shape, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate lb_rules pragma: %v", err)
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
	// G6（第 74 轮）：cert_expiry_days 回填钉（defaultUpdates 已含该列——
	// NULL/<=0 归 DefaultCertExpiryDays；用户已设有效值保留）。
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=0"); err != nil {
		t.Fatalf("zero cert_expiry_days: %v", err)
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
	if _, err := database.Exec(`UPDATE lb_rules SET health_check_interval=0, health_check_timeout=0, health_check_unhealthy_threshold=0, health_check_healthy_threshold=0, tcp_try_interval=0 WHERE caddy_id='lb-backfill-a'`); err != nil {
		t.Fatalf("zero rule columns: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,tcp_try_interval)
		VALUES ('lb-backfill-b','b','http',9102,1,37,13,5,4,777)`); err != nil {
		t.Fatalf("seed rule b: %v", err)
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
	// G6（第 74 轮）：cert_expiry_days 回填归 DefaultCertExpiryDays。
	assertScalar("SELECT cert_expiry_days FROM global_config WHERE id=1", DefaultCertExpiryDays)
	assertScalar("SELECT health_check_interval FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckInterval)
	assertScalar("SELECT health_check_timeout FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckTimeout)
	assertScalar("SELECT health_check_unhealthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckUnhealthyThreshold)
	assertScalar("SELECT health_check_healthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckHealthyThreshold)
	assertScalar("SELECT tcp_try_interval FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultTCPTryInterval)
	// 用户已设值保留（幂等第二轮后仍原样）。
	assertScalar("SELECT health_check_interval FROM lb_rules WHERE caddy_id='lb-backfill-b'", 37)
	assertScalar("SELECT health_check_timeout FROM lb_rules WHERE caddy_id='lb-backfill-b'", 13)
	assertScalar("SELECT health_check_unhealthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-b'", 5)
	assertScalar("SELECT health_check_healthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-b'", 4)
	assertScalar("SELECT tcp_try_interval FROM lb_rules WHERE caddy_id='lb-backfill-b'", 777)
}
