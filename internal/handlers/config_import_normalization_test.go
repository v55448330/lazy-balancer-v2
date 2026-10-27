package handlers

// 两处「归一可见性/判据源」收口的行为钉：
//  ① 全局配置数值归一进链——预览与导入对同一份备份看到同一组归一事实；
//  ② 证书任务 CA 提供商悬挂计数的规则源按「lb_rules 是否随包」二选一，
//     provider 存在性读取走传入 querier（导入路径=事务视图）。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// upstream_keepalive_timeout 归一的双通道可见性：预览输出同一条说明、导入
// 成功审计同样留痕（此前归一在运行期设置门内静默发生，预览「可导入无提示」、
// 审计只记来源与计数）；合法值两处都不得出现说明。
func TestImportConfigBackup_keepaliveClampPreviewAndAuditChannels(t *testing.T) {
	t.Run("负值归一说明双通道可见", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"upstream_keepalive_timeout": -5})

		preview := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", backup)
		if preview.Code != http.StatusOK {
			t.Fatalf("validate status=%d body=%s", preview.Code, preview.Body.String())
		}
		if body := preview.Body.String(); !strings.Contains(body, `"valid":true`) || !strings.Contains(body, "upstream_keepalive_timeout") {
			t.Fatalf("预览必须可导入且给出归一说明: body=%s", body)
		}

		imported := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if imported.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s", imported.Code, imported.Body.String())
		}
		var stored int
		if err := db.DB.QueryRow("SELECT upstream_keepalive_timeout FROM global_config WHERE id=1").Scan(&stored); err != nil {
			t.Fatalf("read keepalive: %v", err)
		}
		if stored != 0 {
			t.Fatalf("keepalive=%d, want 0（负值归零落库）", stored)
		}
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='导入' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("read import audit: %v", err)
		}
		if !strings.Contains(detail, "upstream_keepalive_timeout") {
			t.Fatalf("导入审计缺归一留痕: %q", detail)
		}
	})

	t.Run("合法值不产生说明", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"upstream_keepalive_timeout": 60})

		preview := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", backup)
		if body := preview.Body.String(); !strings.Contains(body, `"valid":true`) || strings.Contains(body, "upstream_keepalive_timeout") {
			t.Fatalf("合法值不得出现归一说明: body=%s", body)
		}
		if imported := postImportShared(t, h.ImportConfigBackup, "/config/import", backup); imported.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s", imported.Code, imported.Body.String())
		}
		var stored int
		if err := db.DB.QueryRow("SELECT upstream_keepalive_timeout FROM global_config WHERE id=1").Scan(&stored); err != nil {
			t.Fatalf("read keepalive: %v", err)
		}
		if stored != 60 {
			t.Fatalf("keepalive=%d, want 60", stored)
		}
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='导入' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("read import audit: %v", err)
		}
		if strings.Contains(detail, "upstream_keepalive_timeout") {
			t.Fatalf("合法值导入审计不得出现归一留痕: %q", detail)
		}
	})
}

// 越界/非法形态的全局配置键在链内归一并产生带值回显的说明；预览与导入
// 消费同一结果（前者 warnings，后者审计），因此本用例只钉链内唯一归一点。
func TestImportChain_normalizeGlobalConfigNumbersProducesVisibleNotes(t *testing.T) {
	backup := &configBackup{
		Config: map[string]any{
			"cert_renewal_days":        float64(3650),
			"request_body_max_size_mb": float64(100000),
		},
		Tables: map[string][]map[string]any{},
	}
	chain := &importValidationChain{ctx: context.Background(), backup: backup}
	if err := chain.normalizeGlobalConfigNumbers(); err == nil || !strings.Contains(err.Error(), "request_body_max_size_mb") {
		t.Fatalf("request body limit above 1GiB must reject import, err=%v", err)
	}

	// 合法值：零说明（预览不得对正常备份刷警告）。
	clean := &configBackup{Config: map[string]any{"request_body_max_size_mb": float64(128), "cert_renewal_days": float64(30)}, Tables: map[string][]map[string]any{}}
	cleanChain := &importValidationChain{ctx: context.Background(), backup: clean}
	if err := cleanChain.normalizeGlobalConfigNumbers(); err != nil {
		t.Fatalf("normalizeGlobalConfigNumbers(clean): %v", err)
	}
	if len(cleanChain.result.ConfigClampNotes) != 0 {
		t.Fatalf("合法值产生归一说明: %v", cleanChain.result.ConfigClampNotes)
	}
}

func TestImportValidation_rejectsRuleBodyLimitAboveEngineMaximum(t *testing.T) {
	tables := ruleTablesShared()
	tables["lb_rules"][0]["request_body_max_size_mb"] = 1025
	if err := validateV2BackupRules(tables); err == nil || !strings.Contains(err.Error(), "request_body_max_size_mb") {
		t.Fatalf("rule request body limit above 1GiB must reject import, err=%v", err)
	}

	tables["lb_rules"][0]["request_body_max_size_mb"] = 1024
	if err := validateV2BackupRules(tables); err != nil {
		t.Fatalf("rule request body limit at 1GiB must import: %v", err)
	}
}

// 计数面：非终态 ∧ 启用 ACME 规则；disabled/missing 分档；终态行不计。
// 规则源随包时用备份行（导入后视图），否则回退 live JOIN。
func TestCertJobProviderDanglingCounts_shapesAndRuleSource(t *testing.T) {
	database := initializeRuleFeatureTestDB(t)
	ctx := context.Background()
	if _, err := database.Exec(`INSERT OR IGNORE INTO global_config (id, caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_dangle_acme','dangle','http','dangle.example.test',443,1,1,'acme_dns'),
		       ('lb_dangle_missing','dangle2','http','dangle2.example.test',443,1,1,'acme_dns'),
		       ('lb_dangle_terminal','dangle3','http','dangle3.example.test',443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,enabled)
		VALUES (11,'disabled-provider','letsencrypt','https://acme.example/dir','{}',0)`); err != nil {
		t.Fatalf("seed disabled provider: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,created_at,updated_at)
		VALUES ('lb_dangle_acme','dangle.example.test','issued',11,datetime('now'),datetime('now')),
		       ('lb_dangle_missing','dangle2.example.test','issued',12,datetime('now'),datetime('now')),
		       ('lb_dangle_terminal','dangle3.example.test','failed',13,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}

	sectionTables := map[string]bool{"ca_providers": true}
	disabled, missing, err := certJobProviderDanglingCounts(ctx, database, map[string][]map[string]any{}, sectionTables)
	if err != nil {
		t.Fatalf("live source: %v", err)
	}
	if disabled != 1 || missing != 1 {
		t.Fatalf("live source disabled/missing=%d/%d, want 1/1（failed 终态行不计）", disabled, missing)
	}

	// lb_rules 随包：live 规则被禁用，备份行启用——判据必须取备份视图，
	// 否则「导入前规则态」与「导入后任务行」组合会漏计。
	if _, err := database.Exec(`UPDATE lb_rules SET enabled=0 WHERE caddy_id='lb_dangle_acme'`); err != nil {
		t.Fatalf("disable live rule: %v", err)
	}
	backupEnabled := map[string][]map[string]any{"lb_rules": {
		{"caddy_id": "lb_dangle_acme", "protocol": "http", "enabled": float64(1), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle"},
		{"caddy_id": "lb_dangle_missing", "protocol": "http", "enabled": float64(1), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle2"},
		{"caddy_id": "lb_dangle_terminal", "protocol": "http", "enabled": float64(1), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle3"},
	}}
	disabled, missing, err = certJobProviderDanglingCounts(ctx, database, backupEnabled, sectionTables)
	if err != nil {
		t.Fatalf("carried rules source: %v", err)
	}
	if disabled != 1 || missing != 1 {
		t.Fatalf("carried rules disabled/missing=%d/%d, want 1/1（按备份启用规则计数）", disabled, missing)
	}

	// 备份行禁用 → 不参与续签，零计数。
	backupDisabled := map[string][]map[string]any{"lb_rules": {
		{"caddy_id": "lb_dangle_acme", "protocol": "http", "enabled": float64(0), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle"},
		{"caddy_id": "lb_dangle_missing", "protocol": "http", "enabled": float64(0), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle2"},
		{"caddy_id": "lb_dangle_terminal", "protocol": "http", "enabled": float64(0), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle3"},
	}}
	disabled, missing, err = certJobProviderDanglingCounts(ctx, database, backupDisabled, sectionTables)
	if err != nil {
		t.Fatalf("carried disabled rules: %v", err)
	}
	if disabled != 0 || missing != 0 {
		t.Fatalf("carried disabled rules disabled/missing=%d/%d, want 0/0", disabled, missing)
	}

	// 空表随包（lb_rules 键存在但为空数组）：导入后无规则 → 零计数。判据必须
	// 是「键存在」而非「行数 > 0」，否则会回退去读 live 规则——live 行在导入
	// 全量替换后会被删除，告警与实际结果相反。
	if _, err := database.Exec(`UPDATE lb_rules SET enabled=1`); err != nil {
		t.Fatalf("re-enable live rules: %v", err)
	}
	disabled, missing, err = certJobProviderDanglingCounts(ctx, database, map[string][]map[string]any{"lb_rules": {}}, sectionTables)
	if err != nil {
		t.Fatalf("empty carried rules: %v", err)
	}
	if disabled != 0 || missing != 0 {
		t.Fatalf("empty carried rules disabled/missing=%d/%d, want 0/0（空表随包不得回退读 live）", disabled, missing)
	}
}
