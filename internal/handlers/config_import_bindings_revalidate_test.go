package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 锁内复核必须覆盖 security_policy_bindings：初检对绑定采用「备份携带则备份行、
// 缺席则 live」回退，而绑定表无外键——初检到加锁窗口（等导入锁/排干/WAF 锁，
// 可达秒级）内管理员删除被引用策略，锁内不复验会让绑定原样落库且不触发剪枝，
// 该规则查不到策略即按无策略渲染（WAF/限流/GeoIP 静默失效）。
func TestRevalidateImportLiveDependencies_rejectsBindingToVanishedPolicy(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port) VALUES ('lb_live_rule','live-rule','http','live.example.test',80)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	// 备份未携带策略表（策略保持 live）——但窗口内策略已被删空。
	if _, err := db.DB.Exec(`DELETE FROM security_policies`); err != nil {
		t.Fatalf("clear policies: %v", err)
	}
	backup := &configBackup{Tables: map[string][]map[string]any{
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_live_rule", "policy_id": int64(42)},
		},
	}}
	sectionTables := map[string]bool{"lb_rules": false, "security_policies": false, "security_policy_bindings": true}

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	err = revalidateImportLiveDependencies(context.Background(), tx, backup, sectionTables)
	if err == nil {
		t.Fatal("绑定引用的策略在导入窗口内被删除时必须拒绝（否则该规则零防护而 UI 显示已绑定）")
	}
	if !strings.Contains(err.Error(), "security_policy_bindings") || !strings.Contains(err.Error(), "42") {
		t.Fatalf("error=%v, want 点名表/行/策略 ID（与初检同口径）", err)
	}
}

// 反向：绑定的规则与策略均存活时不得误拒（锁内复核只补缺口，不放宽成过度拒绝）。
func TestRevalidateImportLiveDependencies_acceptsBindingToLiveRuleAndPolicy(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port) VALUES ('lb_live_rule','live-rule','http','live.example.test',80)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	var policyID int64
	if err := db.DB.QueryRow(`INSERT INTO security_policies (name,mode) VALUES ('live-policy','off') RETURNING id`).Scan(&policyID); err != nil {
		t.Fatalf("seed live policy: %v", err)
	}
	backup := &configBackup{Tables: map[string][]map[string]any{
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_live_rule", "policy_id": policyID},
		},
	}}
	sectionTables := map[string]bool{"lb_rules": false, "security_policies": false, "security_policy_bindings": true}

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	if err := revalidateImportLiveDependencies(context.Background(), tx, backup, sectionTables); err != nil {
		t.Fatalf("存活引用不得误拒: %v", err)
	}
}

func TestRevalidateImportLiveDependencies_rejectsVanishedLivePolicyCustomRule(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,custom_rules) VALUES (7,'live-policy','off','[5]')`); err != nil {
		t.Fatal(err)
	}
	backup := &configBackup{Tables: map[string][]map[string]any{
		"security_custom_rules": {{"id": 6, "name": "replacement"}},
	}}
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	err = revalidateImportLiveDependencies(context.Background(), tx, backup, nil)
	if err == nil || !strings.Contains(err.Error(), "live-policy") || !strings.Contains(err.Error(), "5") {
		t.Fatalf("live 策略引用的自定义规则被替换为不存在时必须点名拒绝，err=%v", err)
	}

	backup.Tables["security_custom_rules"] = append(backup.Tables["security_custom_rules"], map[string]any{"id": 5, "name": "kept"})
	if err := revalidateImportLiveDependencies(context.Background(), tx, backup, nil); err != nil {
		t.Fatalf("备份保留被引用规则 id 时不得误拒: %v", err)
	}
}

func TestRevalidateImportLiveDependencies_usesCarriedTablesNotSelectedSections(t *testing.T) {
	t.Run("default CA section declared but table absent", func(t *testing.T) {
		newBackupTestHandlers(t)
		backup := &configBackup{Config: map[string]any{"default_ca_provider_id": 99}, Tables: map[string][]map[string]any{}}
		tx, err := db.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		err = revalidateImportLiveDependencies(context.Background(), tx, backup, map[string]bool{"ca_providers": true})
		if err == nil || !strings.Contains(err.Error(), "99") {
			t.Fatalf("分类声明不等于实际携表：live 默认 CA 仍需锁内复核，err=%v", err)
		}
	})

	t.Run("block page section declared but table absent", func(t *testing.T) {
		newBackupTestHandlers(t)
		backup := &configBackup{Tables: map[string][]map[string]any{
			"lb_rules": {{"protocol": "http", "enabled": 1, "block_page_stage1_id": 77, "block_page_stage1_status": 403}},
		}}
		tx, err := db.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		err = revalidateImportStageBlockPages(context.Background(), tx, backup.Tables)
		if err == nil || !strings.Contains(err.Error(), "77") {
			t.Fatalf("页表缺席表示保留 live，不得因分类声明跳过复核，err=%v", err)
		}
	})
}

func TestImportConfigBackup_revalidatesBindingReferencesAtProductionCallSite(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1);
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port) VALUES ('lb_live_rule','live-rule','http','live.example.test',80);
		INSERT INTO security_policies (id,name,mode) VALUES (42,'live-policy','off');`); err != nil {
		t.Fatal(err)
	}
	body := legacyBackupJSON(t, map[string][]map[string]any{
		"security_policy_bindings": {{"rule_caddy_id": "lb_live_rule", "policy_id": 42}},
	}, nil, []string{"security"})
	oldHook := configImportBeforeLock
	configImportBeforeLock = func() {
		if _, err := db.DB.Exec(`DELETE FROM security_policies WHERE id=42`); err != nil {
			t.Errorf("delete live policy before lock: %v", err)
		}
	}
	t.Cleanup(func() { configImportBeforeLock = oldHook })

	recorder := importBackupShared(h, t, body)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "42") {
		t.Fatalf("生产导入调用点必须执行锁内复核：status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var bindings int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE policy_id=42`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 {
		t.Fatalf("复核调用点被绕过后会落悬空绑定，bindings=%d", bindings)
	}
}

func TestImportConfigBackup_tlsRecheckUsesCarriedRulesTable(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1);
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,acme_config_id)
		VALUES ('lb_live_acme','live-acme','http','live-acme.example.test',443,1,1,'acme_dns',1);`); err != nil {
		t.Fatal(err)
	}
	// sections 声明 rules 但 Tables 实际不含 lb_rules：规则必须保留 live。
	// certificate_configs 空表会替换本地配置，锁内应复核 live ACME 引用并告警。
	body := buildBackup(t, backupFixtureOptions{Sections: []string{"users", "rules"}, Tables: map[string][]map[string]any{
		"users":               {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		"certificate_configs": {},
	}})
	recorder := importBackupShared(h, t, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "提供商配置悬挂") {
		t.Fatalf("分类声明不得冒充实际规则表携带，live ACME 引用复核缺失：%s", recorder.Body.String())
	}
}
