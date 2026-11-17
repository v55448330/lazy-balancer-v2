package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 校验链 custom_rules live 回退读失败属基础设施故障（锁/IO），必须归入
// importInfraReadError 族由导入入口映射 500 固定文案——裸错误会走 400 并把
// SQL 驱动原文回显进响应/审计（同函数 ip_lists 分支同族契约）。
func TestValidateV2BackupSecurityPolicies_customRulesLiveReadFailureIsInfra(t *testing.T) {
	withBrokenDB(t)
	// ip_lists 表随备份携带（空集）——其 live 回退分支（已包 infra）不触发，
	// 首个 live 读落在 custom_rules 分支，隔离被测位点。
	tables := map[string][]map[string]any{
		"security_ip_lists": {},
		"security_policies": {{"name": "p", "custom_rules": "[1]"}},
	}
	err := validateV2BackupSecurityPoliciesWithQuerier(context.Background(), tables, false, db.DB)
	if err == nil {
		t.Fatal("live 回退读失败必须中止校验")
	}
	var infraErr *importInfraReadError
	if !errors.As(err, &infraErr) {
		t.Fatalf("err=%v, want *importInfraReadError（live 读失败 ≠ 备份内容错误）", err)
	}
	if strings.Contains(err.Error(), "注入的查询失败") || strings.Contains(err.Error(), "no such") {
		t.Fatalf("err=%q 不得回显底层驱动文本", err.Error())
	}
}

// 同族候选位点：validateBackupRuleReferences 的两处 live 引用视图读
// （lb_rules / security_policies）与 validateV2BackupAutoBackupConfig 的
// live 排程读同为「校验所需的现有配置」——读失败必须归 infra 族（500 固定
// 文案），不得以裸错误走 400 回显驱动原文。
func TestValidateBackupRuleReferences_liveReadFailuresAreInfra(t *testing.T) {
	withBrokenDB(t)
	var infraErr *importInfraReadError

	// lb_rules 缺席 + 携带 upstreams → live 规则引用视图读。
	err := validateBackupRuleReferences(map[string][]map[string]any{
		"upstreams": {{"rule_id": "r1", "host": "127.0.0.1", "port": int64(9000), "weight": int64(1)}},
	})
	if err == nil || !errors.As(err, &infraErr) {
		t.Fatalf("lb_rules live 读失败 err=%v, want *importInfraReadError", err)
	}
	if strings.Contains(err.Error(), "注入的查询失败") {
		t.Fatalf("err=%q 不得回显底层驱动文本", err.Error())
	}

	// lb_rules 随备份携带（空集）+ security_policies 缺席 + 携带绑定 →
	// live 策略引用视图读。
	err = validateBackupRuleReferences(map[string][]map[string]any{
		"lb_rules":                 {},
		"security_policy_bindings": {{"rule_caddy_id": "r1", "policy_id": int64(1)}},
	})
	if err == nil || !errors.As(err, &infraErr) {
		t.Fatalf("security_policies live 读失败 err=%v, want *importInfraReadError", err)
	}
	if strings.Contains(err.Error(), "注入的查询失败") {
		t.Fatalf("err=%q 不得回显底层驱动文本", err.Error())
	}
}

func TestValidateV2BackupAutoBackupConfig_liveScheduleReadFailureIsInfra(t *testing.T) {
	withBrokenDB(t)
	// 只带 frequency（day 缺席）→ 必须合并 live 排程，读失败即 infra。
	err := validateV2BackupAutoBackupConfig(map[string]any{"auto_backup_frequency": "daily"})
	if err == nil {
		t.Fatal("live 排程读失败必须中止校验")
	}
	var infraErr *importInfraReadError
	if !errors.As(err, &infraErr) {
		t.Fatalf("err=%v, want *importInfraReadError（live 读失败 ≠ 备份内容错误）", err)
	}
	if strings.Contains(err.Error(), "注入的查询失败") {
		t.Fatalf("err=%q 不得回显底层驱动文本", err.Error())
	}
}

// HTTP 消费点钉：校验链 infra 读失败经 writeImportChainReadFailure 映射
// 500 + 固定文案，响应不得回显驱动原文（审计 detail 由同一固定文案派生）。
func TestImportChain_infraReadFailureResponds500FixedText(t *testing.T) {
	withBrokenDB(t)
	// v1 全量形态（必需表齐备、空行）：users 空=管理员门跳过，策略行保留、
	// security_custom_rules 缺席 → live 回退读（broken DB 真实失败机制）。
	tables := map[string][]map[string]any{
		"security_policies": {{"name": "p", "custom_rules": "[1]"}},
	}
	for _, table := range configBackupV1Tables {
		if _, exists := tables[table]; !exists {
			tables[table] = []map[string]any{}
		}
	}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 1},
		Tables: tables,
	}
	_, chainErr := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})
	if chainErr == nil {
		t.Fatal("broken DB 下校验链必须失败")
	}
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/config/import", nil)
	if !writeImportChainReadFailure(c, chainErr) {
		t.Fatalf("chainErr=%v 必须被识别为基础设施读失败（500 映射）", chainErr)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（基础设施读失败不得归因备份非法）", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "读取校验所需的现有配置失败") {
		t.Fatalf("body=%s, want 固定文案", body)
	}
	if strings.Contains(body, "注入的查询失败") || strings.Contains(body, "no such") || strings.Contains(body, "SELECT") {
		t.Fatalf("body=%s 不得回显驱动原文", body)
	}
}

// 唯一键/主键预检（PRAGMA table_info/index_list/index_info）live 读失败与
// custom_rules/ip_lists live 回退同族：读「校验所需的现有配置」失败必须归
// importInfraReadError（导入 500 固定文案、预览 500），不得以裸错误走
// 400/200 valid=false 回显驱动原文（infra 读失败与备份内容错误分型）。
// broken DB 下整数列门（pragma_table_info，同族已包）对携带表先行失败——
// 单元位点直接钉三函数族归属；链/HTTP 位点钉两侧入口的 500 固定文案映射。
func TestBackupUniqueKeysPragma_InfraReadFailureMaps500FixedText(t *testing.T) {
	// Handlers 构造须先于换库：clusterService 需健康句柄过 requireMaster，
	// 校验链/预检则走换入的 broken db.DB。
	h := newBackupTestHandlers(t)
	broken := sql.OpenDB(brokenQueryConnector{})
	old := db.DB
	db.DB = broken
	t.Cleanup(func() {
		db.DB = old
		_ = broken.Close()
	})
	var infraErr *importInfraReadError

	// 单元位点：唯一键预检对携带表发起 live PRAGMA 读（table_info 先行），
	// 读失败必须中止并归 infra 族。
	_, err := backupUniqueKeySpecs("lb_rules")
	if err == nil {
		t.Fatal("PRAGMA 读失败必须中止唯一键预检")
	}
	if !errors.As(err, &infraErr) {
		t.Errorf("err=%v, want *importInfraReadError（PRAGMA 读失败 ≠ 备份内容错误）", err)
	}
	if strings.Contains(err.Error(), "注入的查询失败") || strings.Contains(err.Error(), "no such") {
		t.Errorf("err=%q 不得回显底层驱动文本", err.Error())
	}

	// 校验链/双入口消费点：任一携带表 ≥2 行即触发唯一键预检（行级门序早于
	// 形态/引用/任务/全局配置门）；JSON 夹具反序列化后与预览侧解析形态同源。
	body := buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Tables: map[string][]map[string]any{
			"lb_rules": {
				{"caddy_id": "lb_infra_a", "name": "rule-a", "protocol": "http", "listen_port": int64(9081), "enabled": int64(1)},
				{"caddy_id": "lb_infra_b", "name": "rule-b", "protocol": "http", "listen_port": int64(9082), "enabled": int64(1)},
			},
		},
	})
	var backup configBackup
	if unmarshalErr := json.Unmarshal([]byte(body), &backup); unmarshalErr != nil {
		t.Fatalf("parse fixture backup: %v", unmarshalErr)
	}
	_, chainErr := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})
	if chainErr == nil {
		t.Fatal("broken DB 下校验链必须失败")
	}
	if !errors.As(chainErr, &infraErr) {
		t.Errorf("chainErr=%v, want *importInfraReadError", chainErr)
	}
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/config/import", nil)
	if !writeImportChainReadFailure(c, chainErr) {
		t.Errorf("chainErr=%v 必须被识别为基础设施读失败（500 映射）", chainErr)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("import status=%d body=%s, want 500（基础设施读失败不得归因备份非法）", rec.Code, rec.Body.String())
	}
	importBody := rec.Body.String()
	if !strings.Contains(importBody, "读取校验所需的现有配置失败") {
		t.Errorf("import body=%s, want 固定文案", importBody)
	}
	if strings.Contains(importBody, "注入的查询失败") || strings.Contains(importBody, "no such") || strings.Contains(importBody, "PRAGMA") {
		t.Errorf("import body=%s 不得回显驱动原文", importBody)
	}

	// 预览消费点：同一备份经 ValidateConfigImport 必须 500 固定文案
	// （非 infra 校验错误在预览侧走 200 valid=false，infra 族必须分流）。
	previewRec := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", body)
	if previewRec.Code != http.StatusInternalServerError {
		t.Errorf("preview status=%d body=%s, want 500（与导入侧同映射）", previewRec.Code, previewRec.Body.String())
	}
	previewBody := previewRec.Body.String()
	if !strings.Contains(previewBody, "读取校验所需的现有配置失败") {
		t.Errorf("preview body=%s, want 固定文案", previewBody)
	}
	if strings.Contains(previewBody, "注入的查询失败") || strings.Contains(previewBody, "no such") {
		t.Errorf("preview body=%s 不得回显驱动原文", previewBody)
	}
}
