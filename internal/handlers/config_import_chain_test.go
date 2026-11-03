package handlers

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 生产校验链的门序锁。链是导入提交与导入预览共用的唯一权威门序，测试用例
// 也直连它（不再自建「只串三道门」的包装）——因此新增/删除/重排任何一道门
// 都必须同步本清单：不同步即变红，避免测试夹具与生产链再次分叉。
func TestImportValidationChain_gateComposition_lockedToProduction(t *testing.T) {
	want := []string{
		"备份表集快照",
		"完整性校验",
		"分类选择解析",
		"回填表缺席还原",
		"分类过滤",
		"过滤后零导入判据",
		"软跳过准备",
		"版本状态归一",
		"行级结构门",
		"空用户表门",
		"规则库元数据剔除",
		"证书任务状态门",
		"剔除后零导入判据",
		"拦截页内容类型归一",
		"规则域名归一",
		"冲突规则置禁用",
		"规则引用校验",
		"规则形态校验",
		"安全策略校验",
		"TLS 形态校验",
		"证书任务不变量",
		"证书任务提供商悬挂",
		"管理端 TLS 门",
		"自动封禁配置门",
		"全局配置数值归一",
		"受信代理配置门",
		"运行期设置门",
		"自动备份设置门",
	}
	got := make([]string, 0, len(importValidationSteps))
	seen := make(map[string]bool, len(importValidationSteps))
	for _, step := range importValidationSteps {
		if step.name == "" || step.run == nil {
			t.Fatalf("校验链存在无名/无实现的门: %+v", step)
		}
		if seen[step.name] {
			t.Fatalf("校验链门名重复: %q", step.name)
		}
		seen[step.name] = true
		got = append(got, step.name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("生产校验链门序已变更——新增/删除/重排门必须同步本清单与用例:\n got=%v\nwant=%v", got, want)
	}
}

// unmarshalBackup 把 buildBackup 产物解回结构体（链按指针就地改写，
// 与生产 ShouldBindJSON/unmarshal 后的形态一致）。
func unmarshalBackup(t *testing.T, body string) configBackup {
	t.Helper()
	var backup configBackup
	if err := json.Unmarshal([]byte(body), &backup); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}
	return backup
}

// sections 过滤与行级门同序：未选分类的坏行不得整包拒绝（过滤在前），
// 选中分类的同一坏行必须被点名拒绝。
func TestImportValidationChain_sectionsFilteringSkipsUnselectedBrokenRows(t *testing.T) {
	newBackupTestHandlers(t)
	badRule := map[string]any{"caddy_id": "lb_bad_bool", "name": "坏布尔", "protocol": "http", "domain": "bad.test", "listen_port": 8443, "enabled": "1"}
	admin := map[string]any{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}

	t.Run("未选「负载规则」时坏行随分类过滤丢弃", func(t *testing.T) {
		backup := unmarshalBackup(t, buildBackup(t, backupFixtureOptions{
			FillAll:          true,
			Sections:         []string{"users"},
			Tables:           map[string][]map[string]any{"lb_rules": {badRule}, "users": {admin}},
			EmptyConfigIfNil: true,
		}))
		result, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})
		if err != nil {
			t.Fatalf("未选分类的坏行不得整包拒绝: %v", err)
		}
		if _, carried := backup.Tables["lb_rules"]; carried {
			t.Fatal("sections 过滤后 lb_rules 不应保留")
		}
		if result.SectionTables["lb_rules"] {
			t.Fatal("分类过滤结果不应包含 lb_rules")
		}
		if !result.IncludeGlobal {
			t.Fatal("选中「系统数据」应包含全局配置区")
		}
	})

	t.Run("选中「负载规则」时同一坏行被布尔门点名", func(t *testing.T) {
		backup := unmarshalBackup(t, buildBackup(t, backupFixtureOptions{
			FillAll:          true,
			Sections:         []string{"rules"},
			Tables:           map[string][]map[string]any{"lb_rules": {badRule}},
			EmptyConfigIfNil: true,
		}))
		_, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})
		if err == nil {
			t.Fatal("选中分类的坏布尔行必须拒绝")
		}
		for _, part := range []string{"lb_rules", "enabled"} {
			if !strings.Contains(err.Error(), part) {
				t.Fatalf("拒绝必须点名 %q，实际: %v", part, err)
			}
		}
	})

	t.Run("请求分类与备份无交集时点名拒绝", func(t *testing.T) {
		backup := unmarshalBackup(t, buildBackup(t, backupFixtureOptions{
			FillAll:          true,
			Sections:         []string{"users"},
			Tables:           map[string][]map[string]any{"users": {admin}},
			EmptyConfigIfNil: true,
		}))
		_, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{RequestedSections: "cluster"})
		if err == nil || !strings.Contains(err.Error(), "无交集") {
			t.Fatalf("err=%v, want 分类无交集拒绝", err)
		}
	})
}

// 空域名规则/空内容拦截页在行级门之前软跳过：将被丢弃行的坏布尔不得升级
// 为整包拒绝，且关联上游/引用同步剔除。
func TestImportValidationChain_emptyDomainRulesAndBlockPagesSoftSkipped(t *testing.T) {
	newBackupTestHandlers(t)
	backup := unmarshalBackup(t, buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Tables: map[string][]map[string]any{
			"lb_rules": {
				{"caddy_id": "lb_empty_domain", "name": "空域名规则", "protocol": "http", "domain": "", "listen_port": 8443, "enabled": "1"},
				{"caddy_id": "lb_page_ref", "name": "引用空页", "protocol": "http", "domain": "page.test", "listen_port": 8444, "enabled": 1, "block_page_stage1_id": 3, "block_page_stage1_status": 403},
			},
			"upstreams": {
				{"rule_id": "lb_empty_domain", "host": "127.0.0.1", "port": 9001, "enabled": 1},
				{"rule_id": "lb_page_ref", "host": "127.0.0.1", "port": 9002, "enabled": 1},
			},
			"security_block_pages": {{"id": 3, "name": "空页", "content": "", "is_default": 0}},
		},
		EmptyConfigIfNil: true,
	}))

	result, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})
	if err != nil {
		t.Fatalf("空域名/空内容页应软跳过而非拒绝: %v", err)
	}
	if len(backup.Tables["lb_rules"]) != 1 || backup.Tables["lb_rules"][0]["caddy_id"] != "lb_page_ref" {
		t.Fatalf("空域名规则应被跳过，剩余规则=%v", backup.Tables["lb_rules"])
	}
	if len(backup.Tables["upstreams"]) != 1 || backup.Tables["upstreams"][0]["rule_id"] != "lb_page_ref" {
		t.Fatalf("空域名规则的上游应随规则跳过，剩余上游=%v", backup.Tables["upstreams"])
	}
	if len(backup.Tables["security_block_pages"]) != 0 {
		t.Fatalf("空内容拦截页应被跳过，剩余=%v", backup.Tables["security_block_pages"])
	}
	// 规则级阶段页已停用：被跳过页面的规则引用不再清零（列仅随备份搬运）。
	keptRule := backup.Tables["lb_rules"][0]
	if backupInt(keptRule["block_page_stage1_id"]) != 3 || backupInt(keptRule["block_page_stage1_status"]) != 403 {
		t.Fatalf("规则阶段页引用应原样保留: %v", keptRule)
	}
	warnings := strings.Join(result.SkipWarnings, "\n")
	for _, want := range []string{"域名为空", "内容为空"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("软跳过警告应包含 %q，实际: %v", want, result.SkipWarnings)
		}
	}
}

// 纯 JSON 通道（payload 为空）威胁源表在行级门之前校验并保留本地：
// 伪造源 URL 必须拒绝，种子源表随软跳过剔除并给出保留本地警告。
func TestImportValidationChain_pureJSONThreatSourcesValidatedThenPreservedLocally(t *testing.T) {
	newBackupTestHandlers(t)
	run := func(rows []map[string]any) (importValidationResult, error) {
		backup := unmarshalBackup(t, buildBackup(t, backupFixtureOptions{
			FillAll:          true,
			Sections:         []string{"security"},
			Tables:           map[string][]map[string]any{"security_threat_sources": rows},
			EmptyConfigIfNil: true,
		}))
		result, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})
		if err != nil {
			return result, err
		}
		if _, carried := backup.Tables["security_threat_sources"]; carried {
			t.Fatal("纯 JSON 备份的威胁源表应剔除并保留本地")
		}
		return result, nil
	}

	if _, err := run([]map[string]any{{"name": "attacker-source", "url": "http://evil.test/x.txt"}}); err == nil || !strings.Contains(err.Error(), "威胁库源") {
		t.Fatalf("伪造威胁源必须拒绝，err=%v", err)
	}
	result, err := run([]map[string]any{{"name": "ustc", "url": "http://evil.test/x.txt"}})
	if err != nil {
		t.Fatalf("内置威胁源应放行: %v", err)
	}
	if !strings.Contains(strings.Join(result.SkipWarnings, "\n"), "已保留本地威胁源配置") {
		t.Fatalf("应给出保留本地威胁源警告: %v", result.SkipWarnings)
	}
}

// 证书任务状态白名单门经生产链生效（词表单一真源 services.AllJobStatuses）。
func TestImportValidationChain_rejectsCertJobStatusOutsideWhitelist(t *testing.T) {
	newBackupTestHandlers(t)
	backup := unmarshalBackup(t, buildBackup(t, backupFixtureOptions{
		FillAll:          true,
		Tables:           map[string][]map[string]any{"cert_jobs": {{"rule_id": "lb_job", "domain": "job.test", "status": "bogus"}}},
		EmptyConfigIfNil: true,
	}))
	_, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})
	if err == nil || !strings.Contains(err.Error(), "无效的证书任务状态") {
		t.Fatalf("err=%v, want 证书任务状态白名单拒绝", err)
	}
}
