package db

import (
	"strings"
	"testing"
)

// 阶段合并迁移 v1 的升级起点契约（2026-11-13 用户报障「升级后 WAF 策略丢失」）：
// v2.4.3 及更早的正式库里 stage3 = WAF（五阶段 stage4 中间态从未发布，全 git
// 历史无 stage3→stage4 数据迁移）。v1 迁移曾把全部 stage3 无条件当人机：
// 配对合并删 WAF 绑定/行、剩余整体改型 stage2——本文件钉住修正后的行为。
//
// 判据（与 models.PolicyTypeFeatures 同口径，迁移期不反向依赖 handlers）：
//   - 人机特征 = human_verify_mode != 'off' OR cc_detect_enabled = 1
//   - WAF 特征 = mode ∈ blocking/detection/custom_only OR custom_rules 引用非空

// seedStageMergeBase 建迁移基线库并清空调试缓冲外的系统审计残留。
func seedStageMergeBase(t *testing.T) {
	t.Helper()
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := ensureNewColumns(newColumnsRegistry, nil); err != nil {
		t.Fatalf("ensure new columns: %v", err)
	}
	drainSystemAuditBuffer()
}

// Given v2.4.3 真实形态：stage2=旧限流、stage3=WAF（无 stage4、无人机特征）。
// When 跑全量迁移。Then WAF 行保持 stage3、字段与绑定零改写。
func TestMigratePolicyStagesV1_keepsV243WafPolicies(t *testing.T) {
	seedStageMergeBase(t)
	if _, err := DB.Exec(`INSERT INTO security_policies
		(id,name,mode,policy_type,crs_rule_groups,custom_rules,human_verify_mode,enabled)
		VALUES
		(20,'旧限流','off','stage2','[]','[]','off',1),
		(21,'WAF-主','blocking','stage3','["42"]','[7]','off',1),
		(22,'WAF-检测','detection','stage3','["43"]','[]','off',1),
		(23,'WAF-仅自定义','custom_only','stage3','[]','[8]','off',1)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	// 20+21 同规则绑定（v1 旧判据的配对合并形态）；22/23 各自独立规则。
	if _, err := DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES
		('rule-x',20,1),('rule-x',21,2),('rule-y',22,1),('rule-z',23,1)`); err != nil {
		t.Fatalf("seed bindings: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	for _, id := range []int{21, 22, 23} {
		var typ, mode, crs, custom string
		if err := DB.QueryRow(`SELECT policy_type, mode, crs_rule_groups, custom_rules FROM security_policies WHERE id=?`, id).
			Scan(&typ, &mode, &crs, &custom); err != nil {
			t.Fatalf("WAF 策略 %d 应仍存在: %v", id, err)
		}
		if typ != "stage3" {
			t.Fatalf("WAF 策略 %d 被改型为 %s（升级后 WAF 丢失根因）", id, typ)
		}
		if mode == "off" || crs == "[]" && custom == "[]" {
			t.Fatalf("WAF 策略 %d 字段被清零: mode=%s crs=%s custom=%s", id, mode, crs, custom)
		}
	}
	var n int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='rule-x'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("rule-x 绑定=%d, want 2（WAF 绑定不得被合并删除）", n)
	}
}

// Given 五阶段中间态（仅 dev 库可达）：stage3=人机、stage4=WAF。
// When 跑全量迁移。Then 原合并语义保持：人机并入 CC、WAF 重编号。
func TestMigratePolicyStagesV1_fiveStageDevShapeStillMerges(t *testing.T) {
	seedStageMergeBase(t)
	if _, err := DB.Exec(`INSERT INTO security_policies
		(id,name,mode,policy_type,human_verify_mode,cc_detect_enabled,cc_rps_limit,enabled)
		VALUES
		(30,'CC-A','off','stage2','off',0,40,1),
		(31,'人机A','off','stage3','force',1,99,1),
		(32,'WAF-C','blocking','stage4','off',0,40,1)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES
		('rule-a',30,1),('rule-a',31,2),('rule-c',32,1)`); err != nil {
		t.Fatalf("seed bindings: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	var typ, humanMode string
	var ccLimit int
	if err := DB.QueryRow(`SELECT p.policy_type, p.human_verify_mode, p.cc_rps_limit
		FROM security_policies p JOIN security_policy_bindings b ON b.policy_id=p.id WHERE b.rule_caddy_id='rule-a'`).
		Scan(&typ, &humanMode, &ccLimit); err != nil {
		t.Fatal(err)
	}
	if typ != "stage2" || humanMode != "force" || ccLimit != 99 {
		t.Fatalf("合并结果 type=%s human=%s cc=%d，want stage2/force/99", typ, humanMode, ccLimit)
	}
	if err := DB.QueryRow(`SELECT policy_type FROM security_policies WHERE id=32`).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	if typ != "stage3" {
		t.Fatalf("旧 WAF(stage4) 重编号=%s, want stage3", typ)
	}
}

// Given 已受 v1 旧判据损伤的库（v1 门已置位）：
//   - 40：WAF 被改型 stage2（字段完好）→ 应还原 stage3
//   - 41：真 CC（human 开启）→ 不动
//   - 42：WAF+human 混合被改型 stage2 → 不动（mixed 语义，留人工拆分）
//   - 43：空壳 stage2（旧限流退役后零能力）→ 不动
//
// When 跑全量迁移。Then 仅 40 还原，且逐条审计留痕；重跑零改写。
func TestRepairPolicyStageMergeV2_restoresRetypedWafOnly(t *testing.T) {
	seedStageMergeBase(t)
	if _, err := DB.Exec(`INSERT INTO security_policies
		(id,name,mode,policy_type,crs_rule_groups,custom_rules,human_verify_mode,cc_detect_enabled,enabled)
		VALUES
		(40,'受害WAF','blocking','stage2','["42"]','[7]','off',0,1),
		(41,'真CC','off','stage2','[]','[]','force',1,1),
		(42,'混合受害','blocking','stage2','["42"]','[]','force',0,1),
		(43,'空壳限流','off','stage2','[]','[]','off',0,1)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	// v1 门已置位（受损库形态）；v2 门未置位。
	if _, err := DB.Exec(`UPDATE global_config SET policy_stage_merge_v1=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	drainSystemAuditBuffer()

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	want := map[int]string{40: "stage3", 41: "stage2", 42: "stage2", 43: "stage2"}
	for id, wantType := range want {
		var got string
		if err := DB.QueryRow(`SELECT policy_type FROM security_policies WHERE id=?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != wantType {
			t.Fatalf("策略 %d type=%s, want %s", id, got, wantType)
		}
	}
	// 还原行的 WAF 字段零改写
	var mode, crs, custom string
	if err := DB.QueryRow(`SELECT mode, crs_rule_groups, custom_rules FROM security_policies WHERE id=40`).Scan(&mode, &crs, &custom); err != nil {
		t.Fatal(err)
	}
	if mode != "blocking" || crs != `["42"]` || custom != "[7]" {
		t.Fatalf("还原行字段被改写: mode=%s crs=%s custom=%s", mode, crs, custom)
	}
	// 逐条审计：恰一条，点名策略 40
	entries := drainSystemAuditBuffer()
	var repairAudits []string
	for _, e := range entries {
		if strings.Contains(e.detail, "阶段合并修复") {
			repairAudits = append(repairAudits, e.detail)
		}
	}
	if len(repairAudits) != 1 || !strings.Contains(repairAudits[0], "#40") {
		t.Fatalf("修复审计=%v, want 恰一条且点名 #40", repairAudits)
	}

	// 幂等：重跑零改写、零新审计
	if err := runMigrations(); err != nil {
		t.Fatalf("re-run migrations: %v", err)
	}
	var got string
	if err := DB.QueryRow(`SELECT policy_type FROM security_policies WHERE id=40`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "stage3" {
		t.Fatalf("重跑后 type=%s, want stage3", got)
	}
	for _, e := range drainSystemAuditBuffer() {
		if strings.Contains(e.detail, "阶段合并修复") {
			t.Fatalf("重跑产生重复修复审计: %s", e.detail)
		}
	}
}

// Given 全新库（v1/v2 门都未置位）。When 跑迁移。Then v2 门随 v1 一并置位，
// 且 v2 对空库零改写（首装用户不产生修复审计）。
func TestRepairPolicyStageMergeV2_freshInstallSetsGateSilently(t *testing.T) {
	seedStageMergeBase(t)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	var v1, v2 bool
	if err := DB.QueryRow(`SELECT COALESCE(policy_stage_merge_v1,0), COALESCE(policy_stage_merge_v2,0) FROM global_config WHERE id=1`).Scan(&v1, &v2); err != nil {
		t.Fatal(err)
	}
	if !v1 || !v2 {
		t.Fatalf("首装门状态 v1=%v v2=%v, want true/true", v1, v2)
	}
	for _, e := range drainSystemAuditBuffer() {
		if strings.Contains(e.detail, "阶段合并修复") {
			t.Fatalf("首装不应产生修复审计: %s", e.detail)
		}
	}
}
