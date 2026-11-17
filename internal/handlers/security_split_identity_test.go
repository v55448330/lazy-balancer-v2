package handlers

// 拆分重试的子策略身份比较必须覆盖 insertChild 写入的全部业务列
// （securityPolicyInsertColumns，仅豁免操作者痕迹 updated_by）——身份结构
// 漏列时，管理员改动过的同名子策略会被重试拆分静默复用（违「同名不同配置
// 409 冲突」契约）。本文件以真实往返钉住 CC/人机十字段的冲突判定，并把
// 「身份字段集 = insert 列清单」变成反射派生的机械护栏。

import (
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// TestSplitSecurityPolicy_retryConflictsOnEditedStage2CCConfig：首轮拆分后
// 管理员修改 stage2 子策略的 CC 阈值，重试拆分必须 409 冲突（不得静默复用
// 改过的子策略），原策略与全部子策略行原样保留。
func TestSplitSecurityPolicy_retryConflictsOnEditedStage2CCConfig(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	mixedID := seedSplitFixture(t)
	// lb_s1 再绑 9 条其他策略（含原混合共 10 条）→ 首轮 10+3=13 超上限被跳过，
	// 原策略保留（可重试形态）。
	for i := range 9 {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES (?, 'off', 'stage3', 1)`, "cc-retry-other-"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		oid, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_s1',?)`, oid); err != nil {
			t.Fatal(err)
		}
	}

	first := postSplit(t, router, mixedID)
	if first.Code != http.StatusOK {
		t.Fatalf("first split status=%d body=%s, want 200", first.Code, first.Body.String())
	}
	var stage2ID int
	if err := db.DB.QueryRow(`SELECT id FROM security_policies WHERE name='legacy-mix（阶段 2）'`).Scan(&stage2ID); err != nil {
		t.Fatalf("stage2 child not created: %v", err)
	}

	// 管理员修改 stage2 子策略的 CC 突刺阈值（40→99）。
	if _, err := db.DB.Exec(`UPDATE security_policies SET cc_rps_limit=99 WHERE id=?`, stage2ID); err != nil {
		t.Fatal(err)
	}

	second := postSplit(t, router, mixedID)
	if second.Code != http.StatusConflict {
		t.Fatalf("retry status=%d body=%s, want 409（stage2 CC 配置已改，不得静默复用）", second.Code, second.Body.String())
	}
	// 冲突在任何插入之前判定：无新建子策略、原策略保留、改过的值不被覆盖。
	var ccRPS, stage2Count, originalAlive int
	if err := db.DB.QueryRow(`SELECT COALESCE(cc_rps_limit,0) FROM security_policies WHERE id=?`, stage2ID).Scan(&ccRPS); err != nil {
		t.Fatal(err)
	}
	if ccRPS != 99 {
		t.Fatalf("stage2 cc_rps_limit=%d, want 99（冲突不得改动既有子策略）", ccRPS)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE name='legacy-mix（阶段 2）'`).Scan(&stage2Count); err != nil {
		t.Fatal(err)
	}
	if stage2Count != 1 {
		t.Fatalf("stage2 同名行=%d, want 1（不得新建）", stage2Count)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id=?`, mixedID).Scan(&originalAlive); err != nil {
		t.Fatal(err)
	}
	if originalAlive != 1 {
		t.Fatal("冲突不得删除原混合策略")
	}
}

// TestSplitSecurityPolicy_retryConflictsOnEditedStage2HumanConfig：人机验证
// 四列同属身份比较集——改 stage2 子策略的人机模式同样必须 409。
func TestSplitSecurityPolicy_retryConflictsOnEditedStage2HumanConfig(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	mixedID := seedSplitFixture(t)
	for i := range 9 {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES (?, 'off', 'stage3', 1)`, "human-retry-other-"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		oid, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_s1',?)`, oid); err != nil {
			t.Fatal(err)
		}
	}
	first := postSplit(t, router, mixedID)
	if first.Code != http.StatusOK {
		t.Fatalf("first split status=%d body=%s, want 200", first.Code, first.Body.String())
	}
	if _, err := db.DB.Exec(`UPDATE security_policies SET human_verify_mode='off' WHERE name='legacy-mix（阶段 2）'`); err != nil {
		t.Fatal(err)
	}
	second := postSplit(t, router, mixedID)
	if second.Code != http.StatusConflict {
		t.Fatalf("retry status=%d body=%s, want 409（stage2 人机配置已改，不得静默复用）", second.Code, second.Body.String())
	}
}

// TestSplitChildIdentity_coversInsertColumns：身份字段集必须与 insert 列清单
// 机械对齐（column↔field 映射为唯一手写处；新增 insert 列未登记映射即红，
// 身份结构漏字段即红）——「身份比较覆盖 insertChild 全部业务列」的守卫。
func TestSplitChildIdentity_coversInsertColumns(t *testing.T) {
	if gaps := splitChildIdentityParityGaps(securityPolicyInsertColumns, reflect.TypeOf(splitChildIdentity{})); len(gaps) != 0 {
		t.Fatalf("子策略身份列集断言失败: %v", gaps)
	}
}
