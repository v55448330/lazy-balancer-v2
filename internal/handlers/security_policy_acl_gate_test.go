package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 显式单职策略的阶段外 ACL 启用门（U8-2 后端半边）：显式 stage0/2/3 策略的
// ACL 已被 normalizeOutOfStageFields 归一归零，PUT 缺省类型提交
// {ip_acl_enabled:true} 绕过归一，更新后 G1 与原阶段特征并存→重推断把类型
// 改写 mixed（类型与内容漂移）。删除前守卫拒绝；stage1 是 ACL 所属阶段
// （归一保留 ACL 字段），启用属正常编辑不拦；mixed/空串存量兼容态不拦。
func TestUpdateSecurityPolicy_rejectsACLEnableOnTypedPolicy(t *testing.T) {
	aclEnable := map[string]any{
		"ip_acl_enabled": true,
		"ip_acl_mode":    "deny",
		"ip_acl_list":    `["203.0.113.0/24"]`,
	}

	t.Run("阶段外类型启用 ACL 拒绝", func(t *testing.T) {
		cases := []struct {
			name        string
			create      map[string]any
			wantSegment string
		}{
			{"stage2", map[string]any{"name": "rl-policy", "policy_type": "stage2", "rate_limit_enabled": true, "rate_limit_rps": 100, "rate_limit_burst": 50}, "阶段 2"},
			{"stage3", map[string]any{"name": "waf-policy", "policy_type": "stage3", "mode": "blocking"}, "阶段 3"},
			{"stage0", map[string]any{"name": "trust-policy", "policy_type": "stage0", "ip_whitelist_enabled": true, "ip_whitelist": `["10.0.0.1"]`}, "阶段 0"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// Given：显式单职策略（ACL 已被创建期归一归零）
				setupSecurityPolicyTestDB(t)
				router := newSecurityRouter(t)
				id := createTestPolicy(t, router, tc.create)

				// When：PUT 缺省 policy_type 携带 ACL 启用三件套
				rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), aclEnable)

				// Then：400，指引文案含自身阶段与「阶段 1」去向
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("PUT status=%d body=%s, want 400", rec.Code, rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), tc.wantSegment) {
					t.Fatalf("body=%s, want %s", rec.Body.String(), tc.wantSegment)
				}
				if !strings.Contains(rec.Body.String(), "阶段 1") {
					t.Fatalf("body=%s, want 阶段 1 guidance", rec.Body.String())
				}
				// 类型与 ACL 字段终态不被改写
				var ptype string
				var aclEnabled int
				if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,''), COALESCE(ip_acl_enabled,0) FROM security_policies WHERE id=?`, id).Scan(&ptype, &aclEnabled); err != nil {
					t.Fatal(err)
				}
				if ptype != tc.name || aclEnabled != 0 {
					t.Fatalf("after reject policy_type=%q acl=%d, want %s/0", ptype, aclEnabled, tc.name)
				}
			})
		}
	})

	t.Run("stage1 启用 ACL 属正常编辑放行", func(t *testing.T) {
		// Given：显式 stage1 策略
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		id := createTestPolicy(t, router, map[string]any{"name": "acl-policy", "policy_type": "stage1"})

		// When：PUT 启用 ACL 三件套
		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), aclEnable)

		// Then：200，类型保持 stage1、ACL 字段落库
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		var ptype, aclList string
		var aclEnabled int
		if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,''), COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_list,'[]') FROM security_policies WHERE id=?`, id).Scan(&ptype, &aclEnabled, &aclList); err != nil {
			t.Fatal(err)
		}
		if ptype != "stage1" || aclEnabled != 1 || aclList != `["203.0.113.0/24"]` {
			t.Fatalf("final policy_type=%q acl=%d list=%s, want stage1/1/list", ptype, aclEnabled, aclList)
		}
	})

	t.Run("指针语义 false 与 nil 均不拦", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			body map[string]any
		}{
			{"显式 false", map[string]any{"ip_acl_enabled": false}},
			{"缺省 nil", map[string]any{"name": "rename-only"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				setupSecurityPolicyTestDB(t)
				router := newSecurityRouter(t)
				id := createTestPolicy(t, router, map[string]any{"name": "rl-policy", "policy_type": "stage2", "rate_limit_enabled": true, "rate_limit_rps": 100, "rate_limit_burst": 50})

				rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), tc.body)

				if rec.Code != http.StatusOK {
					t.Fatalf("PUT status=%d body=%s, want 200", rec.Code, rec.Body.String())
				}
				var ptype string
				if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,'') FROM security_policies WHERE id=?`, id).Scan(&ptype); err != nil {
					t.Fatal(err)
				}
				if ptype != "stage2" {
					t.Fatalf("final policy_type=%q, want stage2", ptype)
				}
			})
		}
	})

	t.Run("存量兼容态 mixed 与空串不拦", func(t *testing.T) {
		cases := []struct {
			name      string
			seed      string
			wantType  string
			wantACLEn int
		}{
			{"mixed", `INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,policy_type) VALUES ('legacy-mix','blocking',0,'deny','[]','mixed')`, "mixed", 1},
			{"空串", `INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,policy_type) VALUES ('legacy-empty','off',0,'deny','[]','')`, "stage1", 1},
			// 边界：typed 策略存量 ACL 已启用（导入/旧快照残留态）——真值再提交
			// 为幂等操作，不拦（门只拦「从禁用→启用」的并存翻转）。终态类型由
			// 既有缺省重推断收敛为 mixed（该行本就 G1+G2 并存不一致，基线钉：
			// 存量残留态收敛语义非本门管辖，保持现状）。
			{"stage2 存量 ACL 已启用", `INSERT INTO security_policies (name,mode,rate_limit_enabled,rate_limit_rps,ip_acl_enabled,ip_acl_mode,ip_acl_list,policy_type) VALUES ('legacy-rl','off',1,100,1,'deny','["198.51.100.0/24"]','stage2')`, "mixed", 1},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				setupSecurityPolicyTestDB(t)
				router := newSecurityRouter(t)
				res, err := db.DB.Exec(tc.seed)
				if err != nil {
					t.Fatal(err)
				}
				id, err := res.LastInsertId()
				if err != nil {
					t.Fatal(err)
				}

				rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), aclEnable)

				if rec.Code != http.StatusOK {
					t.Fatalf("PUT status=%d body=%s, want 200", rec.Code, rec.Body.String())
				}
				var ptype string
				var aclEnabled int
				if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,''), COALESCE(ip_acl_enabled,0) FROM security_policies WHERE id=?`, id).Scan(&ptype, &aclEnabled); err != nil {
					t.Fatal(err)
				}
				if ptype != tc.wantType || aclEnabled != tc.wantACLEn {
					t.Fatalf("final policy_type=%q acl=%d, want %s/%d", ptype, aclEnabled, tc.wantType, tc.wantACLEn)
				}
			})
		}
	})
}
