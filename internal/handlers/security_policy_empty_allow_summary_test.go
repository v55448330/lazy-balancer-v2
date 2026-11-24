package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 策略摘要行必须带「空白名单」判定（acl_empty_allow）：ACL 开启、模式 allow、
// 生效条目（inline ∪ 引用列表条目）为零——这种策略经「绑定规则」挂到规则上
// 会让该规则拒绝所有请求。绑定编辑器两个宿主都没有
// 名单条目数据，判定只能在后端单源产出，供绑定入口与保存入口同口径确认。
func TestSecurityPolicyList_summaryFlagsEmptyAllowACL(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,category,entries,system) VALUES (901,'非空名单','custom','[{"value":"192.0.2.1"}]',0)`); err != nil {
		t.Fatalf("seed non-empty list: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,category,entries,system) VALUES (902,'空名单','custom','[]',0)`); err != nil {
		t.Fatalf("seed empty list: %v", err)
	}
	// aclEnabled 落 ip_acl_enabled 列；policyEnabled 落策略自身的 enabled 列——两者
	// 是不同的开关，夹具参数不得混用（否则用例名声称覆盖的形状其实没测到）。
	seed := func(name, aclMode string, aclEnabled, policyEnabled int, refs string) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO security_policies
			(name, mode, anomaly_threshold, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs,
			 ip_whitelist, ip_blacklist, crs_excluded_rules, custom_rules, enabled, policy_type)
			VALUES (?,'blocking',5,?,'[]',?,?,'[]','[]','[]','[]',?,'mixed')`,
			name, aclMode, aclEnabled, refs, policyEnabled); err != nil {
			t.Fatalf("seed policy %s: %v", name, err)
		}
	}
	seed("空内联无引用", "allow", 1, 1, "")
	seed("内联有条目", "allow", 1, 1, "")
	seed("deny 空集", "deny", 1, 1, "")
	seed("ACL 未启用", "allow", 0, 1, "")
	seed("引用非空名单", "allow", 1, 1, "[901]")
	seed("引用空名单", "allow", 1, 1, "[902]")
	seed("策略已禁用", "allow", 1, 0, "")
	if _, err := db.DB.Exec(`UPDATE security_policies SET ip_acl_list='["198.51.100.0/24"]' WHERE name='内联有条目'`); err != nil {
		t.Fatalf("set inline entry: %v", err)
	}

	recorder := getRequest(t, router, "/security/policies")
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data []struct {
			Name          string `json:"name"`
			ACLEmptyAllow bool   `json:"acl_empty_allow"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	got := map[string]bool{}
	for _, row := range resp.Data {
		got[row.Name] = row.ACLEmptyAllow
	}
	want := map[string]bool{
		"空内联无引用":  true,  // 目标形状：绑定即全拒
		"内联有条目":   false, // 回归形状：有条目不警示
		"deny 空集": false, // 畸形/相邻形状：deny 空集不命中任何请求，不是全拒
		"ACL 未启用": false, // 未启用不发射 ACL
		"引用非空名单":  false,
		"引用空名单":   true, // 引用名单无生效条目 = 全拒
		// 策略已禁用同样标记：绑定后再启用即全拒，宁可多一次确认（与策略保存
		// 入口的确认口径一致——那里也不看 enabled）。
		"策略已禁用": true,
	}
	if len(got) != len(want) {
		t.Fatalf("list rows=%d want %d: %s", len(got), len(want), recorder.Body.String())
	}
	for name, exp := range want {
		if got[name] != exp {
			t.Fatalf("policy %q acl_empty_allow=%v, want %v", name, got[name], exp)
		}
	}
}
