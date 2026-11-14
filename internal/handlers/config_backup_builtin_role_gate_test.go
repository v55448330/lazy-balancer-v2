package handlers

// 备份导入「名单表被替换、策略表保持 live」组合的内置名单角色门：
// 初检 validateImportedSystemIPLists 只校验 system=1 行的名称白名单（允许
// id 与 live 策略引用撞号），锁内复核此前只查引用 id 存在性——备份行以
// system=1 顶替用户名单 id 后，live 策略的信任/放行引用落在内置名单上：
// 内置名单仅允许 IP ACL 黑名单（deny）引用（写侧 validateBuiltinIPListRefs
// 契约），信任名单/allow/CRS 排除作用域引用内置名单会让威胁/封禁 IP 获得
// 放行语义（黑名单语义反转）。与受信代理轴的内置门（revalidateImport-
// TrustedProxyRefs）同构：命中即拒，宁可要求同时携带策略表。

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// seedLivePolicyForBuiltinGate 直插一条 live 策略（引用面由调用方给定）。
func seedLivePolicyForBuiltinGate(t *testing.T, name string, columns map[string]any) {
	t.Helper()
	cols := []string{"id", "name", "mode", "enabled"}
	vals := []any{501, name, "blocking", 1}
	for col, val := range columns {
		cols = append(cols, col)
		vals = append(vals, val)
	}
	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = "?"
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (`+strings.Join(cols, ",")+`) VALUES (`+strings.Join(placeholders, ",")+`)`, vals...); err != nil {
		t.Fatalf("seed live policy %s: %v", name, err)
	}
}

// builtinGateBackup 构造「名单表随包替换（system=1 顶替 id 910）、策略表
// 缺席」的备份；system 参数控制顶替行角色（0=对照组用户名单）。
func builtinGateBackup(t *testing.T, system int) string {
	t.Helper()
	return buildBackup(t, backupFixtureOptions{
		FillAll: true,
		Omit:    map[string]struct{}{"security_policies": {}},
		Tables: map[string][]map[string]any{
			"security_ip_lists": {{
				"id": 910, "name": db.ThreatSystemLists()[0].Name, "system": system,
				"entries": `[{"value":"203.0.113.8","remark":""}]`,
			}},
		},
		EmptyConfigIfNil: true,
	})
}

// Given live 策略的三个引用面之一指向 id 910（当前为用户名单）。
// When 导入以 system=1 内置名单顶替同 id、策略表不随包。
// Then 三个面（信任名单 / ACL allow / CRS 排除 listRefs）都必须 400 拒绝，
// 点名策略与内置名单契约；拒绝路径零写入。
func TestImport_livePolicyRefsRejectBuiltinListSubstitution(t *testing.T) {
	cases := []struct {
		name    string
		columns map[string]any
		want    string
	}{
		{
			name:    "信任名单引用内置名单",
			columns: map[string]any{"ip_whitelist_refs": "[910]"},
			want:    "不能用于信任名单",
		},
		{
			name:    "ACL allow 引用内置名单",
			columns: map[string]any{"ip_acl_enabled": 1, "ip_acl_mode": "allow", "ip_acl_list_refs": "[910]"},
			want:    "仅允许用于 IP 访问控制的黑名单模式",
		},
		{
			name:    "CRS 排除 listRefs 引用内置名单",
			columns: map[string]any{"crs_excluded_rules": `[{"target":"942100","scope":"list","listRefs":[910]}]`},
			want:    "不能用于 CRS 排除",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedLivePolicyForBuiltinGate(t, "角色门策略", tc.columns)

			response := postBackupImport(t, h, builtinGateBackup(t, 1))

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400（内置名单顶替用户名单 id 必须拒绝）", response.Code, response.Body.String())
			}
			body := response.Body.String()
			if !strings.Contains(body, tc.want) || !strings.Contains(body, "角色门策略") {
				t.Fatalf("body=%s, want 点名策略与内置名单契约 %q", body, tc.want)
			}
			// 拒绝路径零写入：live 策略行保持原样。
			var count int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id=501`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("拒绝路径不得改写 live 策略，实际行数=%d", count)
			}
		})
	}
}

// 对照组（防过度拒绝）：同 id 顶替行 system=0（用户名单）时三个引用面放行
// ——角色门只拦内置名单，不改变既有「id 覆盖即放行」语义。
func TestImport_livePolicyRefsAllowUserListSubstitution(t *testing.T) {
	for _, tc := range []struct {
		name    string
		columns map[string]any
	}{
		{"信任名单", map[string]any{"ip_whitelist_refs": "[910]"}},
		{"ACL allow", map[string]any{"ip_acl_enabled": 1, "ip_acl_mode": "allow", "ip_acl_list_refs": "[910]"}},
		{"CRS 排除", map[string]any{"crs_excluded_rules": `[{"target":"942100","scope":"list","listRefs":[910]}]`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedLivePolicyForBuiltinGate(t, "用户名单策略", tc.columns)

			response := postBackupImport(t, h, builtinGateBackup(t, 0))

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200（system=0 顶替不触发角色门）", response.Code, response.Body.String())
			}
		})
	}
}

// 唯一合法用途回归：live 策略以 ACL deny 引用被顶替的内置名单必须继续放行
// （内置名单的黑名单语义正是设计用途，角色门不得误伤）。
func TestImport_livePolicyDenyRefToBuiltinListPasses(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLivePolicyForBuiltinGate(t, "黑名单策略", map[string]any{
		"ip_acl_enabled": 1, "ip_acl_mode": "deny", "ip_acl_list_refs": "[910]",
	})

	response := postBackupImport(t, h, builtinGateBackup(t, 1))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（ACL deny 是内置名单唯一合法引用面）", response.Code, response.Body.String())
	}
}

// 锁内直测：ACL 面按 live ip_acl_mode 分流——deny 放行、allow/绕过拒绝
// （谓词真值表：builtin × aclMode 交叉积的锁内轴）。
func TestRevalidateImportLivePolicyIPListRefs_aclModeGate(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		wantReject bool
	}{
		{"deny", false},
		{"allow", true},
		{"绕过", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			seedLivePolicyForBuiltinGate(t, "锁内策略", map[string]any{
				"ip_acl_enabled": 1, "ip_acl_mode": tc.mode, "ip_acl_list_refs": "[910]",
			})
			backup := &configBackup{Tables: map[string][]map[string]any{
				"security_ip_lists": {{
					"id": 910, "name": db.ThreatSystemLists()[0].Name, "system": 1,
					"entries": `[{"value":"203.0.113.8","remark":""}]`,
				}},
			}}
			tx, err := db.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()

			err = revalidateImportLivePolicyIPListRefs(t.Context(), tx, backup)

			if tc.wantReject {
				if err == nil || !strings.Contains(err.Error(), "仅允许用于 IP 访问控制的黑名单模式") {
					t.Fatalf("mode=%s 必须拒绝内置名单 ACL 引用: %v", tc.mode, err)
				}
			} else if err != nil {
				t.Fatalf("mode=deny 必须放行: %v", err)
			}
		})
	}
}

// 锁内直测：备份未携带名单表时包装器不得进入复核（缺席=保留本地，角色门
// 只在「名单表被替换」组合生效——与受信代理轴的表携带判据同构）。
func TestRevalidateImportLiveDependencies_absentListsSkipsPolicyGate(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	seedLivePolicyForBuiltinGate(t, "缺席策略", map[string]any{"ip_whitelist_refs": "[910]"})
	backup := &configBackup{Tables: map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_1", "domain": "a.example", "listen_port": 80}},
	}}
	tx, err := db.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := revalidateImportLiveDependencies(t.Context(), tx, backup, map[string]bool{}); err != nil {
		t.Fatalf("名单表未随包携带时不得复核 live 引用: %v", err)
	}
}
