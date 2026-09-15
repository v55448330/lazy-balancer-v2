package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 裁定 2026-09-07 S1/S2：多策略 IP 预检——① 信任名单并入 allow 放行集（信任
// 优先，与单策略语义一致）；② 交集改为 CIDR 感知（网络包含关系取更具体方）。
func TestIntersectIPLists_cidrAware(t *testing.T) {
	tests := []struct {
		name  string
		lists [][]string
		want  []string
	}{
		{
			name:  "identical strings still match",
			lists: [][]string{{"1.2.3.4", "5.6.7.8"}, {"1.2.3.4", "10.0.0.1"}},
			want:  []string{"1.2.3.4"},
		},
		{
			name:  "CIDR contains specific IP",
			lists: [][]string{{"10.0.0.0/8"}, {"10.1.0.5"}},
			want:  []string{"10.1.0.5"},
		},
		{
			name:  "specific IP inside CIDR",
			lists: [][]string{{"10.1.0.5"}, {"10.0.0.0/8"}},
			want:  []string{"10.1.0.5"},
		},
		{
			name:  "overlapping CIDRs → more specific",
			lists: [][]string{{"10.0.0.0/8"}, {"10.1.0.0/16"}},
			want:  []string{"10.1.0.0/16"},
		},
		{
			name:  "disjoint CIDRs → empty",
			lists: [][]string{{"10.0.0.0/8"}, {"192.168.0.0/16"}},
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intersectIPLists(tt.lists)
			if len(got) != len(tt.want) {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
			gotSet := make(map[string]bool, len(got))
			for _, e := range got {
				gotSet[e] = true
			}
			for _, w := range tt.want {
				if !gotSet[w] {
					t.Fatalf("got=%v missing %q", got, w)
				}
			}
		})
	}
}

func TestBuildIPPrecheck_trustListInclusion(t *testing.T) {
	// Given：P1 allow=[1.2.3.4] trust=[5.6.7.8]；P2 deny=[9.9.9.9]
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["5.6.7.8"]`)}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["9.9.9.9"]`}
	directives := buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2})

	// Then(2026-09-15 用户裁定,信任 DetectionOnly 取代并入放行集):
	trustRule := `SecRule REMOTE_ADDR "@ipMatch 5.6.7.8" "id:3,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(directives, trustRule) {
		t.Fatalf("directives missing trust DetectionOnly rule:\n%s", directives)
	}
	if strings.Contains(directives, "1.2.3.4,5.6.7.8") {
		t.Fatalf("trust must NOT be merged into allow set (merge = no detection event):\n%s", directives)
	}
	trustIdx := strings.Index(directives, trustRule)
	denyIdx := strings.Index(directives, `"@ipMatch 9.9.9.9" "id:2,phase:1,deny`)
	if trustIdx > denyIdx {
		t.Fatalf("trust DetectionOnly must precede deny rules:\n%s", directives)
	}
}

// 2026-09-08 审计 SF3：D3 门控关闭路径——IPWhitelistEnabled=false 的信任
// 名单不得并入多策略预检（与 BuildCorazaDirectives 信任三态口径一致）。
func TestBuildIPPrecheck_trustDisabledNotIncluded(t *testing.T) {
	// Given：P1 allow=[1.2.3.4] trust=[5.6.7.8] 但信任开关关闭；P2 deny=[9.9.9.9]
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`["5.6.7.8"]`)}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["9.9.9.9"]`}
	directives := buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2})

	// Then：allow 放行集应仅含 1.2.3.4（信任关闭→不并入）
	if strings.Contains(directives, "5.6.7.8") {
		t.Fatalf("directives contains disabled trust IP:\n%s", directives)
	}
	if !strings.Contains(directives, "1.2.3.4") {
		t.Fatalf("directives missing ACL allow IP:\n%s", directives)
	}
}

// 2026-09-08 审计 SF1：同基址不同掩码的方向独立性。
func TestCidrIntersectEntry_directionIndependent(t *testing.T) {
	// 同基址，/8 比 /16 宽——无论参数顺序，都应返回 /16（更窄）
	forward := cidrIntersectEntry("10.0.0.0/8", "10.0.0.0/16")
	backward := cidrIntersectEntry("10.0.0.0/16", "10.0.0.0/8")
	if forward != "10.0.0.0/16" || backward != "10.0.0.0/16" {
		t.Fatalf("forward=%q backward=%q, both want 10.0.0.0/16（更窄方）", forward, backward)
	}
}

// TestBuildCorazaDirectives_BodyAccessTruthTable(R-6 首例,SLB14-N1):
// 机械枚举 body 门控读取的全部变量交叉积——mode(4)×自定义规则态(3:
// 无规则/停放启用/发射启用)×IP 控制(2)。期望:On ⟺ crsActive ‖
// (customActive && hasCustomRules)。历史:R12 引擎不可消费条件→R13 停放
// 规则反向回归——每轮只测目标格,bug 在未测格;本表为构造性全形状。
func TestBuildCorazaDirectives_BodyAccessTruthTable(t *testing.T) {
	rulesJSON := func(enabled bool) json.RawMessage {
		state := "false"
		if enabled {
			state = "true"
		}
		return json.RawMessage(`[{"id":1,"name":"r","conditions":[{"target":"uri","operator":"starts_with","pattern":"/a"}],"action":"block","score":5,"enabled":` + state + `}]`)
	}
	cases := []struct {
		mode       string
		rulesState string // none | parked-enabled | emitted-enabled
		ipControl  bool
		wantBodyOn bool
	}{
		// crsActive(blocking/detection):恒 On(CRS phase:2 消费)
		{"blocking", "none", false, true},
		// parked 格仅对 off 有实义(非 off 模式 parked/emitted 同输入等价类,
		// SLB15-N1 去重)。
		{"blocking", "emitted-enabled", false, true},
		{"blocking", "none", true, true},
		{"detection", "none", false, true},
		{"detection", "emitted-enabled", false, true},
		// custom_only:仅启用规则存在时 On
		{"custom_only", "emitted-enabled", false, true},
		{"custom_only", "emitted-enabled", true, true},
		{"custom_only", "none", false, false}, // 空策略→default return ""
		{"custom_only", "none", true, false},  // 仅 IP 控制:phase:1,无 body 消费者
		// off:IP/GeoIP 仅 phase:1,停放规则不发射→Off(SLB14-N1 回归格)
		{"off", "none", true, false},
		{"off", "parked-enabled", true, false}, // ← R13 反向回归格:此前误 On
		{"off", "parked-enabled", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.mode+"/"+tc.rulesState+"/ip="+boolStr(tc.ipControl), func(t *testing.T) {
			p := &models.SecurityPolicy{Mode: tc.mode, Enabled: true}
			switch tc.rulesState {
			case "parked-enabled":
				p.CustomRules = rulesJSON(true)
			case "emitted-enabled":
				p.CustomRules = rulesJSON(true)
			}
			if tc.ipControl {
				p.IPACLEnabled = true
				p.IPACLMode = "deny"
				p.IPACLList = `["10.0.0.0/8"]`
			}
			directives := BuildCorazaDirectives(p, nil)
			if tc.mode == "custom_only" && tc.rulesState == "none" && !tc.ipControl {
				if directives != "" {
					t.Fatalf("空策略应产空串, got %q", directives)
				}
				return
			}
			gotOn := strings.Contains(directives, "SecRequestBodyAccess On")
			if gotOn != tc.wantBodyOn {
				t.Errorf("body access On=%v, want %v\ndirectives=%q", gotOn, tc.wantBodyOn, directives)
			}
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// SECLB32-1(第 32 轮审计,P1):多策略(预检存在)时策略层 id:2/4 改链式自排除
// 本策略信任集——本策略信任 IP 由预检统一记录(去重保持),他策略信任 IP 不在
// 本策略信任集照常拦截(「信任仅豁免所属策略」裁定边界恢复)。
func TestBuildCorazaDirectives_multiPolicyDenySelfTrustExclusion(t *testing.T) {
	// Given:多策略模式(flag=true)+deny 名单+本策略信任名单
	p := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := BuildCorazaDirectives(p, nil, "", true)
	// Then:id:2 以链式自排除形态存在(非抑制删除、非平原形态)
	if !strings.Contains(directives, "id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END,chain") {
		t.Fatalf("multi-policy deny must emit chain-starter id:2 with deny in head (SECLB33-1), got:\n%s", directives)
	}
	if !strings.Contains(directives, "!@ipMatch 10.0.0.1") {
		t.Fatalf("chained rule must exclude own trust list, got:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_multiPolicyDenyNoTrustPlain(t *testing.T) {
	// Given:多策略+deny 名单+信任关闭(无排除项→平原 id:2,形状不变)
	p := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`[]`)}
	// When
	directives := BuildCorazaDirectives(p, nil, "", true)
	// Then
	if !strings.Contains(directives, "id:2,phase:1,deny") {
		t.Fatalf("no-trust multi-policy must keep plain id:2 deny, got:\n%s", directives)
	}
	if strings.Contains(directives, ",chain\"") {
		t.Fatalf("no-trust policy must not emit chain, got:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_singlePolicyTrustNoChain(t *testing.T) {
	// Given:单策略(flag=false)+deny+信任(回归形状:同实例 DetectionOnly 已正确,无链)
	p := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := BuildCorazaDirectives(p, nil, "", false)
	// Then
	if !strings.Contains(directives, "id:2,phase:1,deny") {
		t.Fatalf("single policy must keep plain id:2 deny, got:\n%s", directives)
	}
	if strings.Contains(directives, ",chain\"") {
		t.Fatalf("single policy must not emit chain, got:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_multiPolicyBlacklistSelfTrustExclusion(t *testing.T) {
	// Given:多策略+旧版黑名单+本策略信任
	p := &models.SecurityPolicy{Mode: "blocking", IPBlacklist: json.RawMessage(`["198.51.100.9"]`), IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := BuildCorazaDirectives(p, nil, "", true)
	// Then:id:4 链式自排除
	if !strings.Contains(directives, "id:4,phase:1,deny,status:403,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END,chain") {
		t.Fatalf("multi-policy blacklist must emit chain-starter id:4 with deny in head (SECLB33-1), got:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_multiPolicyAllowSelfTrustExclusion(t *testing.T) {
	// Given:多策略+allow 模式+本策略信任(信任 IP 不在白名单时不拦,预检记录)
	p := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := BuildCorazaDirectives(p, nil, "", true)
	// Then:id:2 链式(!@ipMatch allow AND !@ipMatch trust → deny)
	if !strings.Contains(directives, "id:2,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END,chain") {
		t.Fatalf("multi-policy allow must emit chain-starter id:2 with deny in head (SECLB33-1), got:\n%s", directives)
	}
	if !strings.Contains(directives, "!@ipMatch 10.0.0.1") {
		t.Fatalf("allow chain must exclude own trust list, got:\n%s", directives)
	}
}
