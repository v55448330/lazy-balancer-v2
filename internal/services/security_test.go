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

	// Then：allow 放行集应包含 1.2.3.4（ACL 交集）和 5.6.7.8（P1 信任名单）
	// ——预检的 !@ipMatch 应仅拒绝不在 [1.2.3.4,5.6.7.8] 的 IP
	if !strings.Contains(directives, "!@ipMatch 1.2.3.4,5.6.7.8") {
		t.Fatalf("directives missing trust IP in allow set:\n%s", directives)
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
		{"blocking", "parked-enabled", false, true},
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
