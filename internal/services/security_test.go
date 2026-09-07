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
