package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 判重键必须按地址语义归一：同一个后端的等价写法（IPv6 压缩/展开、IPv4-mapped、
// 主机名大小写/首尾空白）落库两次会让权重翻倍、健康检查对同一地址跑两遍，
// 且一个后端被判不健康时健康视图与流量分配自相矛盾。
func TestUpstreamDedupeHost_normalizesAddressSemantics(t *testing.T) {
	same := [][]string{
		{"2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:DB8::1", "2001:db8:0:0::0:1"},
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"backend.example.com", " BACKEND.example.com ", "backend.Example.COM"},
	}
	for _, group := range same {
		first := upstreamDedupeHost(group[0])
		for _, host := range group[1:] {
			if got := upstreamDedupeHost(host); got != first {
				t.Fatalf("upstreamDedupeHost(%q)=%q, want %q（与 %q 是同一后端）", host, got, first, group[0])
			}
		}
	}
	// 反向：不同地址/主机名不得归并。
	if upstreamDedupeHost("2001:db8::1") == upstreamDedupeHost("2001:db8::2") {
		t.Fatal("不同 IPv6 地址被归并为同一后端")
	}
	if upstreamDedupeHost("10.0.0.1") == upstreamDedupeHost("10.0.0.2") {
		t.Fatal("不同 IPv4 地址被归并为同一后端")
	}
	if upstreamDedupeHost("a.example.com") == upstreamDedupeHost("b.example.com") {
		t.Fatal("不同主机名被归并为同一后端")
	}
}

// 等价 IPv6 写法同端口 → 保存门点名重复（错误文案回显规范化后的地址）。
func TestValidateRuleUpstreams_rejectsEquivalentIPv6Spellings(t *testing.T) {
	upstreams := []models.Upstream{
		{Host: "2001:db8::80", Port: 8080, Weight: 1, Enabled: true},
		{Host: "2001:0db8:0:0:0:0:0:80", Port: 8080, Weight: 1, Enabled: true},
	}
	_, err := validateRuleUpstreams("http", false, upstreams, true)
	if err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("等价 IPv6 写法必须判重, err=%v", err)
	}
	if !strings.Contains(err.Error(), "2001:db8::80") {
		t.Fatalf("err=%v, want 回显规范化后的地址", err)
	}
}

// 方括号 IPv6 与写侧形状门同口径：isValidHost 拒绝 '['，判重不得先剥成裸
// 地址制造「可接受」假象（否则渲染 JoinHostPort 会二次加括号成 [[::1]]）。
func TestUpstreamDedupeHost_keepsBracketedIPv6ForShapeGate(t *testing.T) {
	const bracketed = "[::1]"
	if got := upstreamDedupeHost(bracketed); got != bracketed {
		t.Fatalf("upstreamDedupeHost(%q)=%q, want 原样保留（方括号由形状门拒绝）", bracketed, got)
	}
	if isValidHost(bracketed) {
		t.Fatalf("isValidHost(%q)=true, want false（写侧必须拒绝方括号形态）", bracketed)
	}
	upstreams := []models.Upstream{{Host: bracketed, Port: 8080, Weight: 1, Enabled: true}}
	_, err := validateRuleUpstreams("http", false, upstreams, true)
	if err == nil || !strings.Contains(err.Error(), "主机") {
		t.Fatalf("方括号 IPv6 必须被写侧形状门拒绝, err=%v", err)
	}
}

// IPv4-mapped 与纯 IPv4 视为同一后端（同一个接口地址）。
func TestValidateRuleUpstreams_rejectsIPv4MappedDuplicate(t *testing.T) {
	upstreams := []models.Upstream{
		{Host: "10.0.0.5", Port: 8080, Weight: 1, Enabled: true},
		{Host: "::ffff:10.0.0.5", Port: 8080, Weight: 1, Enabled: true},
	}
	if _, err := validateRuleUpstreams("http", false, upstreams, true); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("IPv4-mapped 等价形态必须判重, err=%v", err)
	}
}

// 回归形状：不同端口、不同地址、主机名大小写判重仍按原语义，合法组合不误伤。
func TestValidateRuleUpstreams_keepsDistinctUpstreamsValid(t *testing.T) {
	cases := []struct {
		name    string
		hosts   []string
		ports   []int
		wantErr bool
	}{
		{"同地址不同端口", []string{"10.0.0.1", "10.0.0.1"}, []int{8080, 8081}, false},
		{"不同地址同端口", []string{"10.0.0.1", "10.0.0.2"}, []int{8080, 8080}, false},
		{"主机名大小写等价", []string{"Backend.example.com", "backend.example.com"}, []int{8080, 8080}, true},
		{"IPv6 与 IPv4 不同后端", []string{"2001:db8::1", "10.0.0.1"}, []int{8080, 8080}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreams := make([]models.Upstream, 0, len(tc.hosts))
			for i, host := range tc.hosts {
				upstreams = append(upstreams, models.Upstream{Host: host, Port: tc.ports[i], Weight: 1, Enabled: true})
			}
			_, err := validateRuleUpstreams("http", false, upstreams, true)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "重复") {
					t.Fatalf("want 重复错误, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("合法组合被拒: %v", err)
			}
		})
	}
}

// 路径规则自定义上游池与主池同口径（同族路径收敛：等价 IPv6 写法同样判重）。
func TestValidateRuleFeatures_rejectsEquivalentIPv6PathUpstreams(t *testing.T) {
	input := ruleFeatureInput{
		Protocol:            "http",
		CustomRoutesEnabled: true,
		PathRules: []models.PathRule{{
			MatchType: "prefix", Path: "/api/",
			Upstreams: []models.PathRuleUpstream{
				{Address: "2001:db8::9", Port: 9100, Weight: 1},
				{Address: "2001:0db8:0:0:0:0:0:9", Port: 9100, Weight: 1},
			},
		}},
	}
	err := validateRuleFeatures(input)
	if err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("路径规则等价 IPv6 写法必须判重, err=%v", err)
	}
	// 与主池同口径（handlers.go「上游 %s 重复」）：回显去重键而非裸地址+端口，
	// 否则 IPv6 等价写法会打印成 "2001:0db8:...:9100" 无括号裸串，端口歧义。
	if !strings.Contains(err.Error(), "[2001:db8::9]:9100") {
		t.Fatalf("路径规则判重文案必须回显去重键 [2001:db8::9]:9100, got %q", err.Error())
	}
}
