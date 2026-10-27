package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 裁定 2026-09-07：多策略 IP 预检——① 信任名单并入 allow 放行集（信任
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
	// Given： allow=[1.2.3.4] trust=[5.6.7.8]； deny=[9.9.9.9]
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["5.6.7.8"]`)}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["9.9.9.9"]`}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, 0, "lb_test"))

	// Then(2026-09-15 用户裁定,信任 DetectionOnly 取代并入放行集):
	trustRule := `"id:3,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(directives, trustRule) || !strings.Contains(directives, "@ipListFast ") {
		t.Fatalf("directives missing trust DetectionOnly rule:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "u-trust"); got != "5.6.7.8/32\n" {
		t.Fatalf("信任并集文件=%q, want 仅 5.6.7.8/32", got)
	}
	// 信任不并入 allow 放行集（并入=信任 IP 不触发规则=无检测事件）
	if got := readRenderedIPList(t, directives, "u-allow"); strings.Contains(got, "5.6.7.8") {
		t.Fatalf("trust must NOT be merged into allow set: %q", got)
	}
	trustIdx := strings.Index(directives, trustRule)
	denyIdx := strings.Index(directives, `"id:2,phase:1,deny`)
	if trustIdx > denyIdx {
		t.Fatalf("trust DetectionOnly must precede deny rules:\n%s", directives)
	}
}

// 2026-09-08 审计 SF3：门控关闭路径——IPWhitelistEnabled=false 的信任
// 名单不得并入多策略预检（与 BuildCorazaDirectives 信任三态口径一致）。
func TestBuildIPPrecheck_trustDisabledNotIncluded(t *testing.T) {
	// Given： allow=[1.2.3.4] trust=[5.6.7.8] 但信任开关关闭； deny=[9.9.9.9]
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`["5.6.7.8"]`)}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["9.9.9.9"]`}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, 0, "lb_test"))

	// Then：allow 放行集应仅含 1.2.3.4（信任关闭→不并入）；
	// 信任并集规则整体不发射（含信任 IP 的文件不应存在引用）。
	if strings.Contains(directives, "id:3,") {
		t.Fatalf("trust switch rule must not be emitted when trust disabled:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "u-allow"); got != "1.2.3.4/32\n" {
		t.Fatalf("allow 放行集文件=%q, want 仅 1.2.3.4/32", got)
	}
}

// 2026-09-08 审计 SF1：同基址不同掩码的方向独立性。
// 语义钉迁移到生产唯一实现 cidrIntersectParsed（经
// parseEntryCached 构造条目，镜像 intersectIPLists 调用形态）——旧
// cidrIntersectEntry 自预解析缓存改造后生产零调用，已删除。
func TestCidrIntersectParsed_directionIndependent(t *testing.T) {
	// 同基址，/8 比 /16 宽——无论参数顺序，都应返回 /16（更窄）
	cache := map[string]*parsedEntry{}
	forward := cidrIntersectParsed(parseEntryCached("10.0.0.0/8", cache), parseEntryCached("10.0.0.0/16", cache))
	backward := cidrIntersectParsed(parseEntryCached("10.0.0.0/16", cache), parseEntryCached("10.0.0.0/8", cache))
	if forward != "10.0.0.0/16" || backward != "10.0.0.0/16" {
		t.Fatalf("forward=%q backward=%q, both want 10.0.0.0/16（更窄方）", forward, backward)
	}
}

// TestBuildCorazaDirectives_BodyAccessTruthTable
// 机械枚举 body 门控读取的全部变量交叉积——mode(4)×自定义规则态(3:
// 无规则/停放启用/发射启用)×IP 控制(2)。期望:On ⟺ crsActive ‖
// (customActive && hasCustomRules)。历史: 引擎不可消费条件→ 停放
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
		// 故该格去重)。
		{"blocking", "emitted-enabled", false, true},
		{"blocking", "none", true, true},
		{"detection", "none", false, true},
		{"detection", "emitted-enabled", false, true},
		// custom_only:仅启用规则存在时 On
		{"custom_only", "emitted-enabled", false, true},
		{"custom_only", "emitted-enabled", true, true},
		{"custom_only", "none", false, false}, // 空策略→default return ""
		{"custom_only", "none", true, false},  // 仅 IP 控制:phase:1,无 body 消费者
		// off:IP/GeoIP 仅 phase:1,停放规则不发射→Off
		{"off", "none", true, false},
		{"off", "parked-enabled", true, false}, // ← 反向回归格:此前误 On
		{"off", "parked-enabled", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.mode+"/"+tc.rulesState+"/ip="+boolStr(tc.ipControl), func(t *testing.T) {
			p := &models.SecurityPolicy{Mode: tc.mode, Enabled: true}
			// 批 3：blocking/detection 消费 anomaly_threshold（类型①值型列）——
			// 表内 CRS-active 模式给合法值 5。custom_only 在存在启用规则时同样
			// 消费它（body processor 守卫 id:11 计分=fail-visible 门，见
			// emitBodyProcessorRules），故该格也按真实库形态给 5；off 不发射。
			if tc.mode == "blocking" || tc.mode == "detection" || (tc.mode == "custom_only" && tc.rulesState != "none") {
				p.AnomalyThreshold = 5
			}
			if tc.rulesState != "none" {
				// parked-enabled 与 emitted-enabled 对本谓词是同一输入等价类
				//（只有「无自定义规则」/「有启用规则」两态）——单一分支。
				p.CustomRules = rulesJSON(true)
			}
			if tc.ipControl {
				p.IPACLEnabled = true
				p.IPACLMode = "deny"
				p.IPACLList = `["10.0.0.0/8"]`
			}
			directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
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

// TestBuildCorazaDirectives_customOnlyIPControlSkipsBodyProcessors
// custom_only+仅 IP 控制（零启用自定义规则）形状下
// SecRequestBodyAccess 恒 Off（BodyAccessTruthTable 该格已钉），body
// processor 激活规则 id:9/10/11 无任何消费者——不得发射（死指令）。
// 对照格：custom_only+启用自定义规则时 id:9/10/11 必须在场（body 条件规则
// 依赖解析）。
func TestBuildCorazaDirectives_customOnlyIPControlSkipsBodyProcessors(t *testing.T) {
	// Given：custom_only + 仅 IP 控制（无自定义规则）
	ipOnly := &models.SecurityPolicy{Mode: "custom_only", Enabled: true,
		IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["10.0.0.0/8"]`}
	// When
	directives := mustDirectives(BuildCorazaDirectives(ipOnly, nil, "", false, 0, "lb_test"))
	// Then：引擎为 IP 控制开启但 body access Off，id:9/10/11 三条死指令缺席
	if !strings.Contains(directives, "SecRuleEngine On") {
		t.Fatalf("IP 控制形状引擎必须 On:\n%s", directives)
	}
	if !strings.Contains(directives, "SecRequestBodyAccess Off") {
		t.Fatalf("零 body 消费者形状 body access 必须 Off:\n%s", directives)
	}
	for _, id := range []string{"id:9,", "id:10,", "id:11,"} {
		if strings.Contains(directives, id) {
			t.Errorf("custom_only+仅 IP 控制不得发射 body processor 死指令 %s:\n%s", id, directives)
		}
	}
	// 对照格：custom_only+启用自定义规则 → id:9/10/11 在场（body 条件规则依赖）
	withRules := &models.SecurityPolicy{Mode: "custom_only", Enabled: true,
		// 启用规则会发射 body processor 守卫（id:11 计分=anomaly_threshold），
		// 按真实库形态给合法值 5。
		AnomalyThreshold: 5,
		CustomRules:      json.RawMessage(`[{"id":1,"name":"r","conditions":[{"target":"uri","operator":"starts_with","pattern":"/a"}],"action":"block","score":5,"enabled":true}]`)}
	directives2 := mustDirectives(BuildCorazaDirectives(withRules, nil, "", false, 0, "lb_test"))
	for _, id := range []string{"id:9,", "id:10,", "id:11,"} {
		if !strings.Contains(directives2, id) {
			t.Errorf("custom_only+启用自定义规则必须发射 body processor 规则 %s:\n%s", id, directives2)
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// 多策略(预检存在)时策略层 id:2/4 改链式自排除
// 本策略信任集——本策略信任 IP 由预检统一记录(去重保持),他策略信任 IP 不在
// 本策略信任集照常拦截(「信任仅豁免所属策略」裁定边界恢复)。
func TestBuildCorazaDirectives_multiPolicyDenySelfTrustExclusion(t *testing.T) {
	// Given:多策略模式(flag=true)+deny 名单+本策略信任名单
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", true, 0, "lb_test"))
	// Then:id:2 以链式自排除形态存在(非抑制删除、非平原形态)
	if !strings.Contains(directives, "id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END,chain") {
		t.Fatalf("multi-policy deny must emit chain-starter id:2 with deny in head, got:\n%s", directives)
	}
	// 链续段信任集经 @ipListFast 文件投影（p0-trust scope，内容=本策略信任名单）
	if !strings.Contains(directives, "!@ipListFast ") {
		t.Fatalf("chained rule must exclude own trust list via file operand, got:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives[strings.Index(directives, "!@ipListFast "):], "-trust"); got != "10.0.0.1/32\n" {
		t.Fatalf("信任排除文件=%q, want 仅 10.0.0.1/32", got)
	}
}

func TestBuildCorazaDirectives_multiPolicyDenyNoTrustPlain(t *testing.T) {
	// Given:多策略+deny 名单+信任关闭(无排除项→平原 id:2,形状不变)
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`[]`)}
	// When
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", true, 0, "lb_test"))
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
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
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
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPBlacklist: json.RawMessage(`["198.51.100.9"]`), IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", true, 0, "lb_test"))
	// Then:id:4 链式自排除
	if !strings.Contains(directives, "id:4,phase:1,deny,status:403,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END,chain") {
		t.Fatalf("multi-policy blacklist must emit chain-starter id:4 with deny in head, got:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_multiPolicyAllowSelfTrustExclusion(t *testing.T) {
	// Given:多策略+allow 模式+本策略信任(信任 IP 不在白名单时不拦,预检记录)
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
	// When
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", true, 0, "lb_test"))
	// Then:id:2 链式(!@ipListFast allow AND !@ipListFast trust → deny)
	if !strings.Contains(directives, "id:2,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END,chain") {
		t.Fatalf("multi-policy allow must emit chain-starter id:2 with deny in head, got:\n%s", directives)
	}
	if !strings.Contains(directives, "!@ipListFast ") {
		t.Fatalf("allow chain must exclude own trust list via file operand, got:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives[strings.Index(directives, "!@ipListFast "):], "-trust"); got != "10.0.0.1/32\n" {
		t.Fatalf("信任排除文件=%q, want 仅 10.0.0.1/32", got)
	}
}

// a==b 字面捷径不得免检——两条 allow 名单含同一坏
// 条目（集群同步/带外改库可注入，保存面校验不覆盖存量行）时，交集被坏条目
// 顶成非空，恒拒规则（id:7 @rx .*）不发射、改发含坏行投影 → @ipListFast
// 构建期 fail-closed 整份渲染失败。与聚合面「不可解析不参与匹配」同口径：
// 非法元素返回 ""（不参与交集）。
func TestCidrIntersectParsed_equalButInvalidDropped(t *testing.T) {
	cache := map[string]*parsedEntry{}
	if got := cidrIntersectParsed(parseEntryCached("not-an-ip", cache), parseEntryCached("not-an-ip", cache)); got != "" {
		t.Fatalf("字面相等但非法的条目应丢弃: got=%q", got)
	}
	// 合法相等条目保持原样返回
	if got := cidrIntersectParsed(parseEntryCached("203.0.113.7", cache), parseEntryCached("203.0.113.7", cache)); got != "203.0.113.7" {
		t.Fatalf("合法相等条目应保留: got=%q", got)
	}
	if got := cidrIntersectParsed(parseEntryCached("10.0.0.0/24", cache), parseEntryCached("10.0.0.0/24", cache)); got != "10.0.0.0/24" {
		t.Fatalf("合法相等 CIDR 应保留: got=%q", got)
	}
}

// 全链形状：两条 allow 名单共享同一坏条目时，交集不得因坏条目变非空。
func TestIntersectIPLists_badEntryDoesNotFabricateIntersection(t *testing.T) {
	got := intersectIPLists([][]string{
		{"1.2.3.4", "garbage-entry"},
		{"garbage-entry"},
	})
	for _, e := range got {
		if e == "garbage-entry" {
			t.Fatalf("交集不得含坏条目: %v", got)
		}
	}
}

func TestCountEnabledCustomRulesBatch_matchesSingles(t *testing.T) {
	newClusterTestService(t)
	// 计数与发射侧同判据（customRuleEmittable）：空 conditions 的规则发射端会
	// 跳过，夹具须给「启用」行可发射条件，本用例才验证「禁用不计」与批量/
	// 单策略一致性。
	cond := `[{"target":"uri","operator":"regex","pattern":"^/ok$"}]`
	_, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES
		('on', ?, 'block', 5, 1), ('off', ?, 'block', 5, 0)`, cond, cond)
	if err != nil {
		t.Fatal(err)
	}
	var onID, offID int
	if err := db.DB.QueryRow(`SELECT id FROM security_custom_rules WHERE name='on'`).Scan(&onID); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT id FROM security_custom_rules WHERE name='off'`).Scan(&offID); err != nil {
		t.Fatal(err)
	}
	policies := []*models.SecurityPolicy{
		{CustomRules: json.RawMessage(fmt.Sprintf("[%d,%d,999999]", onID, offID))},
		{CustomRules: json.RawMessage(`[{"id":1,"enabled":true,"conditions":[{"target":"uri","operator":"regex","pattern":"^/ok$"}]},{"id":2,"enabled":false,"conditions":[{"target":"uri","operator":"regex","pattern":"^/ok$"}]}]`)},
		{CustomRules: json.RawMessage(`[]`)},
	}
	got := CountEnabledCustomRulesBatch(policies)
	want := []int{1, 1, 0}
	for i := range want {
		single := CountEnabledCustomRules(policies[i].CustomRules)
		if got[i] != want[i] || got[i] != single {
			t.Fatalf("batch[%d]=%d, want %d (single=%d)", i, got[i], want[i], single)
		}
	}
}

// 畸形爬虫引擎列静默等价「全部引擎」 ——

// 畸形非空 engines 保留「全部引擎」向后兼容语义但必须 WARN 留痕（否则豁免面
// 被静默放大且零告警）；空集（""/空白/"[]"）不是畸形、不告警；合法形态只命中
// 勾选引擎。
func TestCrawlerEngines_malformedWarnsAndKeepsCompat(t *testing.T) {
	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	malformed := &models.SecurityPolicy{ID: 8708, GeoIPCrawlerEngines: json.RawMessage(`{"engine":"googlebot"}`)}
	if !crawlerEngineSelected(malformed, "googlebot") || !crawlerEngineSelected(malformed, "bingbot") {
		t.Fatal("畸形 engines 保留「全部引擎」向后兼容语义")
	}
	if !strings.Contains(logs.String(), "geoip_crawler_engines") || !strings.Contains(logs.String(), "解析失败") {
		t.Fatalf("畸形 engines 必须 WARN 留痕（否则豁免面被静默放大且零告警）:\n%s", logs.String())
	}

	// 空集形态（""/空白/"[]"/nil 模型）不告警且视为全部引擎。
	logs.Reset()
	empty := &models.SecurityPolicy{ID: 8709}
	for _, raw := range []string{"", "   ", "[]"} {
		empty.GeoIPCrawlerEngines = json.RawMessage(raw)
		if !crawlerEngineSelected(empty, "bingbot") {
			t.Fatalf("空 engines %q 必须视为全部引擎", raw)
		}
	}
	if strings.Contains(logs.String(), "解析失败") {
		t.Fatalf("空集不是畸形，不得留痕:\n%s", logs.String())
	}

	// 合法形态：仅勾选引擎命中。
	legal := &models.SecurityPolicy{ID: 8710, GeoIPCrawlerEngines: json.RawMessage(`["googlebot"]`)}
	if !crawlerEngineSelected(legal, "googlebot") || crawlerEngineSelected(legal, "bingbot") {
		t.Fatal("合法 engines 必须只命中勾选引擎")
	}
	if strings.Contains(logs.String(), "解析失败") {
		t.Fatalf("合法 engines 不得留痕:\n%s", logs.String())
	}
}

// CRS 段界单源：fallback 门与归因 switch 复用 securityEventsRuleIsCRSFamily，
// 不再各自复写 9xxxxx 字面量。段界 [900000,1000000) 的邻值必须严格分侧。
func TestSecurityEventsRuleIsCRSFamily_boundaries(t *testing.T) {
	for _, id := range []string{"900000", "942100", "999999"} {
		if !securityEventsRuleIsCRSFamily(id) {
			t.Fatalf("securityEventsRuleIsCRSFamily(%q)=false, want true", id)
		}
	}
	for _, id := range []string{"899999", "1000000", "8", ""} {
		if securityEventsRuleIsCRSFamily(id) {
			t.Fatalf("securityEventsRuleIsCRSFamily(%q)=true, want false", id)
		}
	}
}

// Given 策略载荷（可能是大段 JSON 或中文规则名）与截断上限。
// When 生成日志摘要片段。
// Then 按 rune 截断且带省略号——按字节截断会把中文字符切成半字（日志出现
// 非法 UTF-8）；limit<=0 表示「不记录载荷」必须返回空串而非原样透出。
func TestClipForLog_runeSafeTruncation(t *testing.T) {
	payload := `{"crs_excluded_rules":"949110,959100"}`
	if got := clipForLog(payload, 0); got != "" {
		t.Fatalf("limit=0 时=%q, want 空串（负数/零表示不记录载荷）", got)
	}
	if got := clipForLog(payload, -1); got != "" {
		t.Fatalf("limit=-1 时=%q, want 空串", got)
	}
	if got := clipForLog(payload, len([]rune(payload))); got != payload {
		t.Fatalf("恰在上限时=%q, want 原样（不得多打省略号）", got)
	}
	cut := clipForLog(payload, 4)
	if cut != `{"cr…` {
		t.Fatalf("ASCII 截断=%q, want %q", cut, `{"cr…`)
	}

	zh := "策略排除规则载荷超长"
	zhCut := clipForLog(zh, 3)
	if runes := []rune(zhCut); len(runes) != 4 || runes[3] != '…' {
		t.Fatalf("中文截断=%q（rune 数=%d）, want 前 3 个 rune + 省略号", zhCut, len(runes))
	}
	if !strings.HasPrefix(zhCut, "策略排") {
		t.Fatalf("中文截断=%q, want 以「策略排」开头（不得切坏多字节字符）", zhCut)
	}
	if got := clipForLog(zh, len([]rune(zh))+5); got != zh {
		t.Fatalf("上限大于长度时=%q, want 原样 %q", got, zh)
	}
}
