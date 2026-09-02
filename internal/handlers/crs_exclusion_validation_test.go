package handlers

// crs_excluded_rules 双格式 / crs_rule_groups 混合选择的保存侧校验矩阵与
// 端到端（listRefs 存在性、列表删除引用拦截、rule-index 端点）测试。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// useCRSRuleIndexFixture 写入 920/942 两组最小索引夹具并覆盖导出测试缝
// services.CRSRuleIndexDir（942 组含 942100、942550）。
func useCRSRuleIndexFixture(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"REQUEST-920-PROTOCOL-ANOMALY.conf": `SecRule &REQUEST_HEADERS:Accept "@eq 0" "id:920100,phase:1,log,deny,status:406,msg:'Request Missing an Accept Header'"
`,
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf": `SecRule ARGS "@rx (?i)union.*select" "id:942100,phase:2,block,msg:'SQLi'"
SecRule ARGS_NAMES "@rx ^id$" "id:942550,phase:2,pass,msg:'SQLi benchmark'"
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	old := services.CRSRuleIndexDir
	services.CRSRuleIndexDir = dir
	t.Cleanup(func() { services.CRSRuleIndexDir = old })
}

// seedHandlerIPList 直插一条 IP 地址列表并返回 id。
func seedHandlerIPList(t *testing.T, name, entriesJSON string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, ?)`, name, entriesJSON)
	if err != nil {
		t.Fatalf("seed ip list %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestValidateAndNormalizeCRSField_hybridRuleGroups(t *testing.T) {
	useCRSRuleIndexFixture(t)
	cases := []struct {
		payload string
		wantErr string
	}{
		{`["42"]`, ""},
		{`["942100"]`, ""},
		{`["42","942550"]`, ""},
		{`["999999"]`, "规则 ID 不存在于当前 CRS"},
		{`["941"]`, "两位数字组号"},
		{`["9x1"]`, "两位数字组号"},
		{`[" 42"]`, "首尾空白"},
		{`["942100 "]`, "首尾空白"},
		{`["42*"]`, "非法字符"},
		{`not-json`, "JSON 数组"},
	}
	for _, tc := range cases {
		val := tc.payload
		err := validateAndNormalizeCRSField("crs_rule_groups", &val)
		if tc.wantErr == "" {
			if err != nil {
				t.Fatalf("groups %s: unexpected error %v", tc.payload, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("groups %s: error = %v, want containing %q", tc.payload, err, tc.wantErr)
		}
	}
}

func TestValidateCRSExcludedRulesPayload_matrix(t *testing.T) {
	useCRSRuleIndexFixture(t)
	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		// 旧格式：现状兼容，不加索引校验
		{"legacy ID", `["942100"]`, ""},
		{"legacy filename", `["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]`, ""},
		{"legacy stale ID passes (现状)", `["999888"]`, ""},
		{"legacy illegal form", `["942100L"]`, "必须是 CRS 规则 ID"},
		// 新格式：合法形态
		{"group in index", `[{"target":"42","scope":"all"}]`, ""},
		{"6-digit in index all", `[{"target":"942100"}]`, ""},
		{"scope=ip with ips", `[{"target":"942100","scope":"ip","ips":"1.1.1.1,10.0.0.0/8"}]`, ""},
		{"scope=ip with ips+refs", `[{"target":"42","scope":"ip","ips":"1.1.1.1","listRefs":[3]}]`, ""},
		{"scope=list with refs", `[{"target":"942550","scope":"list","listRefs":[3,4]}]`, ""},
		{"duplicate entries pass (读侧去重)", `[{"target":"942100"},{"target":"942100"}]`, ""},
		// 新格式：非法形态
		{"stale 6-digit", `[{"target":"999999","scope":"ip","ips":"1.1.1.1"}]`, "规则 ID 不存在于当前 CRS"},
		{"stale group", `[{"target":"99","scope":"ip","ips":"1.1.1.1"}]`, "规则组不存在于当前 CRS"},
		{"bad scope", `[{"target":"942100","scope":"global"}]`, "scope 无效"},
		{"scope=ip empty ips", `[{"target":"942100","scope":"ip"}]`, "必须填写 ips"},
		{"scope=ip bad ip", `[{"target":"942100","scope":"ip","ips":"1.1.1.1,abc"}]`, "无效的 IP/CIDR"},
		{"scope=list empty refs", `[{"target":"942100","scope":"list"}]`, "必须填写 listRefs"},
		{"scope=all with ips", `[{"target":"942100","ips":"1.1.1.1"}]`, "不允许携带 ips/listRefs"},
		{"legacy target scoped", `[{"target":"REQUEST-942-APPLICATION-ATTACK-SQLI.conf","scope":"ip","ips":"1.1.1.1"}]`, "仅支持 scope=all"},
		{"empty target", `[{"target":"  ","scope":"all"}]`, "target 不能为空"},
		{"target whitespace", `[{"target":" 942100"}]`, "首尾空白"},
		{"target charset", `[{"target":"942100*"}`, "JSON 数组"},
		{"over 50 entries", "[" + strings.TrimSuffix(strings.Repeat(`{"target":"942100"},`, 51), ",") + "]", "不能超过 50 条"},
		{"mixed array", `["942100",{"target":"42"}]`, "JSON 数组"},
		{"not json", "oops", "JSON 数组"},
	}
	for _, tc := range cases {
		val := tc.payload
		err := validateCRSExcludedRulesPayload(&val)
		if tc.wantErr == "" {
			if err != nil {
				t.Fatalf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: error = %v, want containing %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestSecurityPolicyCRSExcludedNewFormatEndToEnd(t *testing.T) {
	useCRSRuleIndexFixture(t)
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)

	listID := seedHandlerIPList(t, "crs-scoped", `[{"value":"192.0.2.0/24","remark":""}]`)

	// 创建：新格式（含 listRefs 引用真实列表）→ 200 且列内容原样落库
	payload := map[string]any{
		"name":               "作用域排除策略",
		"mode":               "blocking",
		"crs_excluded_rules": fmt.Sprintf(`[{"target":"42","scope":"ip","ips":"1.1.1.1","listRefs":[%d]}]`, listID),
	}
	id := createTestPolicy(t, router, payload)
	var stored string
	if err := db.DB.QueryRow("SELECT crs_excluded_rules FROM security_policies WHERE id=?", id).Scan(&stored); err != nil {
		t.Fatalf("read stored: %v", err)
	}
	if !strings.Contains(stored, `"scope":"ip"`) || !strings.Contains(stored, fmt.Sprintf(`[%d]`, listID)) {
		t.Fatalf("stored payload = %s", stored)
	}

	// 更新：listRefs 指向不存在列表 → 400 引用了不存在的 IP 列表
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"crs_excluded_rules": `[{"target":"942550","scope":"list","listRefs":[9999]}]`,
	})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "引用了不存在的 IP 列表 #9999") {
		t.Fatalf("dangling listRef must 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	// 更新：陈旧 6 位 ID → 400 规则 ID 不存在于当前 CRS（PUT 接受新格式的
	// 事件快捷排除支撑面）
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
		"crs_excluded_rules": `[{"target":"999999","scope":"ip","ips":"1.1.1.1"}]`,
	})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "规则 ID 不存在于当前 CRS") {
		t.Fatalf("stale ID must 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	// 更新：合法新格式与旧格式仍可落库
	for _, valid := range []string{
		`[{"target":"942100","scope":"ip","ips":"203.0.113.7"}]`,
		`["942100"]`,
	} {
		recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_excluded_rules": valid})
		if recorder.Code != http.StatusOK {
			t.Fatalf("valid payload %s must 200, got %d body=%s", valid, recorder.Code, recorder.Body.String())
		}
	}
}

func TestDeleteIPList_blockedByCRSExclusionScopedRef(t *testing.T) {
	useCRSRuleIndexFixture(t)
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	h := &Handlers{}
	router.DELETE("/security/ip-lists/:id", h.DeleteIPList)

	listID := seedHandlerIPList(t, "scoped-ref", `[{"value":"198.51.100.0/24","remark":""}]`)
	createTestPolicy(t, router, map[string]any{
		"name":               "引用列表的作用域排除",
		"mode":               "detection",
		"crs_excluded_rules": fmt.Sprintf(`[{"target":"942550","scope":"list","listRefs":[%d]}]`, listID),
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/security/ip-lists/%d", listID), nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("list referenced by crs_excluded_rules must block deletion, got %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGetCRSRuleIndex_endpoint(t *testing.T) {
	useCRSRuleIndexFixture(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/crs/rule-index", h.GetCRSRuleIndex)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/crs/rule-index", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Rules []struct {
				ID  string `json:"id"`
				Msg string `json:"msg"`
			} `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Code != 0 || len(resp.Data.Rules) != 3 {
		t.Fatalf("rules = %+v, want 3 entries", resp.Data.Rules)
	}
	if resp.Data.Rules[0].ID != "920100" || resp.Data.Rules[2].ID != "942550" {
		t.Fatalf("rules must be id-ascending: %+v", resp.Data.Rules)
	}
	if resp.Data.Rules[1].Msg != "SQLi" {
		t.Fatalf("msg not parsed: %+v", resp.Data.Rules)
	}
}
