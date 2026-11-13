package handlers

// CC 防护写侧契约：cc_4xx_ratio 0=关（保留 0）、合法域 [0,100]、负值回落缺省 70；
// cc_rps_window 合法域 [1,3600]、缺省 10、超上限钳制。Create/Update 同口径单源。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func ccContractInt(t *testing.T, id int, col string) int {
	t.Helper()
	var v int
	if err := db.DB.QueryRow(`SELECT COALESCE(`+col+`,0) FROM security_policies WHERE id=?`, id).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", col, err)
	}
	return v
}

// CC 阈值归一：4xx 比例 0=关保留、超上限钳 100、负值回落缺省；window 超上限钳
// 3600、缺省 10。POST 与 PUT 对同一输入落库一致（单源归一）。
func TestSecurityPolicy_ccThresholdNormalization(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)

	// 4xx：input → want（Create 与 Update 同口径）
	xxCases := []struct{ input, want int }{
		{0, 0},     // 0=关，保留（旧实现吞成 70）
		{150, 100}, // 超上限钳 100（旧实现直通）
		{-5, 70},   // 负值回落缺省 70
		{100, 100},
		{1, 1},
		{70, 70},
	}
	for _, tc := range xxCases {
		t.Run("4xx/"+fmt.Sprint(tc.input), func(t *testing.T) {
			cid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-4xx-c-%d", tc.input), "policy_type": "stage2", "cc_detect_enabled": true,
				"cc_4xx_ratio": tc.input,
			})
			if got := ccContractInt(t, cid, "cc_4xx_ratio"); got != tc.want {
				t.Fatalf("POST cc_4xx_ratio=%d stored=%d, want %d", tc.input, got, tc.want)
			}
			uid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-4xx-u-%d", tc.input), "policy_type": "stage2", "cc_detect_enabled": true,
			})
			rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", uid), map[string]any{
				"policy_type": "stage2", "cc_4xx_ratio": tc.input,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT cc_4xx_ratio=%d status=%d body=%s", tc.input, rec.Code, rec.Body.String())
			}
			if got := ccContractInt(t, uid, "cc_4xx_ratio"); got != tc.want {
				t.Fatalf("PUT cc_4xx_ratio=%d stored=%d, want %d（须与 Create 同口径）", tc.input, got, tc.want)
			}
		})
	}

	// window：input → want
	winCases := []struct{ input, want int }{
		{99999, 3600}, // 超上限钳 3600（旧实现直通）
		{0, 10},       // 低于下限回落缺省 10
		{-3, 10},
		{1, 1},
		{3600, 3600},
		{15, 15},
	}
	for _, tc := range winCases {
		t.Run("window/"+fmt.Sprint(tc.input), func(t *testing.T) {
			cid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-win-c-%d", tc.input), "policy_type": "stage2", "cc_detect_enabled": true,
				"cc_rps_window": tc.input,
			})
			if got := ccContractInt(t, cid, "cc_rps_window"); got != tc.want {
				t.Fatalf("POST cc_rps_window=%d stored=%d, want %d", tc.input, got, tc.want)
			}
			uid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-win-u-%d", tc.input), "policy_type": "stage2", "cc_detect_enabled": true,
			})
			rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", uid), map[string]any{
				"policy_type": "stage2", "cc_rps_window": tc.input,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT cc_rps_window=%d status=%d body=%s", tc.input, rec.Code, rec.Body.String())
			}
			if got := ccContractInt(t, uid, "cc_rps_window"); got != tc.want {
				t.Fatalf("PUT cc_rps_window=%d stored=%d, want %d（须与 Create 同口径）", tc.input, got, tc.want)
			}
		})
	}

	// 缺省：window 创建省略 → 10；4xx 更新省略 → 保持存量缺省 70。
	t.Run("defaults", func(t *testing.T) {
		cid := createTestPolicy(t, router, map[string]any{
			"name": "cc-def-c", "policy_type": "stage2", "cc_detect_enabled": true,
		})
		if got := ccContractInt(t, cid, "cc_rps_window"); got != 10 {
			t.Fatalf("POST 省略 cc_rps_window stored=%d, want 10", got)
		}
		// Create 省略 cc_4xx_ratio → 缺省 70（*int 区分省略与显式 0；裸 int 会落 0=关）。
		if got := ccContractInt(t, cid, "cc_4xx_ratio"); got != 70 {
			t.Fatalf("POST 省略 cc_4xx_ratio stored=%d, want 70（缺省，非 0=关）", got)
		}
		id := createTestPolicy(t, router, map[string]any{
			"name": "cc-def-u", "policy_type": "stage2", "cc_detect_enabled": true,
			"cc_4xx_ratio": 70,
		})
		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
			"policy_type": "stage2", "cc_rps_limit": 60, // 不带 cc_4xx_ratio
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
		}
		if got := ccContractInt(t, id, "cc_4xx_ratio"); got != 70 {
			t.Fatalf("省略 cc_4xx_ratio 后 stored=%d, want 70（保持存量缺省）", got)
		}
	})
}

func ccContractStr(t *testing.T, id int, col string) string {
	t.Helper()
	var v string
	if err := db.DB.QueryRow(`SELECT COALESCE(`+col+`,'') FROM security_policies WHERE id=?`, id).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", col, err)
	}
	return v
}

// 人机/CC 字段更新归一：PUT 与 POST 对同一非法/边界输入落库一致（单源 helper）。
// 覆盖 ttl/mode/type/豁免路径/rps/ua；4xx 与 window 的阈值归一见 ccThresholdNormalization。
func TestSecurityPolicy_updateNormalizesHumanCCFieldsLikeCreate(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)

	intCases := []struct {
		field string
		input int
		want  int
	}{
		{"human_verify_ttl", 99999, 30}, // 超上限 → 缺省 30
		{"human_verify_ttl", 0, 30},     // 低于下限 → 缺省 30
		{"human_verify_ttl", 45, 45},    // 合法保留
		{"cc_rps_limit", -5, 40},        // 负 → 缺省 40
		{"cc_rps_limit", 0, 40},         // 0 → 缺省 40（rps 无「0=关」语义）
		{"cc_rps_limit", 55, 55},
		{"cc_session_ua_threshold", -1, 5},
		{"cc_session_ua_threshold", 0, 5},
		{"cc_session_ua_threshold", 7, 7},
	}
	for _, tc := range intCases {
		t.Run("int/"+tc.field+"/"+fmt.Sprint(tc.input), func(t *testing.T) {
			cid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-n-c-%s-%d", tc.field, tc.input), "policy_type": "stage2", "cc_detect_enabled": true,
				tc.field: tc.input,
			})
			if got := ccContractInt(t, cid, tc.field); got != tc.want {
				t.Fatalf("POST %s=%d stored=%d, want %d", tc.field, tc.input, got, tc.want)
			}
			uid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-n-u-%s-%d", tc.field, tc.input), "policy_type": "stage2", "cc_detect_enabled": true,
			})
			rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", uid), map[string]any{
				"policy_type": "stage2", tc.field: tc.input,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT %s=%d status=%d body=%s", tc.field, tc.input, rec.Code, rec.Body.String())
			}
			if got := ccContractInt(t, uid, tc.field); got != tc.want {
				t.Fatalf("PUT %s=%d stored=%d, want %d（须与 Create 同口径）", tc.field, tc.input, got, tc.want)
			}
		})
	}

	strCases := []struct {
		field string
		input string
		want  string
	}{
		{"human_verify_mode", "FORCE", "off"}, // 非法枚举 → off
		{"human_verify_mode", "", "off"},
		{"human_verify_mode", "force", "force"},
		{"human_verify_type", "bogus", "slider"},
		{"human_verify_type", "js", "js"},
		{"human_exempt_paths", "", "[]"},               // 空串 → []
		{"human_exempt_paths", "not-json", "not-json"}, // 与 Create 同口径（透传）
		{"human_exempt_paths", `["/health/"]`, `["/health/"]`},
	}
	for i, tc := range strCases {
		t.Run(fmt.Sprintf("str/%s/%d", tc.field, i), func(t *testing.T) {
			cid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-n-c-%s-%d", tc.field, i), "policy_type": "stage2", "cc_detect_enabled": true,
				tc.field: tc.input,
			})
			if got := ccContractStr(t, cid, tc.field); got != tc.want {
				t.Fatalf("POST %s=%q stored=%q, want %q", tc.field, tc.input, got, tc.want)
			}
			uid := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("cc-n-u-%s-%d", tc.field, i), "policy_type": "stage2", "cc_detect_enabled": true,
			})
			rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", uid), map[string]any{
				"policy_type": "stage2", tc.field: tc.input,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT %s=%q status=%d body=%s", tc.field, tc.input, rec.Code, rec.Body.String())
			}
			if got := ccContractStr(t, uid, tc.field); got != tc.want {
				t.Fatalf("PUT %s=%q stored=%q, want %q（须与 Create 同口径）", tc.field, tc.input, got, tc.want)
			}
		})
	}
}

func ccContractBool(t *testing.T, id int, col string) bool {
	t.Helper()
	var v bool
	if err := db.DB.QueryRow(`SELECT COALESCE(`+col+`,0) FROM security_policies WHERE id=?`, id).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", col, err)
	}
	return v
}

// 缺省类型创建按人机/CC 内容推断 stage2：仅人机开启或仅 CC 检测启用（无 WAF/ACL/
// 信任内容）时，推断必须落 stage2（与更新侧重推断同口径），不得回落零组桶 stage3。
func TestCreateSecurityPolicy_infersStage2FromHumanOrCCContent(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"human-only", map[string]any{"name": "infer-human", "human_verify_mode": "force"}},
		{"cc-only", map[string]any{"name": "infer-cc", "cc_detect_enabled": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, router, "/security/policies", tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body.String())
			}
			var ptype string
			if err := db.DB.QueryRow(`SELECT COALESCE(policy_type,'') FROM security_policies WHERE name=?`, tc.body["name"]).Scan(&ptype); err != nil {
				t.Fatal(err)
			}
			if ptype != "stage2" {
				t.Fatalf("inferred policy_type=%q, want stage2（人机/CC 内容）", ptype)
			}
		})
	}
}

// 阶段外归零矩阵覆盖 cc_* 六列：显式非 stage2 类型创建/更新时，人机与 CC 字段
// 一并归零（注释宣称的 human_verify_*+cc_* 族，实现须一致）。
func TestSecurityPolicy_stageZeroCoversCCFields(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)

	t.Run("create-stage3-zeroes-cc", func(t *testing.T) {
		cid := createTestPolicy(t, router, map[string]any{
			"name": "zero-c", "policy_type": "stage3", "mode": "blocking",
			"human_verify_mode": "force", "human_verify_type": "js", "human_verify_ttl": 45,
			"human_exempt_paths": `["/keep/"]`,
			"cc_detect_enabled":  true, "cc_rps_limit": 55, "cc_rps_window": 15,
			"cc_4xx_ratio": 65, "cc_session_anomaly": true, "cc_session_ua_threshold": 7,
		})
		assertCCZeroed(t, cid)
	})

	t.Run("update-stage2-to-stage3-zeroes-cc", func(t *testing.T) {
		uid := createTestPolicy(t, router, map[string]any{
			"name": "zero-u", "policy_type": "stage2",
			"human_verify_mode": "force", "human_verify_type": "js", "human_verify_ttl": 45,
			"human_exempt_paths": `["/keep/"]`,
			"cc_detect_enabled":  true, "cc_rps_limit": 55, "cc_rps_window": 15,
			"cc_4xx_ratio": 65, "cc_session_anomaly": true, "cc_session_ua_threshold": 7,
		})
		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", uid), map[string]any{
			"policy_type": "stage3", "mode": "blocking",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
		}
		assertCCZeroed(t, uid)
	})
}

// assertCCZeroed 断言人机四列与 CC 六列全部落阶段零值（off/slider/30/[] 与
// false/40/10/70/false/5）。
func assertCCZeroed(t *testing.T, id int) {
	t.Helper()
	if got := ccContractStr(t, id, "human_verify_mode"); got != "off" {
		t.Fatalf("human_verify_mode=%q, want off", got)
	}
	if got := ccContractStr(t, id, "human_verify_type"); got != "slider" {
		t.Fatalf("human_verify_type=%q, want slider", got)
	}
	if got := ccContractInt(t, id, "human_verify_ttl"); got != 30 {
		t.Fatalf("human_verify_ttl=%d, want 30", got)
	}
	if got := ccContractStr(t, id, "human_exempt_paths"); got != "[]" {
		t.Fatalf("human_exempt_paths=%q, want []", got)
	}
	if ccContractBool(t, id, "cc_detect_enabled") {
		t.Fatal("cc_detect_enabled=true, want false")
	}
	if got := ccContractInt(t, id, "cc_rps_limit"); got != 40 {
		t.Fatalf("cc_rps_limit=%d, want 40", got)
	}
	if got := ccContractInt(t, id, "cc_rps_window"); got != 10 {
		t.Fatalf("cc_rps_window=%d, want 10", got)
	}
	if got := ccContractInt(t, id, "cc_4xx_ratio"); got != 70 {
		t.Fatalf("cc_4xx_ratio=%d, want 70", got)
	}
	if ccContractBool(t, id, "cc_session_anomaly") {
		t.Fatal("cc_session_anomaly=true, want false")
	}
	if got := ccContractInt(t, id, "cc_session_ua_threshold"); got != 5 {
		t.Fatalf("cc_session_ua_threshold=%d, want 5", got)
	}
}

// 显式非 stage2 类型更新携带「生效中」的人机/CC 字段 = 矛盾载荷 400（与其余阶段外
// 族同口径）；惰性默认值（off/slider/30/[]/false/40/10/70/false/5）不算冲突。
func TestUpdateSecurityPolicy_rejectsActiveHumanCCForNonStage2(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)

	activeCases := []struct {
		name string
		body map[string]any
	}{
		{"human-mode-force", map[string]any{"human_verify_mode": "force"}},
		{"cc-detect-on", map[string]any{"cc_detect_enabled": true}},
		{"cc-session-on", map[string]any{"cc_session_anomaly": true}},
		{"cc-rps-nondefault", map[string]any{"cc_rps_limit": 55}},
		{"cc-window-nondefault", map[string]any{"cc_rps_window": 15}},
		{"cc-4xx-nondefault", map[string]any{"cc_4xx_ratio": 65}},
		{"cc-ua-nondefault", map[string]any{"cc_session_ua_threshold": 7}},
		{"human-ttl-nondefault", map[string]any{"human_verify_ttl": 45}},
		{"human-type-js", map[string]any{"human_verify_type": "js"}},
		{"human-paths-nonempty", map[string]any{"human_exempt_paths": `["/keep/"]`}},
	}
	for _, tc := range activeCases {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			id := createTestPolicy(t, router, map[string]any{
				"name": fmt.Sprintf("conf-%s", tc.name), "policy_type": "stage2",
				"human_verify_mode": "force", "cc_detect_enabled": true,
			})
			body := map[string]any{"policy_type": "stage3", "mode": "blocking"}
			for k, v := range tc.body {
				body[k] = v
			}
			rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT status=%d body=%s, want 400（阶段外人机/CC 显式生效）", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "阶段 2") {
				t.Fatalf("body=%s, want 指引阶段 2", rec.Body.String())
			}
		})
	}

	t.Run("inert-defaults-allowed", func(t *testing.T) {
		id := createTestPolicy(t, router, map[string]any{
			"name": "conf-inert", "policy_type": "stage2",
			"human_verify_mode": "force", "cc_detect_enabled": true,
		})
		rec := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{
			"policy_type": "stage3", "mode": "blocking",
			"human_verify_mode": "off", "human_verify_type": "slider", "human_verify_ttl": 30,
			"human_exempt_paths": "[]",
			"cc_detect_enabled":  false, "cc_rps_limit": 40, "cc_rps_window": 10,
			"cc_4xx_ratio": 70, "cc_session_anomaly": false, "cc_session_ua_threshold": 5,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s, want 200（惰性默认值不算矛盾载荷）", rec.Code, rec.Body.String())
		}
	})
}
