package handlers

// 写侧引用门与清单查询口径的钉测试：
//   - 三库「自动更新」开关统一走导入写门（IP2Region 曾缺席）；
//   - 拆分迁移被视为「新建策略」路径：子策略要落库的引用面与 Create 同门
//     （IP 名单 refs 存在性、CRS 排除作用域名单、内置名单禁令）；
//   - 显式 policy_type + 阶段外字段显式生效 = 400（不再静默归零）；
//   - 列表过滤参数 enabled=false 生效、策略详情绑定有序。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 三库「自动更新」开关端点在导入窗口一律 409（先于 body 解析）。
// IP2Region 与 CRS/威胁同族：版本表在导入全量替换清单内，窗口内写入会被
// 静默覆盖或撞写锁 500。
func TestLibAutoUpdateEndpoints_rejectWriteDuringImport(t *testing.T) {
	beginImportWindowForTest(t)

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	cases := []struct {
		name   string
		path   string
		invoke func(ctx *gin.Context)
	}{
		{"ip2region", "/security/ip2region/auto-update", h.UpdateIP2RegionAutoUpdate},
		{"crs", "/security/crs/auto-update", h.UpdateCRSAutoUpdate},
		{"threat", "/security/threat/auto-update", h.UpdateThreatAutoUpdate},
		{"crawler", "/security/crawler-lib/auto-update", h.UpdateCrawlerAutoUpdate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPut, tc.path, nil)
			tc.invoke(ctx)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("%s during import = %d body=%s, want 409", tc.name, recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "配置导入进行中") {
				t.Fatalf("%s body=%s, want 导入门文案", tc.name, recorder.Body.String())
			}
		})
	}
}

// 拆分迁移：子策略要落库的 IP 名单引用（阶段 0 信任 refs / 阶段 1 ACL refs）
// 若指向已删除的名单，拆分必须 400 拒绝——否则 ACL/信任合并集静默缩窄为
// inline-only（DeleteIPList 的引用扫描只拦启用策略，禁用态引用可悬空）。
func TestSplitSecurityPolicy_rejectsDanglingIPListRefs(t *testing.T) {
	cases := []struct {
		name    string
		columns string
		values  string
		want    string
	}{
		{
			name:    "ACL 引用",
			columns: "ip_acl_enabled,ip_acl_mode,ip_acl_list_refs",
			values:  `1,'deny','[424242]'`,
			want:    "IP 列表",
		},
		{
			name:    "信任名单引用",
			columns: "ip_whitelist_enabled,ip_whitelist_refs",
			values:  `0,'[424243]'`,
			want:    "IP 列表",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := splitRouter(t)
			res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled,` + tc.columns + `) VALUES ('mix-ref','blocking','mixed',0,` + tc.values + `)`)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := res.LastInsertId()
			response := postSplit(t, router, int(id))
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.want) {
				t.Fatalf("dangling refs split = %d body=%s, want 400 containing %q", response.Code, response.Body.String(), tc.want)
			}
			var policies int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies`).Scan(&policies); err != nil {
				t.Fatal(err)
			}
			if policies != 1 {
				t.Fatalf("rejected split must not create child policies: policies=%d", policies)
			}
		})
	}
}

// 拆分迁移：内置威胁名单只能用于 ACL 黑名单——把内置名单复制进阶段 0 子策略的
// 信任 refs 必须拒绝（与 Create 的 validateBuiltinThreatListRefs 同门）。
func TestSplitSecurityPolicy_rejectsBuiltinListInWhitelistRefs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, system, entries) VALUES ('内置威胁测试名单', 1, '[]')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, _ := res.LastInsertId()
	policyRes, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled,ip_whitelist_enabled,ip_whitelist_refs) VALUES ('mix-builtin','blocking','mixed',0,1,?)`, "["+strconv.FormatInt(listID, 10)+"]")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := policyRes.LastInsertId()
	response := postSplit(t, router, int(id))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "仅允许用于 IP 访问控制的黑名单模式") {
		t.Fatalf("builtin list in whitelist refs split = %d body=%s, want 400 内置名单门", response.Code, response.Body.String())
	}
}

// 显式 policy_type + 阶段外字段显式生效 → 400（此前静默归零后 200，
// 脚本/MCP 无法从响应区分「已生效」与「被忽略」）。
func TestUpdateSecurityPolicy_rejectsExplicitOutOfStageFields(t *testing.T) {
	cases := []struct {
		name     string
		createAs map[string]any
		payload  map[string]any
		want     string
	}{
		{
			name:     "stage3 显式启用 ACL",
			createAs: map[string]any{"name": "conflict-acl", "policy_type": "stage4", "mode": "blocking"},
			payload: map[string]any{
				"policy_type": "stage4", "ip_acl_enabled": true, "ip_acl_mode": "deny", "ip_acl_list": `["203.0.113.0/24"]`,
			},
			want: "阶段 1",
		},
		{
			name:     "stage3 显式启用地域控制",
			createAs: map[string]any{"name": "conflict-rl", "policy_type": "stage4", "mode": "blocking"},
			payload: map[string]any{
				"policy_type": "stage4", "geoip_mode": "deny", "geoip_countries": `["CN"]`,
			},
			want: "阶段 1",
		},
		{
			name:     "stage1 显式设置 WAF 模式",
			createAs: map[string]any{"name": "conflict-mode", "policy_type": "stage1", "ip_acl_enabled": true, "ip_acl_mode": "deny", "ip_acl_list": `["203.0.113.0/24"]`},
			payload: map[string]any{
				"policy_type": "stage1", "mode": "blocking",
			},
			want: "阶段 4",
		},
		{
			name:     "stage0 显式设置地域控制",
			createAs: map[string]any{"name": "conflict-geo", "policy_type": "stage0", "ip_whitelist": `["198.51.100.7"]`},
			payload: map[string]any{
				"policy_type": "stage0", "geoip_mode": "deny", "geoip_countries": `["中国"]`,
			},
			want: "阶段 1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			router := newSecurityRouter(t)
			id := createTestPolicy(t, router, tc.createAs)
			recorder := putJSON(t, router, "/security/policies/"+strconv.Itoa(id), tc.payload)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("PUT status=%d body=%s, want 400（阶段外字段显式生效）", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.want) {
				t.Fatalf("body=%s, want hint containing %q", recorder.Body.String(), tc.want)
			}
		})
	}
}

// 回归：编辑器对「该阶段不呈现」的字段仍会回传默认值（爬虫引擎默认三项、
// 拦截页 1/状态码 403、名单保留但开关关闭）——
// 这些值在该阶段不产生任何行为面，不得被矛盾载荷门误拒。
func TestUpdateSecurityPolicy_allowsInertOutOfStageDefaults(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "inert-defaults", "policy_type": "stage4", "mode": "blocking"})
	recorder := putJSON(t, router, "/security/policies/"+strconv.Itoa(id), map[string]any{
		"policy_type": "stage4", "mode": "blocking",
		"ip_acl_enabled": false, "ip_acl_list": "[]", "ip_acl_list_refs": "[]",
		"geoip_mode": "off", "geoip_countries": "[]", "geoip_crawler_exempt": false,
		"geoip_crawler_engines": `["googlebot","bingbot","baiduspider"]`,
		"waf_check_response":    false, "log_request_body": false, "trust_detection": false,
		"block_page_id": 1, "block_status_code": 403,
		"crs_rule_groups": "[]", "crs_excluded_rules": "[]", "custom_rules": "[]",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200（惰性默认值不算矛盾载荷）", recorder.Code, recorder.Body.String())
	}
}

// 列表过滤 enabled=false 必须生效（此前被静默忽略，返回全量）。
func TestListSecurityPolicies_filtersDisabled(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	for _, row := range []struct {
		name    string
		enabled int
	}{{"on", 1}, {"off", 0}} {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,enabled) VALUES (?, 'off', ?)`, row.name, row.enabled); err != nil {
			t.Fatal(err)
		}
	}
	recorder := getRequest(t, router, "/security/policies?enabled=false")
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, recorder.Body.String())
	}
	if len(payload.Data) != 1 || payload.Data[0].Name != "off" {
		t.Fatalf("?enabled=false = %+v, want only disabled policy", payload.Data)
	}
}

// 策略详情 bindings 与全量绑定端点同口径（rule_caddy_id ASC）。
func TestGetSecurityPolicy_bindingsOrdered(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,enabled) VALUES ('ordered','off',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	for _, rule := range []string{"lb_z", "lb_a", "lb_m"} {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, rule, id); err != nil {
			t.Fatal(err)
		}
	}
	recorder := getRequest(t, router, "/security/policies/"+strconv.FormatInt(id, 10))
	if recorder.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Bindings []string `json:"bindings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, recorder.Body.String())
	}
	want := []string{"lb_a", "lb_m", "lb_z"}
	if strings.Join(payload.Data.Bindings, ",") != strings.Join(want, ",") {
		t.Fatalf("bindings=%v, want %v (ORDER BY rule_caddy_id ASC)", payload.Data.Bindings, want)
	}
}

// 策略/拦截页全局数量上限（与自定义规则/IP 名单 200 同族双限额口径）：
// 计数在写事务内 fail-closed。
func TestCreateSecurityPolicyAndBlockPage_globalCountCaps(t *testing.T) {
	t.Run("policies", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityRouter(t)
		for i := range securityPolicyMaxGlobalCount {
			if _, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,enabled) VALUES (?,'off',1)`, "seed-"+strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "one-too-many", "mode": "off"})
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "上限") {
			t.Fatalf("create over cap = %d body=%s, want 400 上限", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("block pages", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		gin.SetMode(gin.TestMode)
		h := &Handlers{}
		router := gin.New()
		router.POST("/security/block-pages", h.CreateSecurityBlockPage)
		var seed int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_block_pages`).Scan(&seed); err != nil {
			t.Fatal(err)
		}
		for i := range securityBlockPageMaxGlobalCount - seed {
			if _, err := db.DB.Exec(`INSERT INTO security_block_pages (name,content,content_type) VALUES (?,'<p>x</p>','text/html; charset=utf-8')`, "page-"+strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		recorder := postJSON(t, router, "/security/block-pages", map[string]any{"name": "one-too-many", "content": "<p>y</p>"})
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "上限") {
			t.Fatalf("create over cap = %d body=%s, want 400 上限", recorder.Code, recorder.Body.String())
		}
	})
}

// 摘要路径（GET 列表 ~1s 轮询）不得产生审计写：引用名单装载失败只在服务端
// 日志留痕，「渲染跳过」审计归渲染路径（读端点带写副作用会污染审计追溯）。
func TestListSecurityPolicies_summaryDoesNotWriteRenderSkipAudit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	// 威胁库 system 名单引用的文件不存在 → 严格模式装载失败（渲染路径置
	// IPRefMissing 并写「渲染跳过」审计）。摘要路径必须只留日志。
	systemLists := db.ThreatSystemLists()
	if len(systemLists) == 0 {
		t.Skip("威胁系统名单未播种")
	}
	var listID int64
	err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, systemLists[0].Name).Scan(&listID)
	if err != nil {
		res, insErr := db.DB.Exec(`INSERT INTO security_ip_lists (name, system, entries) VALUES (?, 1, '[]')`, systemLists[0].Name)
		if insErr != nil {
			t.Fatal(insErr)
		}
		listID, _ = res.LastInsertId()
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,enabled,ip_acl_enabled,ip_acl_mode,ip_acl_list_refs,policy_type) VALUES ('ref-fail','blocking',1,1,'deny',?,'stage1')`, "["+strconv.FormatInt(listID, 10)+"]"); err != nil {
		t.Fatal(err)
	}
	before := countRenderSkipAuditRows(t)
	recorder := getRequest(t, router, "/security/policies")
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if after := countRenderSkipAuditRows(t); after != before {
		t.Fatalf("summary path wrote %d render-skip audit rows, want 0（读路径不写审计）", after-before)
	}
}

func countRenderSkipAuditRows(t *testing.T) int {
	t.Helper()
	if db.AuditDB == nil {
		return 0
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='渲染跳过'`).Scan(&count); err != nil {
		t.Fatalf("count render-skip audit rows: %v", err)
	}
	return count
}
