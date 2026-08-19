package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// TestUpdateSecurityPolicy_crsRuleGroupsRequiresTwoDigitGroupCode 验证 R46 B-F2：
// crs_rule_groups 条目必须是两位数字组号（发射端拼接 REQUEST-9<code>-*.conf）。
// "941"、"REQUEST-942" 这类写法会 glob 零匹配——coraza 对空 Include 静默接受，
// blocking 模式将无任何 CRS 规则生效且无任何报错；旧校验只限字符集，放行此类
// 条目。拒绝时必须点名问题条目。
func TestUpdateSecurityPolicy_crsRuleGroupsRequiresTwoDigitGroupCode(t *testing.T) {
	// Given 一个存在的策略
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "组号校验策略"})

	// When 提交两位数字组号（90-99 风格）
	// Then 接受并按原样存储
	recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_rule_groups": `["90","94","99"]`})
	if recorder.Code != http.StatusOK {
		t.Fatalf("two-digit groups status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var groups string
	if err := db.DB.QueryRow("SELECT crs_rule_groups FROM security_policies WHERE id=?", id).Scan(&groups); err != nil {
		t.Fatalf("read back groups: %v", err)
	}
	if groups != `["90","94","99"]` {
		t.Fatalf("crs_rule_groups = %q, want stored as-is", groups)
	}

	// When 提交 glob 零匹配的写法
	// Then 一律 400，且 message 点名问题条目
	for _, tc := range []struct {
		payload string
		entry   string
	}{
		{`["941"]`, "941"},
		{`["REQUEST-942"]`, "REQUEST-942"},
		{`["942 "]`, "942 "},
	} {
		recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_rule_groups": tc.payload})
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s, want 400", tc.payload, recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "两位数字组号") || !strings.Contains(recorder.Body.String(), tc.entry) {
			t.Fatalf("%s rejection must name the offending entry: %s", tc.payload, recorder.Body.String())
		}
	}
	// 单位数字同样 400（条目过短，单独断言状态码即可）
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_rule_groups": `["9"]`})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf(`["9"] status=%d body=%s, want 400`, recorder.Code, recorder.Body.String())
	}

	// And Create 路径同样收紧
	recorder = postJSON(t, router, "/security/policies", map[string]any{"name": "坏组号策略", "crs_rule_groups": `["941"]`})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create with bad group status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}

	// And crs_excluded_rules 不受两位组号约束（规则 id 为 6 位数字）
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_excluded_rules": `["942100"]`})
	if recorder.Code != http.StatusOK {
		t.Fatalf("crs_excluded_rules status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

// TestStartCRSUpdate_slaveNodeRejected403 验证 R46 B-F3：手动 CRS 更新从节点
// 一律 403（镜像 R41 A 域手动同步门控：直查 is_master，查询失败按非主节点拒绝）。
// 从节点本地更新会造成磁盘/DB 分叉——主节点下次同步把 version 行覆盖回主节点
// 口径，而从节点的启动对账是 master-only，分叉长期残留。
func TestStartCRSUpdate_slaveNodeRejected403(t *testing.T) {
	// Given 一个从节点（更新服务未初始化：若门控缺失会命中 500 而非 403，
	// 403 本身即证明门控先于 manager 触发）
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	services.ResetCRSUpdateManagerForTest()
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/crs/update", h.StartCRSUpdate)

	// When 从节点调用手动更新
	recorder := postJSON(t, router, "/security/crs/update", nil)

	// Then 403 且文案为主节点专属
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("slave status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "该操作仅允许在主节点执行") {
		t.Fatalf("body=%s, want 主节点专属文案", recorder.Body.String())
	}
}

// TestStartCRSUpdate_masterPassesGate 验证门控不误伤主节点：主节点上请求穿过
// 门控到达 manager 检查（未初始化 → 500 而非 403）。
func TestStartCRSUpdate_masterPassesGate(t *testing.T) {
	// Given 一个主节点（is_master 默认为 1），更新服务未初始化
	setupSecurityPolicyTestDB(t)
	services.ResetCRSUpdateManagerForTest()
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/crs/update", h.StartCRSUpdate)

	// When 主节点调用手动更新
	recorder := postJSON(t, router, "/security/crs/update", nil)

	// Then 穿过门控，命中 manager 未初始化的 500
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "CRS 更新服务未初始化") {
		t.Fatalf("master status=%d body=%s, want 500 CRS 更新服务未初始化（门控已放行）", recorder.Code, recorder.Body.String())
	}
}

// TestStartIP2RegionUpdate_slaveNodeRejected403 验证 R46 B-F3：手动 IP2Region
// 更新从节点一律 403，与 StartCRSUpdate 同一门控口径。
func TestStartIP2RegionUpdate_slaveNodeRejected403(t *testing.T) {
	// Given 一个从节点（更新服务未初始化）
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	services.ResetIP2RegionUpdateManagerForTest()
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/ip2region/update", h.StartIP2RegionUpdate)

	// When 从节点调用手动更新
	recorder := postJSON(t, router, "/security/ip2region/update", nil)

	// Then 403 且文案为主节点专属
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("slave status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "该操作仅允许在主节点执行") {
		t.Fatalf("body=%s, want 主节点专属文案", recorder.Body.String())
	}
}

// TestStartIP2RegionUpdate_masterPassesGate 验证门控不误伤主节点。
func TestStartIP2RegionUpdate_masterPassesGate(t *testing.T) {
	// Given 一个主节点，更新服务未初始化
	setupSecurityPolicyTestDB(t)
	services.ResetIP2RegionUpdateManagerForTest()
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/ip2region/update", h.StartIP2RegionUpdate)

	// When 主节点调用手动更新
	recorder := postJSON(t, router, "/security/ip2region/update", nil)

	// Then 穿过门控，命中 manager 未初始化的 500
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "IP2Region 更新服务未初始化") {
		t.Fatalf("master status=%d body=%s, want 500 IP2Region 更新服务未初始化（门控已放行）", recorder.Code, recorder.Body.String())
	}
}
