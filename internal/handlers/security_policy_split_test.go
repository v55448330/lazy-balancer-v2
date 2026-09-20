package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 混合策略一键拆分迁移（2026-09-20 用户裁定）：POST /security/policies/:id/split
// 仅 mixed 策略可用——按特征组生成「原名（阶段 N）」单职子策略（空组不生成），
// 全量重映射绑定（≤5 上限的规则进 skipped 并保留原绑定），无 skipped 才删除
// 原策略；单事务单渲染；响应 {created, remapped, skipped, deleted_original}。

func splitRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/policies/:id/split", h.SplitSecurityPolicy)
	return router
}

func seedSplitFixture(t *testing.T) (mixedID int) {
	t.Helper()
	// mixed：blocking + ACL + 限流（三阶段全特征）
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,rate_limit_enabled,rate_limit_rps,rate_limit_burst,block_page_id,block_status_code,policy_type,enabled)
		VALUES ('legacy-mix','blocking',1,'deny','["203.0.113.0/24"]',1,100,50,0,403,'mixed',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	// 两条绑定规则
	for _, rule := range []string{"lb_s1", "lb_s2"} {
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES (?,?, 'http', ?, 8080, 1)`, rule, rule, rule+".test"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, rule, id); err != nil {
			t.Fatal(err)
		}
	}
	return int(id)
}

func postSplit(t *testing.T, router *gin.Engine, id int) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/security/policies/"+strconv.Itoa(id)+"/split", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

type splitPayload struct {
	Code int `json:"code"`
	Data struct {
		Created []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			PolicyType string `json:"policy_type"`
		} `json:"created"`
		Remapped        int              `json:"remapped"`
		Skipped         []map[string]any `json:"skipped"`
		DeletedOriginal bool             `json:"deleted_original"`
	} `json:"data"`
}

func TestSplitSecurityPolicy_threeChildrenAndRemap(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	mixedID := seedSplitFixture(t)

	response := postSplit(t, router, mixedID)
	if response.Code != http.StatusOK {
		t.Fatalf("split status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload splitPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, response.Body.String())
	}
	if len(payload.Data.Created) != 3 || payload.Data.Remapped != 2 || len(payload.Data.Skipped) != 0 || !payload.Data.DeletedOriginal {
		t.Fatalf("split result=%+v, want created=3 remapped=2 skipped=0 deleted=true", payload.Data)
	}
	// 子策略按阶段携带字段
	byType := map[string]int{}
	for _, child := range payload.Data.Created {
		byType[child.PolicyType] = child.ID
	}
	var mode, aclList string
	var rlRPS int
	if err := db.DB.QueryRow(`SELECT COALESCE(mode,''), COALESCE(ip_acl_list,'[]') FROM security_policies WHERE id=?`, byType["stage1"]).Scan(&mode, &aclList); err != nil {
		t.Fatal(err)
	}
	if mode != "off" || aclList != `["203.0.113.0/24"]` {
		t.Fatalf("stage1 child mode=%q acl=%q, want off + ACL preserved", mode, aclList)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(mode,''), COALESCE(rate_limit_rps,0) FROM security_policies WHERE id=?`, byType["stage2"]).Scan(&mode, &rlRPS); err != nil {
		t.Fatal(err)
	}
	if mode != "off" || rlRPS != 100 {
		t.Fatalf("stage2 child mode=%q rps=%d, want off + 100", mode, rlRPS)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(mode,'') FROM security_policies WHERE id=?`, byType["stage3"]).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "blocking" {
		t.Fatalf("stage3 child mode=%q, want blocking", mode)
	}
	// 绑定重映射：原策略绑定消失、子策略绑定在位
	for _, rule := range []string{"lb_s1", "lb_s2"} {
		var pids string
		if err := db.DB.QueryRow(`SELECT COALESCE(GROUP_CONCAT(policy_id),'') FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id`, rule).Scan(&pids); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(pids, strconv.Itoa(mixedID)) {
			t.Fatalf("%s still bound to original %d: [%s]", rule, mixedID, pids)
		}
		for _, childID := range byType {
			if !strings.Contains(pids, strconv.Itoa(childID)) {
				t.Fatalf("%s missing child %d binding: [%s]", rule, childID, pids)
			}
		}
	}
	// 原策略已删
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id=?`, mixedID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("original mixed policy must be deleted")
	}
}

func TestSplitSecurityPolicy_partialGroups(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	// 两特征组混合（detection + GeoIP → g1+g3）
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,geoip_mode,geoip_countries,policy_type,enabled) VALUES ('mix-two','detection','deny','["海外"]','mixed',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_s3','lb_s3','http','s3.test',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_s3',?)`, id); err != nil {
		t.Fatal(err)
	}

	response := postSplit(t, router, int(id))
	if response.Code != http.StatusOK {
		t.Fatalf("split status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload splitPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Created) != 2 || !payload.Data.DeletedOriginal {
		t.Fatalf("split result=%+v, want created=2 deleted=true", payload.Data)
	}
	for _, child := range payload.Data.Created {
		if child.PolicyType == "stage2" {
			t.Fatalf("empty stage2 group must not produce a child: %+v", payload.Data.Created)
		}
	}
}

func TestSplitSecurityPolicy_overflowRuleSkippedAndOriginalKept(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	mixedID := seedSplitFixture(t)
	// lb_s1 再绑 4 条其他策略（含原混合共 5 条）——拆分后 4+3=7 超限 → skipped
	for i := 0; i < 4; i++ {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES (?, 'off', 'stage3', 1)`, "other-"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		oid, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_s1',?)`, oid); err != nil {
			t.Fatal(err)
		}
	}

	response := postSplit(t, router, mixedID)
	if response.Code != http.StatusOK {
		t.Fatalf("split status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload splitPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Remapped != 1 || len(payload.Data.Skipped) != 1 || payload.Data.Skipped[0]["rule_id"] != "lb_s1" {
		t.Fatalf("split result=%+v, want remapped=1 skipped=[lb_s1]", payload.Data)
	}
	if payload.Data.DeletedOriginal {
		t.Fatal("original must be kept while a rule still references it")
	}
	// lb_s1 原绑定保留不动
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_s1' AND policy_id=?`, mixedID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("skipped rule must keep its original binding")
	}
	var original int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id=?`, mixedID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if original != 1 {
		t.Fatal("original mixed policy must be kept while in use")
	}
}

func TestSplitSecurityPolicy_nonMixedRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := splitRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES ('typed','blocking','stage3',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	if response := postSplit(t, router, int(id)); response.Code != http.StatusBadRequest {
		t.Fatalf("non-mixed split status=%d, want 400", response.Code)
	}
	if response := postSplit(t, router, 99999); response.Code != http.StatusNotFound {
		t.Fatalf("missing policy split status=%d, want 404", response.Code)
	}
}
