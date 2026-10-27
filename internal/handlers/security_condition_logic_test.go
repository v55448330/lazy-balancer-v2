package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

func TestSecurityCustomRule_conditionLogicCRUDAndValidation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/custom-rules", h.ListSecurityCustomRules)
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
	conditions := []map[string]any{{"target": "uri", "operator": "contains", "pattern": "/x"}}

	create := func(name string, logic any) *httptest.ResponseRecorder {
		t.Helper()
		payload := map[string]any{"name": name, "conditions": conditions, "action": "block", "score": 5, "enabled": true}
		if logic != nil {
			payload["condition_logic"] = logic
		}
		return postJSON(t, router, "/security/custom-rules", payload)
	}
	if rec := create("默认 AND", nil); rec.Code != http.StatusOK {
		t.Fatalf("省略 condition_logic 创建失败: %d %s", rec.Code, rec.Body.String())
	}
	if rec := create("显式 OR", "or"); rec.Code != http.StatusOK {
		t.Fatalf("OR 创建失败: %d %s", rec.Code, rec.Body.String())
	}
	if rec := create("非法关系", "xor"); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 condition_logic status=%d, want 400", rec.Code)
	}
	if rec := create("空关系", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("显式空 condition_logic status=%d, want 400", rec.Code)
	}

	var defaultLogic, orLogic string
	var orID int
	if err := db.DB.QueryRow(`SELECT condition_logic FROM security_custom_rules WHERE name='默认 AND'`).Scan(&defaultLogic); err != nil {
		t.Fatalf("读取默认关系: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT id,condition_logic FROM security_custom_rules WHERE name='显式 OR'`).Scan(&orID, &orLogic); err != nil {
		t.Fatalf("读取 OR 关系: %v", err)
	}
	if defaultLogic != "and" || orLogic != "or" {
		t.Fatalf("落库关系 default=%q or=%q, want and/or", defaultLogic, orLogic)
	}
	var invalidCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_custom_rules WHERE name='非法关系'`).Scan(&invalidCount); err != nil {
		t.Fatal(err)
	}
	if invalidCount != 0 {
		t.Fatal("非法 condition_logic 不得落库")
	}

	if rec := putJSON(t, router, fmt.Sprintf("/security/custom-rules/%d", orID), map[string]any{"description": "部分更新"}); rec.Code != http.StatusOK {
		t.Fatalf("OR 部分更新失败: %d %s", rec.Code, rec.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT condition_logic FROM security_custom_rules WHERE id=?`, orID).Scan(&orLogic); err != nil {
		t.Fatal(err)
	}
	if orLogic != "or" {
		t.Fatalf("省略 condition_logic 的部分更新改变现值为 %q", orLogic)
	}
	if rec := putJSON(t, router, fmt.Sprintf("/security/custom-rules/%d", orID), map[string]any{"condition_logic": "and"}); rec.Code != http.StatusOK {
		t.Fatalf("OR→AND 更新失败: %d %s", rec.Code, rec.Body.String())
	}
	if rec := putJSON(t, router, fmt.Sprintf("/security/custom-rules/%d", orID), map[string]any{"condition_logic": "invalid"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法更新 status=%d, want 400", rec.Code)
	}
	if rec := putJSON(t, router, fmt.Sprintf("/security/custom-rules/%d", orID), map[string]any{"condition_logic": ""}); rec.Code != http.StatusBadRequest {
		t.Fatalf("空关系更新 status=%d, want 400", rec.Code)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/custom-rules", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("列表 status=%d", recorder.Code)
	}
	var response struct {
		Data []struct {
			Name           string `json:"name"`
			ConditionLogic string `json:"condition_logic"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析列表: %v", err)
	}
	got := map[string]string{}
	for _, rule := range response.Data {
		got[rule.Name] = rule.ConditionLogic
	}
	if got["默认 AND"] != "and" || got["显式 OR"] != "and" {
		t.Fatalf("列表 condition_logic=%v, want 默认 AND=and、更新后显式 OR=and", got)
	}
}
