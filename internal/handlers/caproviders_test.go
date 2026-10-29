package handlers

// CA 提供商写路径契约：凭证审计三态（unchanged/changed/cleared）。空白串对
// ZeroSSL 会真实清空 credentials 列（服务层放行空串），审计必须记「凭证
// （清空）」；语义相等的载荷（键序/空白重排）不得记成「凭证」变更。
// 全星号掩码回传不在审计态内：非 LE 提供商的凭证走 JSON 门，全星号载荷在
// 审计判定前即被服务层 400 拒绝（见下面的端点钉测）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestCredentialAuditStateFor_truthTable(t *testing.T) {
	cases := []struct {
		name, newValue, oldValue string
		want                     credentialAuditState
	}{
		{"blank_old_blank", "", "", credentialUnchanged},
		{"blank_whitespace_only", "  ", `{"api_key":"real"}`, credentialCleared},
		{"blank_clears_existing", "", `{"api_key":"real"}`, credentialCleared},
		// 语义比较：键序/空白重排不算变更（原实现按字符串比较，前端重排键序
		// 会被误记为凭证变更并刷审计噪声）。
		{"reordered_keys", `{"b":2,"a":1}`, `{"a":1,"b":2}`, credentialUnchanged},
		{"reformatted_whitespace", " { \"api_key\" : \"real\" } ", `{"api_key":"real"}`, credentialUnchanged},
		{"same_value", `{"api_key":"real"}`, `{"api_key":"real"}`, credentialUnchanged},
		{"real_change", `{"api_key":"next"}`, `{"api_key":"real"}`, credentialChanged},
		{"nested_reordered_keys", `{"outer":{"b":"2","a":"1"}}`, `{"outer":{"a":"1","b":"2"}}`, credentialUnchanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialAuditStateFor(tc.newValue, tc.oldValue); got != tc.want {
				t.Fatalf("state=%v, want %v", got, tc.want)
			}
		})
	}
}

// Given：ZeroSSL 提供商带真实凭证。When：显式清空凭证。Then：服务层真实
// 落库为空串，审计必须记「凭证（清空）」而非「无修改」。
func TestUpdateCAProvider_clearingCredentialsIsAudited(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('ZeroSSL-clear','zerossl','https://acme.zerossl.com/v2/DV90','{"api_key":"real"}',1,2000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(`{"credentials":""}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("credentials=%q, want 空串（清空已落库）", stored)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='CA提供商' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query CA provider audit: %v", err)
	}
	if !strings.Contains(detail, "凭证（清空）") {
		t.Fatalf("audit detail=%q, want 凭证（清空）", detail)
	}
}

// Given：ZeroSSL 提供商带真实凭证。When：凭证全星号占位回传。Then：服务层
// JSON 门直接 400（全星号不是合法 JSON），凭证不被覆盖——这是真实契约；
// 原测试只断言「未被覆盖」却隐含「服务层可能放行」，把不可达的掩码回传
// 审计态钉成了必须保留的行为。
func TestUpdateCAProvider_allStarCredentialsRejectedByJSONGate(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('ZeroSSL-mask','zerossl','https://acme.zerossl.com/v2/DV90','{"api_key":"real"}',1,2000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(`{"credentials":"****"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（全星号载荷须被 JSON 门拒绝）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "凭证必须是有效的 JSON") {
		t.Fatalf("body=%s, want 凭证必须是有效的 JSON", response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != `{"api_key":"real"}` {
		t.Fatalf("credentials=%q, want 原值保留（400 拒绝不得落库）", stored)
	}
}

// Given：ZeroSSL 提供商凭证 `{"a":"1","b":"2"}`。When：仅重排键序的更新。
// Then：200 且审计记「无修改」——语义相等的载荷不得记成凭证变更。
func TestUpdateCAProvider_keyOrderOnlyChangeIsNotAuditedAsCredentialChange(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('ZeroSSL-order','zerossl','https://acme.zerossl.com/v2/DV90','{"a":"1","b":"2"}',1,2000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(`{"credentials":"{\"b\":\"2\",\"a\":\"1\"}"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='CA提供商' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query CA provider audit: %v", err)
	}
	if !strings.Contains(detail, "无修改") {
		t.Fatalf("audit detail=%q, want 无修改（键序重排不是凭证变更）", detail)
	}
}

// 名称与 DNS 配置同口径归一：首尾空白落库前剥离；纯空白名按空名 400，
// 不得形成列表/选择器里无法辨识的行（API 可绕过前端 trim）。
func TestUpdateCAProvider_trimsName(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('LE-trim','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','',1,2000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	putName := func(name string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(fmt.Sprintf(`{"name":%q}`, name)))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		return response
	}

	if response := putName("  trimmed-name  "); response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT name FROM ca_providers WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "trimmed-name" {
		t.Fatalf("name=%q, want trimmed-name（写入口必须 trim）", stored)
	}

	response := putName("   ")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "名称不能为空") {
		t.Fatalf("status=%d body=%s, want 400 名称不能为空（纯空白必须拒绝）", response.Code, response.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT name FROM ca_providers WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "trimmed-name" {
		t.Fatalf("name=%q, want 保留原名称（纯空白不得落库）", stored)
	}
}

// 更新 CA 提供商的失败面必须留痕：该路由是 Explicit 审计路由（中间件对
// Explicit 既不补记成功也不补记失败），只有 handler 自己记；此前全部失败分支
// 零留痕，运维无法从审计回答「谁试图禁用默认 CA 提供商被挡」。载荷 4xx 属于
// 未进入写入层的请求，不落审计（与同族测试入口口径一致）。
func TestUpdateCAProvider_failureBranchesAreAudited(t *testing.T) {
	newHarness := func(t *testing.T) (*Handlers, *gin.Engine) {
		h := newBackupTestHandlers(t)
		h.caProviderService = services.NewCAProviderService()
		router := gin.New()
		router.PUT("/ca-providers/:id", h.UpdateCAProvider)
		return h, router
	}
	seedProvider := func(t *testing.T) int64 {
		t.Helper()
		res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
			VALUES ('ZeroSSL-audit','zerossl','https://acme.zerossl.com/v2/DV90','{"api_key":"real"}',1,2000,1)`)
		if err != nil {
			t.Fatalf("seed CA provider: %v", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	put := func(t *testing.T, router *gin.Engine, id int64, body string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		return response
	}
	countFailureAudits := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='CA提供商'`).Scan(&n); err != nil {
			t.Fatalf("count CA provider failure audits: %v", err)
		}
		return n
	}

	t.Run("business_reject_409_is_audited", func(t *testing.T) {
		_, router := newHarness(t)
		id := seedProvider(t)
		if _, err := db.DB.Exec(`UPDATE global_config SET default_ca_provider_id=? WHERE id=1`, id); err != nil {
			t.Fatalf("set default CA provider: %v", err)
		}

		response := put(t, router, id, `{"enabled":false}`)

		if response.Code != http.StatusConflict {
			t.Fatalf("status=%d body=%s, want 409（默认 CA 提供商不得禁用）", response.Code, response.Body.String())
		}
		if n := countFailureAudits(t); n != 1 {
			t.Fatalf("更新失败审计条数=%d, want 1", n)
		}
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新失败' AND resource='CA提供商' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("read failure audit: %v", err)
		}
		if !strings.Contains(detail, fmt.Sprintf("提供商 %d", id)) {
			t.Fatalf("审计 detail=%q, want 含提供商 id（否则无法定位被拒对象）", detail)
		}
	})

	t.Run("internal_error_500_is_audited", func(t *testing.T) {
		_, router := newHarness(t)
		id := seedProvider(t)
		// 让服务层的事务内查询失败：表被带外删除（不依赖注入点）。
		if _, err := db.DB.Exec(`DROP TABLE ca_providers`); err != nil {
			t.Fatalf("drop ca_providers: %v", err)
		}

		response := put(t, router, id, `{"name":"after"}`)

		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
		}
		if n := countFailureAudits(t); n != 1 {
			t.Fatalf("更新失败审计条数=%d, want 1", n)
		}
	})

	t.Run("payload_4xx_is_not_audited", func(t *testing.T) {
		_, router := newHarness(t)
		id := seedProvider(t)

		response := put(t, router, id, `{"provider":"bogus"}`)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400（非法提供商类型）", response.Code, response.Body.String())
		}
		if n := countFailureAudits(t); n != 0 {
			t.Fatalf("更新失败审计条数=%d, want 0（载荷 4xx 未进入写入层）", n)
		}
	})
}
