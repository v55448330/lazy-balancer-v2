package handlers

// OIDC 自由文本字段上限：保存侧超限 400，公开状态端点对存量坏值按同一预算
// 截断（带外写入的历史值可能是任意长度）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestOIDCSettingsUpdate_rejectsOversizedFreeTextFields(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	cases := []struct {
		name string
		body string
	}{
		{"display_name", `{"display_name":"` + strings.Repeat("长", oidcDisplayNameMaxRunes+1) + `"}`},
		{"client_id", `{"client_id":"` + strings.Repeat("c", 256) + `"}`},
		{"issuer", `{"issuer":"https://` + strings.Repeat("a", 512) + `"}`},
		{"client_secret", `{"client_secret":"` + strings.Repeat("s", 513) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "过长") {
				t.Fatalf("message=%s, want 超限友好文案", rec.Body.String())
			}
		})
	}

	// 边界内照常保存（30 字符展示名 = 前端 maxlength 上限）。
	body := `{"display_name":"` + strings.Repeat("长", oidcDisplayNameMaxRunes) + `"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（上限值本身合法）", rec.Code, rec.Body.String())
	}
}

// OIDC 访问白名单的条目数与单项长度预算：名单整块落进 global_config 单列、
// 随集群快照搬运，每次 OIDC 回调按 len(AllowedGroups)×len(claims.Groups)
// 线性扫描——无上限时一次误粘贴就能把回调路径放大成 O(n×m)（与 api key
// 白名单 256 上限同族）。数值 100 条 / 128 rune 为审计建议值。
func TestOIDCSettingsUpdate_rejectsOversizedAllowLists(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	groupList := func(n int) string {
		items := make([]string, 0, n)
		for i := range n {
			items = append(items, fmt.Sprintf(`"g%03d"`, i))
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	domainList := func(n int) string {
		items := make([]string, 0, n)
		for i := range n {
			items = append(items, fmt.Sprintf(`"d%03d.example.com"`, i))
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	cases := []struct {
		name string
		body string
		want string
	}{
		{"allowed_email_domains 条目数超限", `{"allowed_email_domains":` + domainList(oidcAllowListMaxEntries+1) + `}`, "允许的 email 域"},
		{"allowed_groups 条目数超限", `{"allowed_groups":` + groupList(oidcAllowListMaxEntries+1) + `}`, "允许的组"},
		{"allowed_email_domains 单项超长", `{"allowed_email_domains":["` + strings.Repeat("a", oidcAllowListEntryMaxRunes) + `.com"]}`, "允许的 email 域"},
		{"allowed_groups 单项超长", `{"allowed_groups":["` + strings.Repeat("g", oidcAllowListEntryMaxRunes+1) + `"]}`, "允许的组"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("message=%s, want 点名 %q", rec.Body.String(), tc.want)
			}
		})
	}

	// 边界值本身合法：100 条 + 单项恰好 128 rune 必须落库成功。
	boundaryDomain := strings.Repeat("b", oidcAllowListEntryMaxRunes-4) + ".com" // 恰 128 rune
	body := `{"allowed_email_domains":` + domainList(oidcAllowListMaxEntries) +
		`,"allowed_groups":["` + strings.Repeat("g", oidcAllowListEntryMaxRunes) + `","` + boundaryDomain + `"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（边界值本身合法）", rec.Code, rec.Body.String())
	}
}

// 已落库的超限旧值（带外写入/历史版本）读侧必须照常工作——写侧上限不得把
// 存量配置变成 500/panic（读侧只做逐条比较，不施加上限）。
func TestOIDCStatus_toleratesOversizedStoredAllowLists(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	legacyGroups := make([]string, 0, oidcAllowListMaxEntries*3)
	for i := range oidcAllowListMaxEntries * 3 {
		legacyGroups = append(legacyGroups, fmt.Sprintf("legacy-group-%03d", i))
	}
	if err := saveOIDCConfig(OIDCConfig{
		Enabled: true, Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "sec",
		AllowedGroups:       legacyGroups,
		AllowedEmailDomains: []string{strings.Repeat("a", oidcAllowListEntryMaxRunes) + ".com"},
	}); err != nil {
		t.Fatalf("seed stored config: %v", err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s, want 200（存量超限值不得让读侧失败）", rec.Code, rec.Body.String())
	}

	cfg, err := loadOIDCConfig()
	if err != nil {
		t.Fatalf("load stored config: %v", err)
	}
	if allowed, reason := oidcAccessAllowed(cfg, oidcAccessClaims{Groups: []string{"nobody"}}); allowed {
		t.Fatalf("超限存量组名单下不得放行未知组（reason=%s）", reason)
	}
}

func TestOIDCStatus_truncatesOversizedStoredDisplayName(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	oversized := strings.Repeat("x", 100000)
	if err := saveOIDCConfig(OIDCConfig{
		Enabled: true, Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "sec",
		DisplayName: oversized,
	}); err != nil {
		t.Fatalf("seed stored config: %v", err)
	}
	// 前置：坏值确实落库（不是被写侧悄悄拦住）。
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read stored config: %v", err)
	}
	if !strings.Contains(stored, oversized) {
		t.Fatal("fixture 未真正写入超长展示名")
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() >= 1024 {
		t.Fatalf("公开响应体 %d 字节，want <1KB（展示名须截断）", rec.Body.Len())
	}
	var resp struct {
		Data struct {
			Enabled     bool   `json:"enabled"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !resp.Data.Enabled {
		t.Fatal("合规 issuer 应保持 enabled=true")
	}
	if runes := []rune(resp.Data.DisplayName); len(runes) > oidcDisplayNameMaxRunes {
		t.Fatalf("display_name %d 字符，want ≤%d", len(runes), oidcDisplayNameMaxRunes)
	}
}
