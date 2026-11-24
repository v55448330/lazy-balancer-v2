package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 受信代理开关明确关闭时，网段/引用名单/请求头三字段没有意义：保存与备份导入
// 两条路径都把它们归一为空数组落库，且不再校验引用名单是否存在——关闭状态下
// 残留的引用可能已指向被删除的名单，照常校验会让保存与还原恒报「受信代理引用
// 的地址列表不存在」。开关开启、或请求未带开关时照常严格校验。

// trustedProxyRelatedFields 三字段载荷（引用 id 由调用方格式化）。
const trustedProxyRelatedFields = `"trusted_proxy_ranges":"[\"203.0.113.0/24\"]","trusted_proxy_range_refs":"[%d]","trusted_proxy_headers":"[\"CF-Connecting-IP\"]"`

type trustedProxyRow struct {
	enabled int
	ranges  string
	refs    string
	headers string
}

// clearedTrustedProxyRow 关闭态落库形态：开关 0，三字段均为空数组。
var clearedTrustedProxyRow = trustedProxyRow{ranges: "[]", refs: "[]", headers: "[]"}

func assertTrustedProxyRow(t *testing.T, want trustedProxyRow) {
	t.Helper()
	var got trustedProxyRow
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_enabled,0), COALESCE(trusted_proxy_ranges,'[]'), COALESCE(trusted_proxy_range_refs,'[]'), COALESCE(trusted_proxy_headers,'[]') FROM global_config WHERE id=1`).
		Scan(&got.enabled, &got.ranges, &got.refs, &got.headers); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("trusted proxy row enabled=%d ranges=%s refs=%s headers=%s, want %+v", got.enabled, got.ranges, got.refs, got.headers, want)
	}
}

func previewConfig(t *testing.T, router http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/config/preview", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestUpdateConfig_trustedProxyDisabledClearsRelatedFields(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	// 存量形态：开启时保存过引用，名单随后被删，库里留下悬空引用。
	staleListID := seedTrustedRefList(t, "deleted-ref-list", `[{"value":"198.51.100.0/24","remark":""}]`)
	if rec := putConfig(t, router, fmt.Sprintf(`{"source":"caddy","trusted_proxy_enabled":true,`+trustedProxyRelatedFields+`}`, staleListID)); rec.Code != http.StatusOK {
		t.Fatalf("seed status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if _, err := db.DB.Exec(`DELETE FROM security_ip_lists WHERE id = ?`, staleListID); err != nil {
		t.Fatal(err)
	}
	stale := fmt.Sprintf(trustedProxyRelatedFields, staleListID)
	validListID := seedTrustedRefList(t, "live-ref-list", `[{"value":"198.51.100.0/24","remark":""}]`)
	valid := fmt.Sprintf(trustedProxyRelatedFields, validListID)

	t.Run("关闭+悬空引用：保存成功且三字段落库为空数组", func(t *testing.T) {
		if rec := putConfig(t, router, `{"source":"caddy","trusted_proxy_enabled":false,`+stale+`}`); rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		assertTrustedProxyRow(t, clearedTrustedProxyRow)
	})

	t.Run("关闭+合法引用：同样清空", func(t *testing.T) {
		if rec := putConfig(t, router, `{"source":"caddy","trusted_proxy_enabled":false,`+valid+`}`); rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		assertTrustedProxyRow(t, clearedTrustedProxyRow)
	})

	t.Run("开启+悬空引用：仍拒绝且不落库", func(t *testing.T) {
		rec := putConfig(t, router, `{"source":"caddy","trusted_proxy_enabled":true,`+stale+`}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不存在") {
			t.Fatalf("status=%d body=%s, want 400 不存在", rec.Code, rec.Body.String())
		}
		assertTrustedProxyRow(t, clearedTrustedProxyRow)
	})

	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{"开关字段缺席", `{"source":"caddy",`},
		{"开关字段为 null", `{"source":"caddy","trusted_proxy_enabled":null,`},
	} {
		t.Run(tc.name+"+悬空引用：仍拒绝", func(t *testing.T) {
			rec := putConfig(t, router, tc.prefix+stale+`}`)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不存在") {
				t.Fatalf("status=%d body=%s, want 400 不存在", rec.Code, rec.Body.String())
			}
			assertTrustedProxyRow(t, clearedTrustedProxyRow)
		})
	}

	t.Run("预览端点同口径：关闭+悬空引用可预览，未带开关仍 400", func(t *testing.T) {
		if rec := previewConfig(t, router, `{"source":"caddy","trusted_proxy_enabled":false,`+stale+`}`); rec.Code != http.StatusOK {
			t.Fatalf("preview status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		if rec := previewConfig(t, router, `{"source":"caddy",`+stale+`}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("preview status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
	})
}

func TestImportConfigBackup_trustedProxyDisabledClearsRelatedFields(t *testing.T) {
	related := map[string]any{
		"trusted_proxy_ranges":     `["203.0.113.0/24"]`,
		"trusted_proxy_range_refs": "[10]",
		"trusted_proxy_headers":    `["CF-Connecting-IP"]`,
	}
	withEnabled := func(enabled any, extra map[string]any) map[string]any {
		config := map[string]any{}
		for key, value := range related {
			config[key] = value
		}
		for key, value := range extra {
			config[key] = value
		}
		if enabled != nil {
			config["trusted_proxy_enabled"] = enabled
		}
		return config
	}

	t.Run("关闭+悬空引用：导入成功且三字段落库为空数组", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		for _, enabled := range []any{false, 0} {
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", configBackupJSON(t, map[string][]map[string]any{}, withEnabled(enabled, nil)))
			if response.Code != http.StatusOK {
				t.Fatalf("enabled=%v status=%d body=%s, want 200", enabled, response.Code, response.Body.String())
			}
			assertTrustedProxyRow(t, clearedTrustedProxyRow)
		}
	})

	t.Run("关闭+合法引用（名单随备份到达）：同样清空", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{
			"security_ip_lists": {{"id": 5, "name": "ref-list", "entries": `[{"value":"198.51.100.0/24","remark":""}]`}},
		}, withEnabled(false, map[string]any{"trusted_proxy_range_refs": "[5]"}))
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		assertTrustedProxyRow(t, clearedTrustedProxyRow)
	})

	t.Run("关闭+备份未携带三字段：库内残留引用随导入清空", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=0, trusted_proxy_ranges='["203.0.113.0/24"]', trusted_proxy_range_refs='[10]', trusted_proxy_headers='["CF-Connecting-IP"]' WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"trusted_proxy_enabled": false}))
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		assertTrustedProxyRow(t, clearedTrustedProxyRow)
	})

	// 只导入名单、不带全局配置：库内引用保持原值并按备份名单复核。开关关闭时
	// 残留引用无意义，不得拦导入；开关开启时仍按原口径拦截。
	for _, tc := range []struct {
		name    string
		enabled int
		wantOK  bool
	}{{"库内开关关闭", 0, true}, {"库内开关开启", 1, false}} {
		t.Run("只导入名单不带全局配置+"+tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=?, trusted_proxy_ranges='[]', trusted_proxy_range_refs='[10]', trusted_proxy_headers='[]' WHERE id=1`, tc.enabled); err != nil {
				t.Fatal(err)
			}
			backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
				"security_ip_lists": {{"id": 5, "name": "ref-list", "entries": `[{"value":"198.51.100.0/24","remark":""}]`}},
			}})
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
			if tc.wantOK {
				if response.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s, want 200（开关关闭时残留引用无意义，不得拦导入）", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不存在") {
				t.Fatalf("status=%d body=%s, want 400 不存在", response.Code, response.Body.String())
			}
			assertZeroWriteShared(t)
		})
	}

	for _, tc := range []struct {
		name    string
		enabled any
	}{
		{"开启", true},
		{"未带开关", nil},
	} {
		t.Run(tc.name+"+悬空引用：仍拒绝且零写入", func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", configBackupJSON(t, map[string][]map[string]any{}, withEnabled(tc.enabled, nil)))
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不存在") {
				t.Fatalf("status=%d body=%s, want 400 不存在", response.Code, response.Body.String())
			}
			assertZeroWriteShared(t)
		})
	}

	t.Run("预览同口径：关闭可导入，开启/未带开关不可导入", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		for _, tc := range []struct {
			enabled any
			valid   bool
		}{{false, true}, {true, false}, {nil, false}} {
			response := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", configBackupJSON(t, map[string][]map[string]any{}, withEnabled(tc.enabled, nil)))
			if response.Code != http.StatusOK {
				t.Fatalf("enabled=%v validate status=%d body=%s, want 200 envelope", tc.enabled, response.Code, response.Body.String())
			}
			want := fmt.Sprintf(`"valid":%v`, tc.valid)
			if !strings.Contains(response.Body.String(), want) {
				t.Fatalf("enabled=%v body=%s, want %s", tc.enabled, response.Body.String(), want)
			}
		}
	})
}
