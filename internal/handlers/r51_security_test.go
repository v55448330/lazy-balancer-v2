package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R51 B-F1：validateV2BackupSecurityPolicies 此前只归一/校验 crs_rule_groups 与
// crs_excluded_rules，ip_acl_mode/mode/geoip_mode 经 restoreTable 原样落库。
// R50 前的旧备份合法携带空串（旧 Create 不归一、列默认 TEXT DEFAULT ”），导入后
// 重现零强制状态：发射端仅 bypass/allow/deny 分支产出 ACL 规则，"" 零产出，而
// UI 仍宣称 IP 访问控制已启用（mode/geoip_mode 空串同型漂移：汇总计数与发射行为
// 分裂、地域控制静默失效）。导入侧必须与 Create 侧同口径归一/校验：
// ip_acl_mode 空→"deny"、mode 空→"off"、geoip_mode 空→"deny"，非法值拒绝并点名策略。
func TestImportConfigBackup_normalizes_empty_security_policy_enum_fields(t *testing.T) {
	tests := []struct {
		name          string
		row           map[string]any
		wantMode      string
		wantIPACLMode string
		wantGeoIPMode string
	}{
		{
			name:          "全部空串归一",
			row:           map[string]any{"id": 1, "name": "empty-enums", "mode": "", "ip_acl_mode": "", "geoip_mode": ""},
			wantMode:      "off",
			wantIPACLMode: "deny",
			wantGeoIPMode: "deny",
		},
		{
			name:          "null 与缺省归一",
			row:           map[string]any{"id": 1, "name": "null-enums", "mode": nil, "ip_acl_mode": nil},
			wantMode:      "off",
			wantIPACLMode: "deny",
			wantGeoIPMode: "deny",
		},
		{
			name:          "合法值原样保留",
			row:           map[string]any{"id": 1, "name": "valid-enums", "mode": "blocking", "ip_acl_mode": "bypass", "geoip_mode": "allow"},
			wantMode:      "blocking",
			wantIPACLMode: "bypass",
			wantGeoIPMode: "allow",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given 一个 security_policies 携带空/null/缺省枚举字段的完整 v2 备份
			h := newBackupTestHandlers(t)
			gin.SetMode(gin.TestMode)
			backup := completeBackupJSON(t, map[string][]map[string]any{"security_policies": {tt.row}})
			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then：导入成功，三个枚举字段按 Create 侧口径归一落库
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var gotMode, gotIPACLMode, gotGeoIPMode string
			if err := db.DB.QueryRow("SELECT mode, ip_acl_mode, geoip_mode FROM security_policies WHERE id=1").
				Scan(&gotMode, &gotIPACLMode, &gotGeoIPMode); err != nil {
				t.Fatalf("read imported policy: %v", err)
			}
			if gotMode != tt.wantMode || gotIPACLMode != tt.wantIPACLMode || gotGeoIPMode != tt.wantGeoIPMode {
				t.Fatalf("imported enums=(%q,%q,%q), want (%q,%q,%q)",
					gotMode, gotIPACLMode, gotGeoIPMode, tt.wantMode, tt.wantIPACLMode, tt.wantGeoIPMode)
			}
		})
	}
}

func TestImportConfigBackup_rejects_invalid_security_policy_enum_fields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value any
	}{
		{name: "非法 ip_acl_mode", field: "ip_acl_mode", value: "drop"},
		{name: "非法 mode", field: "mode", value: "audit"},
		{name: "非法 geoip_mode", field: "geoip_mode", value: "block"},
		{name: "非字符串 ip_acl_mode", field: "ip_acl_mode", value: 123},
		{name: "非字符串 mode", field: "mode", value: true},
		{name: "非字符串 geoip_mode", field: "geoip_mode", value: []any{"deny"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given 一个 security_policies 携带非法枚举值的完整 v2 备份
			h := newBackupTestHandlers(t)
			gin.SetMode(gin.TestMode)
			row := map[string]any{"id": 1, "name": "bad-enum-policy", "mode": "detection"}
			row[tt.field] = tt.value
			backup := completeBackupJSON(t, map[string][]map[string]any{"security_policies": {row}})
			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then：整包 400 拒绝并点名策略，且零写入（策略未落库）
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "bad-enum-policy") {
				t.Fatalf("response missing policy name: %s", response.Body.String())
			}
			var count int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE name='bad-enum-policy'").Scan(&count); err != nil {
				t.Fatalf("count imported policies: %v", err)
			}
			if count != 0 {
				t.Fatalf("rejected backup still persisted %d policy rows, want 0", count)
			}
		})
	}
}
