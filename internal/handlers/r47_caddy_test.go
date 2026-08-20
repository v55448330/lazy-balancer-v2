package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R47 B-5: v2 备份导入此前原样恢复 security_policies 的 crs_rule_groups /
// crs_excluded_rules，绕过保存侧 validateAndNormalizeCRSField——旧版备份中的
// "941" 式组号（应为两位 "41"）落库后 REQUEST-9<code>-*.conf glob 零匹配，
// blocking 模式静默无任何 CRS 规则生效。导入/预览须按同口径拒绝并点名策略。
func TestImportConfigBackup_rejects_invalid_crs_rule_groups_in_security_policy(t *testing.T) {
	tests := []struct {
		name       string
		groups     string
		exclusions string
		wantReject bool
	}{
		{name: "三位数组号", groups: `["941"]`, exclusions: "[]", wantReject: true},
		{name: "组号含非法字符", groups: `["42\"x"]`, exclusions: "[]", wantReject: true},
		{name: "排除项含空白", groups: `["42"]`, exclusions: `["base rule"]`, wantReject: true},
		{name: "非数组 JSON", groups: `"42"`, exclusions: "[]", wantReject: true},
		{name: "合法组号与排除项", groups: `["42","43"]`, exclusions: `["942100"]`, wantReject: false},
		{name: "空串归一为 []", groups: ``, exclusions: ``, wantReject: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given 一个 security_policies 携带指定 crs 字段的完整 v2 备份
			h := newBackupTestHandlers(t)
			gin.SetMode(gin.TestMode)
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"security_policies": {{
					"id": 1, "name": "crs-legacy-policy", "mode": "blocking",
					"crs_rule_groups": tt.groups, "crs_excluded_rules": tt.exclusions,
				}},
			})
			router := gin.New()
			router.POST("/config/import", h.ImportConfigBackup)
			request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if tt.wantReject {
				if response.Code != http.StatusBadRequest {
					t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
				}
				if !strings.Contains(response.Body.String(), "crs-legacy-policy") {
					t.Fatalf("rejection must name the policy: %s", response.Body.String())
				}
				var count int
				if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE name='crs-legacy-policy'").Scan(&count); err != nil {
					t.Fatalf("read imported policy: %v", err)
				}
				if count != 0 {
					t.Fatalf("rejected backup must not persist the policy, got %d rows", count)
				}
				return
			}
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var groups, exclusions string
			if err := db.DB.QueryRow("SELECT crs_rule_groups, crs_excluded_rules FROM security_policies WHERE name='crs-legacy-policy'").Scan(&groups, &exclusions); err != nil {
				t.Fatalf("read imported policy: %v", err)
			}
			wantGroups := tt.groups
			if wantGroups == "" {
				wantGroups = "[]"
			}
			if groups != wantGroups {
				t.Fatalf("imported crs_rule_groups=%q, want %q", groups, wantGroups)
			}
		})
	}
}
