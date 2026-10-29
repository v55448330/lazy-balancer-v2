package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func apiKeyWhitelistEntries(count int) []string {
	entries := make([]string, count)
	for i := range entries {
		entries[i] = fmt.Sprintf("10.%d.%d.1", i/256, i%256)
	}
	return entries
}

func serveAPIKeyWhitelistMutation(t *testing.T, method, path string, whitelist []string) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"name":             "bounded-whitelist",
		"mcp_ip_whitelist": whitelist,
	})
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, path, strings.NewReader(string(payload)))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")
	h := &Handlers{}
	if method == http.MethodPost {
		h.CreateCurrentUserAPIKey(ctx)
	} else {
		ctx.Params = gin.Params{{Key: "id", Value: "10"}}
		h.UpdateCurrentUserAPIKeyStatus(ctx)
	}
	return recorder
}

func TestAPIKeyWhitelist_rejectsExcessiveEntriesBeforePersistence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "create", method: http.MethodPost, path: "/api/v1/users/me/api-keys"},
		{name: "update", method: http.MethodPatch, path: "/api/v1/users/me/api-keys/10/status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given 257 条合法且互不重复的白名单条目，超过单 Key 上限。
			database := setupAPIKeyTestDB(t)
			var before string
			if tc.method == http.MethodPatch {
				if err := database.QueryRow(`SELECT mcp_ip_whitelist FROM api_keys WHERE id=10`).Scan(&before); err != nil {
					t.Fatal(err)
				}
			}

			// When 提交超限白名单。
			recorder := serveAPIKeyWhitelistMutation(t, tc.method, tc.path, apiKeyWhitelistEntries(257))

			// Then 400 点名上限，且创建/更新均未落库。
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "256") {
				t.Fatalf("status=%d body=%s, want 400 and limit 256", recorder.Code, recorder.Body.String())
			}
			if tc.method == http.MethodPost {
				var count int
				if err := database.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE name='bounded-whitelist'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("over-limit create persisted %d rows", count)
				}
			} else {
				var after string
				if err := database.QueryRow(`SELECT mcp_ip_whitelist FROM api_keys WHERE id=10`).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if after != before {
					t.Fatalf("over-limit update changed whitelist from %q to %q", before, after)
				}
			}
		})
	}
}

func TestAPIKeyWhitelist_acceptsLimitBoundary(t *testing.T) {
	// Given 恰好 256 条合法条目。
	setupAPIKeyTestDB(t)

	// When 创建边界形状的 Key。
	recorder := serveAPIKeyWhitelistMutation(t, http.MethodPost, "/api/v1/users/me/api-keys", apiKeyWhitelistEntries(256))

	// Then 边界值正常落库，未被上限误伤。
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", recorder.Code, recorder.Body.String())
	}
}

func TestImportedAPIKeyWhitelist_rejectsExcessiveEntries(t *testing.T) {
	// Given 备份中一个 Key 携带 257 条合法 CIDR。
	encoded, err := json.Marshal(apiKeyWhitelistEntries(257))
	if err != nil {
		t.Fatal(err)
	}

	// When 执行与预览/导入共用的行级校验。
	err = validateV2BackupMCPIPWhitelist([]map[string]any{{"mcp_ip_whitelist": string(encoded)}})

	// Then 整包拒绝并点名条目上限，不把超限形状写入库中。
	if err == nil || !strings.Contains(err.Error(), "256") {
		t.Fatalf("validation error=%v, want whitelist limit 256", err)
	}
}
