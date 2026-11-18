package handlers

// API Key 列表的行级健壮性：布尔列可空（带外写入/历史数据）不得让整张列表
// 500；单行白名单 JSON 损坏只降级该行。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestListAPIKeys_survivesNullBooleanColumns(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec(`UPDATE api_keys
		SET is_enabled=NULL, mcp_enabled=NULL, read_only=NULL WHERE id=10`); err != nil {
		t.Fatalf("null out boolean columns: %v", err)
	}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	ctx.Set("role", "admin")
	ctx.Set("user_id", int64(1))

	(&Handlers{}).ListAPIKeys(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（NULL 布尔列不得整表 500）", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data []struct {
			ID         int  `json:"id"`
			IsEnabled  bool `json:"is_enabled"`
			MCPEnabled bool `json:"mcp_enabled"`
			ReadOnly   bool `json:"read_only"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var found bool
	for _, key := range body.Data {
		if key.ID != 10 {
			continue
		}
		found = true
		// 列表显示与鉴权判定有意不同：列表把 NULL 按启用展示（缺省即启用），
		// 鉴权侧对 NULL fail-closed（401）。不得为「统一口径」而放行脏行——
		// 两侧语义由 apikey_enabled_null_test.go 分别钉住。
		if !key.IsEnabled || key.MCPEnabled || key.ReadOnly {
			t.Fatalf("key=%+v, want is_enabled=true/mcp=false/read_only=false", key)
		}
	}
	if !found {
		t.Fatal("NULL 列行丢失")
	}
}

func TestListCurrentUserAPIKeys_degradesCorruptedWhitelist(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec(`UPDATE api_keys SET mcp_ip_whitelist='not-json' WHERE id=10`); err != nil {
		t.Fatalf("corrupt whitelist: %v", err)
	}
	buf := captureLog(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/users/me/api-keys", nil)
	ctx.Set("user_id", 1)

	(&Handlers{}).ListCurrentUserAPIKeys(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（坏行降级不整表 500）", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data []struct {
			ID             int      `json:"id"`
			MCPIPWhitelist []string `json:"mcp_ip_whitelist"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data) != 1 || body.Data[0].ID != 10 {
		t.Fatalf("unexpected keys: %+v", body.Data)
	}
	if len(body.Data[0].MCPIPWhitelist) != 0 {
		t.Fatalf("whitelist=%v, want 空数组/不限制", body.Data[0].MCPIPWhitelist)
	}
	if buf.Len() == 0 {
		t.Fatal("坏值降级必须 warn 留痕，便于排查带外写入")
	}
}
