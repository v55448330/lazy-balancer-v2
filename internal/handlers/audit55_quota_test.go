package handlers

// 第 55 轮 P5-8 RED（用户裁定按建议处理）：API Key 创建无数量配额——普通用户
// 可经 POST /users/me/api-keys 无界增长 api_keys 表。修复后每用户上限 50。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCreateCurrentUserAPIKey_quotaFiftyPerUser(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	// Given：alice 已有 49 个 Key（含种子 1 个，补 48 个）——第 50 个创建可达边界
	for i := 2; i <= 49; i++ {
		if _, err := database.Exec(`INSERT INTO api_keys (id, name, key_hash, key_prefix, created_by, is_enabled) VALUES (?, ?, ?, ?, 1, 1)`, 100+i, fmt.Sprintf("k%d", i), fmt.Sprintf("h%d", i), fmt.Sprintf("p%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	create := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Set("user_id", 1)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"new-key"}`))
		ctx.Request.Header.Set("Content-Type", "application/json")
		createAPIKeyForUser(ctx, 1)
		return recorder
	}

	// 第 50 个：仍允许
	if r := create(); r.Code != http.StatusCreated {
		t.Fatalf("第 50 个 status=%d body=%s, want 201（边界内不误伤）", r.Code, r.Body.String())
	}

	// 第 51 个：400 配额拒绝
	r := create()
	if r.Code != http.StatusBadRequest {
		t.Fatalf("第 51 个 status=%d body=%s, want 400（每用户配额 50）", r.Code, r.Body.String())
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE created_by=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 50 {
		t.Fatalf("api_keys count=%d, want 50（拒绝后不得落库）", count)
	}
}
