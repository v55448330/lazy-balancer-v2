package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// UpdateRuleRequest 的值类型字段族（Domain/CompressTypes 等）没有「显式清空」
// 形态：写侧把零值一律当作「未提交」合并存量（见 models.UpdateRuleRequest 的
// 类型注释与 handler 合并块）。以下两条用例钉住该契约的两个代表字段——客户端
// 提交空串既不报错也不清空，库值保持原样；非空提交照常生效。
func TestUpdateRule_emptyValueFieldsKeepStoredValues(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	put := func(caddyID, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("compress_types", func(t *testing.T) {
		// Given：compress_types 非默认的 HTTP 规则
		seedAuditRule(t, "lb_keep_compress", "before", "keep-compress.example.test", 19603, true, "manual", false)
		seedAuditUpstream(t, "lb_keep_compress")
		if _, err := db.DB.Exec("UPDATE lb_rules SET compress_types='gzip,zstd' WHERE caddy_id='lb_keep_compress'"); err != nil {
			t.Fatalf("seed compress_types: %v", err)
		}

		// When：显式提交 compress_types:""
		response := put("lb_keep_compress", `{"name":"after","compress_types":""}`)

		// Then：200，压缩族按「未提交」处理（存量值不变）
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200（值类型字段空串=沿用存量，不是非法请求）", response.Code, response.Body.String())
		}
		var compressTypes string
		if err := db.DB.QueryRow("SELECT COALESCE(compress_types,'') FROM lb_rules WHERE caddy_id='lb_keep_compress'").Scan(&compressTypes); err != nil {
			t.Fatalf("read rule: %v", err)
		}
		if compressTypes != "gzip,zstd" {
			t.Fatalf("compress_types=%q, want gzip,zstd（空串不得清空压缩族）", compressTypes)
		}
	})

	t.Run("domain", func(t *testing.T) {
		// Given：域名已存在的 HTTP 规则
		seedAuditRule(t, "lb_keep_domain", "before", "keep-domain.example.test", 19604, true, "manual", false)
		seedAuditUpstream(t, "lb_keep_domain")

		// When：显式提交 domain:"" + 一个新的规则名
		response := put("lb_keep_domain", `{"name":"after","domain":""}`)

		// Then：200，域名按「未提交」处理（HTTP 规则域名必填，空串不清空），
		// 同请求里的非空字段照常生效。
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200（域名空串=沿用存量，不是非法请求）", response.Code, response.Body.String())
		}
		var name, domain string
		if err := db.DB.QueryRow("SELECT name, COALESCE(domain,'') FROM lb_rules WHERE caddy_id='lb_keep_domain'").Scan(&name, &domain); err != nil {
			t.Fatalf("read rule: %v", err)
		}
		if domain != "keep-domain.example.test" {
			t.Fatalf("domain=%q, want keep-domain.example.test（空串不得清空域名）", domain)
		}
		if name != "after" {
			t.Fatalf("name=%q, want after（非空提交必须生效）", name)
		}
	})
}
