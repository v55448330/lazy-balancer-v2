package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 源开关写路径必须把读前值/更新/行数校验放在同一事务语义内，并只在
// 「关闭→启用」真实变更时武装首槽：0 行更新不得回 200 假成功。
func TestUpdateLibSourceFlags_rowsAffectedAndArmGate(t *testing.T) {
	t.Run("0 行更新返回 404 且不武装首槽", func(t *testing.T) {
		router, armed := newLibSourceFlagsTestRouter(t)
		seedCrawlerSource(t, 71, "并发删除", 1)
		if _, err := db.DB.Exec(`CREATE TRIGGER discard_crawler_flag_update
			BEFORE UPDATE ON security_crawler_sources
			WHEN OLD.update_enabled = NEW.update_enabled
			BEGIN SELECT RAISE(IGNORE); END`); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
		if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1 WHERE id=71`); err != nil {
			t.Fatal(err)
		}
		response := putLibSourceFlag(t, router, 71, true)
		if response.Code != http.StatusNotFound {
			t.Fatalf("0 行更新 status=%d body=%s, want 404（行已消失，不得假成功）", response.Code, response.Body.String())
		}
		if *armed != 0 {
			t.Fatalf("0 行更新后武装首槽 %d 次, want 0", *armed)
		}
	})

	t.Run("已启用重复提交不武装首槽", func(t *testing.T) {
		router, armed := newLibSourceFlagsTestRouter(t)
		seedCrawlerSource(t, 72, "已启用", 1)
		if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1 WHERE id=72`); err != nil {
			t.Fatal(err)
		}
		response := putLibSourceFlag(t, router, 72, true)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if *armed != 0 {
			t.Fatalf("已启用重复提交武装首槽 %d 次, want 0（仅关闭→启用变更才武装）", *armed)
		}
	})

	t.Run("关闭→启用武装首槽一次", func(t *testing.T) {
		router, armed := newLibSourceFlagsTestRouter(t)
		seedCrawlerSource(t, 73, "待启用", 1)
		if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0 WHERE id=73`); err != nil {
			t.Fatal(err)
		}
		response := putLibSourceFlag(t, router, 73, true)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		if *armed != 1 {
			t.Fatalf("关闭→启用武装首槽 %d 次, want 1", *armed)
		}
	})
}

func newLibSourceFlagsTestRouter(t *testing.T) (*gin.Engine, *int) {
	t.Helper()
	newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	armed := 0
	router := gin.New()
	router.PUT("/sources/:id/flags", func(c *gin.Context) {
		updateLibSourceFlags(c, libSourceFlagsSpec{
			Table:        "security_crawler_sources",
			Family:       "爬虫地址库",
			NotFoundMsg:  "爬虫源不存在",
			ReadErrMsg:   "读取失败",
			UpdateErrMsg: "更新失败",
			ArmFirstSlots: func() {
				armed++
			},
			InternalError: func(message string, err error) models.APIResponse {
				return models.APIResponse{Code: http.StatusInternalServerError, Message: message + ": " + err.Error()}
			},
		})
	})
	return router, &armed
}

func putLibSourceFlag(t *testing.T, router *gin.Engine, id int, enabled bool) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/sources/%d/flags", id), strings.NewReader(fmt.Sprintf(`{"update_enabled":%t}`, enabled)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	return response
}
