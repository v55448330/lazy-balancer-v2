package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 设置保存 / 导入结果 / 日志存储条的用户可见文案走 apimsg 词条。
//
// 2026-11-25 项目所有者裁定（web/docs/I18N.md 第 0 节）：后端只下发稳定键 + 参数，
// 文案只归前端。因此本文件的判据是「同一请求带 zh-CN 与 en 的响应体逐字相同，
// 且内容为中文母本」——后端不存在按请求语言渲染的分支。

// languageRouter 装上测试上下文（可预置操作者用户名）。
// 名称沿用旧布局：Accept-Language 头仍可发送，但生产链路不再读取它——本组用例
// 正是用「带不同头得到同一份响应」来钉住这一点。
func languageRouter(username string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if username != "" {
			c.Set("username", username)
		}
	})
	return router
}

func TestUpdateConfig_successMessageIsLanguageIndependentChineseMother(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"仅落库", `{"source":"basic","jwt_expire_minutes":25}`, "配置已更新"},
		{"已应用", `{"source":"caddy","caddy_log_level":"warn"}`, "配置已更新并应用"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var bodies []string
			for _, lang := range []string{"zh-CN", "en"} {
				h := newBackupTestHandlers(t)
				router := languageRouter("")
				router.PUT("/config", h.UpdateConfig)
				req := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept-Language", lang)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s status=%d body=%s, want 200", lang, rec.Code, rec.Body.String())
				}
				bodies = append(bodies, rec.Body.String())
			}
			if normalizeVolatile(bodies[0]) != normalizeVolatile(bodies[1]) {
				t.Fatalf("响应体随 Accept-Language 变化:\n zh: %s\n en: %s", bodies[0], bodies[1])
			}
			var resp struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal([]byte(bodies[0]), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Message != tc.want {
				t.Fatalf("message=%q, want 中文母本 %q", resp.Message, tc.want)
			}
		})
	}
}

func TestImportConfigBackup_operatorReplacedWarningIsLanguageIndependent(t *testing.T) {
	const want = "备份不含当前操作账户——系统数据已替换，请使用备份内的管理员账户登录"
	var bodies []string
	for _, lang := range []string{"zh-CN", "en"} {
		h := newAutoBackupTestHandlers(t)
		// 备份内的管理员是 backup-admin：操作者 current-admin 不在其中。
		router := languageRouter("current-admin")
		router.POST("/config/import", h.ImportConfigBackup)
		req := httptest.NewRequest(http.MethodPost, "/config/import",
			strings.NewReader(buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true})))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept-Language", lang)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s, want 200", lang, rec.Code, rec.Body.String())
		}
		warnings := decodeImportWarnings(t, rec)
		if !warningsContain(warnings, want) {
			t.Fatalf("%s 下 warnings 缺少中文母本 %q: %v", lang, want, warnings)
		}
		bodies = append(bodies, rec.Body.String())
	}
	if normalizeVolatile(bodies[0]) != normalizeVolatile(bodies[1]) {
		t.Fatalf("响应体随 Accept-Language 变化:\n zh: %s\n en: %s", bodies[0], bodies[1])
	}
}

func TestGetLogStats_governanceNotesAreLanguageIndependent(t *testing.T) {
	type row struct {
		Key           string `json:"key"`
		RetentionNote string `json:"retention_note"`
		ConfigSource  string `json:"config_source"`
	}
	h := newBackupTestHandlers(t)
	router := languageRouter("")
	router.GET("/logs/stats", h.GetLogStats)
	var bodies []string
	for _, lang := range []string{"zh-CN", "en"} {
		req := httptest.NewRequest(http.MethodGet, "/logs/stats", nil)
		req.Header.Set("Accept-Language", lang)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s, want 200", lang, rec.Code, rec.Body.String())
		}
		bodies = append(bodies, rec.Body.String())
	}
	if normalizeVolatile(bodies[0]) != normalizeVolatile(bodies[1]) {
		t.Fatalf("响应体随 Accept-Language 变化:\n zh: %s\n en: %s", bodies[0], bodies[1])
	}
	var resp struct {
		Data struct {
			Logs []row `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &resp); err != nil {
		t.Fatal(err)
	}
	byKey := map[string]row{}
	for _, r := range resp.Data.Logs {
		byKey[r.Key] = r
	}
	wantSource := map[string]string{
		"audit":      "基础设置 · 日志保留（操作/运行/安全事件）",
		"certjob":    "基础设置 · 任务日志大小",
		"crs_update": "统一任务日志（tasks/crs.log）",
		"runtime":    "基础设置 · 运行日志大小",
		"caddy_tls":  "Caddy 全局配置 · 日志大小",
	}
	for key, want := range wantSource {
		if got := byKey[key].ConfigSource; got != want {
			t.Errorf("%s config_source=%q, want 中文母本 %q", key, got, want)
		}
	}
	wantAuditNote := fmt.Sprintf("每日清理 · 保留 %d 个月", db.DefaultAuditRetentionMonths)
	if got := byKey["audit"].RetentionNote; got != wantAuditNote {
		t.Errorf("audit retention_note=%q, want %q", got, wantAuditNote)
	}
	wantRuntimeNote := "时间戳轮转，按保留期清理（份数随保留期）"
	if got := byKey["runtime"].RetentionNote; got != wantRuntimeNote {
		t.Errorf("runtime retention_note=%q, want %q", got, wantRuntimeNote)
	}
}
