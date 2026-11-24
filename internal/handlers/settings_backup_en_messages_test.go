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
	"lazy-balancer-v2/internal/i18n"
)

// 设置保存 / 导入结果 / 日志存储条的用户可见文案走 apimsg 词条：英文界面
// （Accept-Language: en）不得混入中文母本，中文界面文案保持不变。

// languageRouter 装上与中间件同口径的语言协商，并可预置操作者用户名。
func languageRouter(username string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(i18n.CtxLangKey, i18n.Negotiate(c.GetHeader("Accept-Language")))
		if username != "" {
			c.Set("username", username)
		}
	})
	return router
}

// pick 按语言取期望文案（en 译文 / zh 母本）。
func pick(lang, enText, zhText string) string {
	if lang == "en" {
		return enText
	}
	return zhText
}

func TestUpdateConfig_successMessageFollowsLanguage(t *testing.T) {
	cases := []struct {
		name, lang, body, want string
	}{
		{"仅落库 zh", "zh-CN", `{"source":"basic","jwt_expire_minutes":25}`, "配置已更新"},
		{"仅落库 en", "en", `{"source":"basic","jwt_expire_minutes":26}`, "Configuration updated"},
		{"已应用 en", "en", `{"source":"caddy","caddy_log_level":"warn"}`, "Configuration updated and applied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			router := languageRouter("")
			router.PUT("/config", h.UpdateConfig)
			req := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Language", tc.lang)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
			}
			var resp struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Message != tc.want {
				t.Fatalf("message=%q, want %q", resp.Message, tc.want)
			}
		})
	}
}

func TestImportConfigBackup_operatorReplacedWarningFollowsLanguage(t *testing.T) {
	cases := []struct {
		name, lang, want string
	}{
		{"zh", "zh-CN", "备份不含当前操作账户——系统数据已替换，请使用备份内的管理员账户登录"},
		{"en", "en", "The backup does not contain the current account — system data was replaced, so sign in with an administrator account from the backup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAutoBackupTestHandlers(t)
			// 备份内的管理员是 backup-admin：操作者 current-admin 不在其中。
			router := languageRouter("current-admin")
			router.POST("/config/import", h.ImportConfigBackup)
			req := httptest.NewRequest(http.MethodPost, "/config/import",
				strings.NewReader(buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true})))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Language", tc.lang)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
			}
			warnings := decodeImportWarnings(t, rec)
			if !warningsContain(warnings, tc.want) {
				t.Fatalf("%s 下 warnings 缺少 %q: %v", tc.lang, tc.want, warnings)
			}
		})
	}
}

func TestGetLogStats_governanceNotesFollowLanguage(t *testing.T) {
	type row struct {
		Key           string `json:"key"`
		RetentionNote string `json:"retention_note"`
		ConfigSource  string `json:"config_source"`
	}
	for _, lang := range []string{"zh-CN", "en"} {
		t.Run(lang, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			router := languageRouter("")
			router.GET("/logs/stats", h.GetLogStats)
			req := httptest.NewRequest(http.MethodGet, "/logs/stats", nil)
			req.Header.Set("Accept-Language", lang)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
			}
			var resp struct {
				Data struct {
					Logs []row `json:"logs"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			byKey := map[string]row{}
			for _, r := range resp.Data.Logs {
				byKey[r.Key] = r
			}
			wantSource := map[string]string{
				"audit":      pick(lang, "Basic settings · log retention (operations/runtime/security events)", "基础设置 · 日志保留（操作/运行/安全事件）"),
				"certjob":    pick(lang, "Basic settings · task log size", "基础设置 · 任务日志大小"),
				"crs_update": pick(lang, "Unified task log (tasks/crs.log)", "统一任务日志（tasks/crs.log）"),
				"runtime":    pick(lang, "Basic settings · runtime log size", "基础设置 · 运行日志大小"),
				"caddy_tls":  pick(lang, "Caddy global settings · log size", "Caddy 全局配置 · 日志大小"),
			}
			for key, want := range wantSource {
				if got := byKey[key].ConfigSource; got != want {
					t.Errorf("%s config_source=%q, want %q", key, got, want)
				}
			}
			wantAuditNote := pick(lang,
				fmt.Sprintf("Cleaned daily · keep %d months", db.DefaultAuditRetentionMonths),
				fmt.Sprintf("每日清理 · 保留 %d 个月", db.DefaultAuditRetentionMonths))
			if got := byKey["audit"].RetentionNote; got != wantAuditNote {
				t.Errorf("audit retention_note=%q, want %q", got, wantAuditNote)
			}
			wantRuntimeNote := pick(lang, "Timestamp rotation, pruned by the retention period (copy count follows it)", "时间戳轮转，按保留期清理（份数随保留期）")
			if got := byKey["runtime"].RetentionNote; got != wantRuntimeNote {
				t.Errorf("runtime retention_note=%q, want %q", got, wantRuntimeNote)
			}
		})
	}
}
