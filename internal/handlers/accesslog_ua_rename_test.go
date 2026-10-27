package handlers

// UA 改名保护门只认精确路径——祖先改名
//（request>headers->hdrs 整树带走，filterencoder.go:466-471 引擎实证）
// 绕过校验，UA 统计静默失效。钉三形状：祖先改名/根改名/精确改名全拒。
// 回归：合法改名（remote_ip→src）与无关改名放行。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestValidateAccessLogFormat_rejectsUARenameIncludingAncestors(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		wantErr string
		// rejectOnly=true 只断言「被拒（错误非空）」，不绑定具体文案：该形状
		// 由另一个门（remote_ip 保护）先行拦截，文案归属不在本用例目标内——
		// 绑定对方门措辞会让本用例以与 UA 无关的原因变红/假绿。
		rejectOnly bool
	}{
		{"祖先 headers 整树改名", "request>headers -> hdrs", "User-Agent", false},
		{"精确 UA 改名", "request>headers>User-Agent -> ua", "User-Agent", false},
		{"根 request 整树改名", "request -> req", "", true},
		{"合法 remote_ip→src 放行", "request>remote_ip -> src", "", false},
		{"合法 uri→uri_path 放行", "request>uri -> uri_path", "", false},
		{"无关字段改名放行", "request>host -> h", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessLogFormat(tc.format)
			if tc.rejectOnly {
				if err == nil {
					t.Fatalf("format %q must be rejected（拒绝成立即可，不绑定具体门文案）", tc.format)
				}
				return
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("format %q must pass, got %v", tc.format, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("format %q must reject with %q, got %v", tc.format, tc.wantErr, err)
			}
		})
	}
}

// 非法行（无 ->、空路径、空动作）保存侧必须 400 并点名行号——
// 旧实现静默跳过，非法行落库后渲染层同样静默跳过，用户以为生效。
func TestValidateAccessLogFormat_rejectsInvalidLinesWithLineNumber(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		wantErr string
	}{
		{"无箭头行", "request>remote_ip -> src\nnot-a-mapping", "第 2 行"},
		{"空路径", " -> delete", "第 1 行"},
		{"空动作", "request>host -> ", "第 1 行"},
		{"首行非法+末行非法", "junk\nrequest>uri -> uri_path\n???", "第 1 行"},
		{"空行不算非法", "\nrequest>remote_ip -> src\n\n", ""},
		{"全合法", "request>remote_ip -> src\nrequest>host -> delete", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessLogFormat(tc.format)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("format %q must pass, got %v", tc.format, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("format %q must reject with %q, got %v", tc.format, tc.wantErr, err)
			}
		})
	}
}

// 保存/预览两侧同口径 400（非法行进校验单源，预览不得给出「可变更」）。
func TestUpdateConfig_accessLogFormatInvalidLine400(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", h.PreviewConfigUpdate)
	router.PUT("/config", h.UpdateConfig)
	post := func(handler gin.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	body := `{"source":"caddy","access_log_format":"request>remote_ip -> src\nnot-a-mapping"}`
	preview := post(h.PreviewConfigUpdate, http.MethodPost, "/config/preview", body)
	if preview.Code != http.StatusBadRequest || !strings.Contains(preview.Body.String(), "第 2 行") {
		t.Fatalf("preview status=%d body=%s, want 400 含行号", preview.Code, preview.Body.String())
	}
	save := post(h.UpdateConfig, http.MethodPut, "/config", body)
	if save.Code != http.StatusBadRequest || !strings.Contains(save.Body.String(), "第 2 行") {
		t.Fatalf("save status=%d body=%s, want 400 含行号", save.Code, save.Body.String())
	}
}

// access_log_json=false 时自定义格式不生效（渲染层仅在 json=true 消费映射）：
// 现状保存成功但运行态零生效（五链断裂、无告警）。写侧口径：
//  1. 同一请求显式携带非空格式且 json=false → 400（不静默丢弃用户输入）；
//  2. json 关闭后的存量残留格式 → 归一清空并在响应披露（不再静默忽略）。
func TestUpdateConfig_accessLogFormatIgnoredWhenJSONDisabled(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	router.POST("/config/preview", h.PreviewConfigUpdate)
	send := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	put := func(body string) *httptest.ResponseRecorder { return send(http.MethodPut, "/config", body) }
	preview := func(body string) *httptest.ResponseRecorder { return send(http.MethodPost, "/config/preview", body) }
	if _, err := db.DB.Exec(`UPDATE global_config SET access_log_json=1, access_log_format='request>host -> h' WHERE id=1`); err != nil {
		t.Fatalf("seed format: %v", err)
	}

	// 显式携带非空格式 + json=false → 400 点名不生效（保存与预览同门）。
	for name, response := range map[string]*httptest.ResponseRecorder{
		"save":    put(`{"access_log_json":false,"access_log_format":"request>host -> h"}`),
		"preview": preview(`{"access_log_json":false,"access_log_format":"request>host -> h"}`),
	} {
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不生效") {
			t.Fatalf("%s：json=false + 非空格式必须 400 点名，status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	// 预览仅关闭 json（不携带格式）→ 200 且变更清单预告「日志格式模板」清空。
	previewed := preview(`{"access_log_json":false}`)
	if previewed.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s, want 200", previewed.Code, previewed.Body.String())
	}
	if !strings.Contains(previewed.Body.String(), "日志格式模板") {
		t.Fatalf("预览必须预告存量格式将被清空，body=%s", previewed.Body.String())
	}

	// 仅关闭 json（不携带格式）→ 归一清空存量格式并披露。
	saved := put(`{"access_log_json":false}`)
	if saved.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", saved.Code, saved.Body.String())
	}
	if !strings.Contains(saved.Body.String(), "自定义格式已清空") {
		t.Fatalf("归一清空必须披露，body=%s", saved.Body.String())
	}
	var storedJSON, storedFormat string
	if err := db.DB.QueryRow(`SELECT COALESCE(access_log_json,1), COALESCE(access_log_format,'') FROM global_config WHERE id=1`).Scan(&storedJSON, &storedFormat); err != nil {
		t.Fatalf("read stored: %v", err)
	}
	if storedJSON != "0" || storedFormat != "" {
		t.Fatalf("落库終态 json=%s format=%q, want 0/空", storedJSON, storedFormat)
	}
}

// access_log_format 是管理员可写的自由多行 DSL（每行 `路径 -> 动作`）：无规模
// 门时超长格式可落库，并按「格式行数 × 启用日志规则数」放大 /load 载荷、LKG/
// 集群快照与变更计划。写侧与规则文本长度门同口径 400 点名（不静默截断）：
// 行数上限 200、总字节上限 16KiB。
func TestUpdateConfig_accessLogFormatSizeLimit(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	router.POST("/config/preview", h.PreviewConfigUpdate)
	send := func(method, path, format string) *httptest.ResponseRecorder {
		payload, err := json.Marshal(map[string]any{"source": "caddy", "access_log_format": format})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		request := httptest.NewRequest(method, path, strings.NewReader(string(payload)))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder
	}
	preview := func(format string) *httptest.ResponseRecorder {
		return send(http.MethodPost, "/config/preview", format)
	}
	// 存量为 JSON 输出开启（默认值），避免跨字段门抢先 400 掩盖规模门。
	if _, err := db.DB.Exec(`UPDATE global_config SET access_log_json=1 WHERE id=1`); err != nil {
		t.Fatalf("seed access_log_json: %v", err)
	}

	// 行数边界：199 行普通映射 + 归一自动补的脱敏行 = 落库 200 行放行；
	// 200 行普通映射归一后 201 行即 400（门认落库值，否则回读再保存会被自己
	// 的门拒绝）；201 行原始串在归一前就超限。
	const line = "request>host -> h"
	joinLines := func(n int) string {
		lines := make([]string, n)
		for i := range lines {
			lines[i] = line
		}
		return strings.Join(lines, "\n")
	}
	if res := preview(joinLines(199)); res.Code != http.StatusOK {
		t.Fatalf("199 行（归一后 200 行）status=%d body=%s, want 200（上限内不得拦截）", res.Code, res.Body.String())
	}
	atCap := joinLines(200)
	if res := preview(atCap); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("200 行（归一后 201 行）preview status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}
	if res := send(http.MethodPut, "/config", atCap); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("200 行（归一后 201 行）save status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}
	over := joinLines(201)
	if res := preview(over); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("201 行 preview status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}
	if res := send(http.MethodPut, "/config", over); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("201 行 save status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}

	// 字节边界：恰好 16KiB（已含规范脱敏行=归一幂等，落库值等于输入）放行，
	// 超 1 字节 400。
	const maxBytes = 16 * 1024
	prefix := "request>host -> "
	exact := prefix + strings.Repeat("a", maxBytes-1-len(accessLogRedactionLine)-len(prefix)) + "\n" + accessLogRedactionLine
	if len(exact) != maxBytes {
		t.Fatalf("夹具长度=%d, want %d", len(exact), maxBytes)
	}
	if normalized := normalizeAccessLogRedaction(exact); normalized != exact {
		t.Fatalf("夹具必须是归一幂等形态（长度 %d→%d）", len(exact), len(normalized))
	}
	if res := preview(exact); res.Code != http.StatusOK {
		t.Fatalf("恰好 16KiB status=%d body=%s, want 200", res.Code, res.Body.String())
	}
	if res := preview(exact + "c"); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "字节") {
		t.Fatalf("16KiB+1 preview status=%d body=%s, want 400 含「字节」", res.Code, res.Body.String())
	}
	if res := send(http.MethodPut, "/config", exact+"c"); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "字节") {
		t.Fatalf("16KiB+1 save status=%d body=%s, want 400 含「字节」", res.Code, res.Body.String())
	}

	// 纯空白格式=「不裁剪原生字段」的语义，但空白串仍是可落库自由串：规模门
	// 必须先于空白短路，否则纯空格/空行超限串可绕过 16KiB/200 行上限落库。
	// 先钉一个已知落库值——超限请求必须零落库。
	if _, err := db.DB.Exec(`UPDATE global_config SET access_log_format='request>host -> h' WHERE id=1`); err != nil {
		t.Fatalf("seed access_log_format: %v", err)
	}
	readStored := func() string {
		var stored string
		if err := db.DB.QueryRow(`SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
			t.Fatalf("read access_log_format: %v", err)
		}
		return stored
	}
	if res := preview(strings.Repeat(" ", maxBytes)); res.Code != http.StatusOK {
		t.Fatalf("16KiB 纯空格 preview status=%d body=%s, want 200（上限内不得拦截）", res.Code, res.Body.String())
	}
	overSpaces := strings.Repeat(" ", maxBytes+1)
	if res := preview(overSpaces); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "字节") {
		t.Fatalf("16KiB+1 纯空格 preview status=%d body=%s, want 400 含「字节」", res.Code, res.Body.String())
	}
	if res := send(http.MethodPut, "/config", overSpaces); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "字节") {
		t.Fatalf("16KiB+1 纯空格 save status=%d body=%s, want 400 含「字节」", res.Code, res.Body.String())
	}
	if stored := readStored(); stored != "request>host -> h" {
		t.Fatalf("超限纯空格请求落库=%q, want 原值（零落库）", stored)
	}
	// 行数域同理：每行一个空格+换行，空白行逐行计数。
	blankLines := func(n int) string { return strings.Repeat(" \n", n) }
	if res := preview(blankLines(200)); res.Code != http.StatusOK {
		t.Fatalf("200 空白行 preview status=%d body=%s, want 200", res.Code, res.Body.String())
	}
	if res := preview(blankLines(201)); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("201 空白行 preview status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}
	if res := send(http.MethodPut, "/config", blankLines(201)); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("201 空白行 save status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}
	if stored := readStored(); stored != "request>host -> h" {
		t.Fatalf("超限空白行请求落库=%q, want 原值（零落库）", stored)
	}
	// 纯换行不能被 TrimRight 折叠成一行：200 个换行放行，201 个拒绝且零落库。
	pureNewlines := func(n int) string { return strings.Repeat("\n", n) }
	if res := preview(pureNewlines(200)); res.Code != http.StatusOK {
		t.Fatalf("200 个纯换行 preview status=%d body=%s, want 200", res.Code, res.Body.String())
	}
	if res := preview(pureNewlines(201)); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("201 个纯换行 preview status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}
	if res := send(http.MethodPut, "/config", pureNewlines(201)); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "200 行") {
		t.Fatalf("201 个纯换行 save status=%d body=%s, want 400 含「200 行」", res.Code, res.Body.String())
	}
	if stored := readStored(); stored != "request>host -> h" {
		t.Fatalf("超限纯换行请求落库=%q, want 原值（零落库）", stored)
	}
}
