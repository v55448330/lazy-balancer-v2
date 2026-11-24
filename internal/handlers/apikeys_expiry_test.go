package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// patchAPIKeyStatus 以 actorID/role 身份调用密钥更新端点：self=true 走自助入口
// （只能改本人 key），false 走管理端入口。
func patchAPIKeyStatus(t *testing.T, self bool, id, actorID int, role, body string) *httptest.ResponseRecorder {
	t.Helper()
	update := (&Handlers{}).UpdateAPIKeyStatus
	path := "/api-keys/" + strconv.Itoa(id) + "/status"
	if self {
		update = (&Handlers{}).UpdateCurrentUserAPIKeyStatus
		path = "/users/me/api-keys/" + strconv.Itoa(id)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, path, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(id)}}
	ctx.Set("user_id", actorID)
	ctx.Set("role", role)
	update(ctx)
	return recorder
}

// seedAPIKeyExpiry 写入密钥过期时间；expires 为 nil 表示永不过期。
func seedAPIKeyExpiry(t *testing.T, id int, expires *time.Time) {
	t.Helper()
	if _, err := db.DB.Exec("UPDATE api_keys SET expires_at = ? WHERE id = ?", expires, id); err != nil {
		t.Fatalf("seed api key %d expiry: %v", id, err)
	}
}

// readAPIKeyExpiry 读回密钥过期时间的终态。
func readAPIKeyExpiry(t *testing.T, id int) sql.NullTime {
	t.Helper()
	var expires sql.NullTime
	if err := db.DB.QueryRow("SELECT expires_at FROM api_keys WHERE id = ?", id).Scan(&expires); err != nil {
		t.Fatalf("read api key %d expiry: %v", id, err)
	}
	return expires
}

// latestAPIKeyUpdateAuditDetail 取最近一条密钥更新审计的明细。
func latestAPIKeyUpdateAuditDetail(t *testing.T) string {
	t.Helper()
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='API密钥' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	return detail
}

// countAPIKeyUpdateAudits 统计密钥更新审计行数。
func countAPIKeyUpdateAudits(t *testing.T) int {
	t.Helper()
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新' AND resource='API密钥'`).Scan(&rows); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return rows
}

// 有效期创建后不能改——到期只能新建密钥并替换全部客户端。更新端点接受
// expires_at 后，已过期的密钥直接延期即可恢复可用，客户端无需换密钥。
func TestUpdateAPIKeyStatus_extendsExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expired := now.AddDate(0, 0, -1)
	extended := now.AddDate(0, 0, 30)
	// 真实可鉴权的密钥：哈希/前缀与创建路径同形，用鉴权解析验证「延期即恢复」。
	const plaintext = "lb_sk_0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(plaintext))
	for _, tc := range []struct {
		label string
		self  bool
		role  string
	}{
		{"管理端入口", false, "admin"},
		{"自助入口", true, "user"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			// Given 一把昨天已过期、因此已无法鉴权的密钥
			setupAPIKeyTestDB(t)
			if _, err := db.DB.Exec("UPDATE api_keys SET key_hash = ?, key_prefix = ? WHERE id = 10", hex.EncodeToString(sum[:]), plaintext[:12]); err != nil {
				t.Fatalf("seed real key: %v", err)
			}
			seedAPIKeyExpiry(t, 10, &expired)
			if _, err := db.ResolveAPIKeyIdentity(db.DB, plaintext); err == nil {
				t.Fatal("过期密钥不应通过鉴权")
			}

			// When 只提交新的过期时间
			recorder := patchAPIKeyStatus(t, tc.self, 10, 1, tc.role, `{"expires_at":"`+extended.Format(time.RFC3339)+`"}`)

			// Then 接受为一次有效提交，库内过期时间换成新值，同一把密钥恢复可用
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
			}
			got := readAPIKeyExpiry(t, 10)
			if !got.Valid || !got.Time.Equal(extended) {
				t.Fatalf("expires_at=%v, want %s", got.Time, extended)
			}
			identity, err := db.ResolveAPIKeyIdentity(db.DB, plaintext)
			if err != nil || identity.ID != 10 {
				t.Fatalf("延期后密钥仍不可用: identity=%+v err=%v", identity, err)
			}
		})
	}
}

// expires_at 提交 null = 改为永不过期（与创建时留空同义），不能与「未提交」混同。
func TestUpdateAPIKeyStatus_clearsExpiryWithNull(t *testing.T) {
	// Given 一把 7 天后过期的密钥
	setupAPIKeyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	soon := time.Now().UTC().AddDate(0, 0, 7).Truncate(time.Second)
	seedAPIKeyExpiry(t, 10, &soon)

	// When
	recorder := patchAPIKeyStatus(t, false, 10, 1, "admin", `{"expires_at":null}`)

	// Then 过期时间清空，审计记为改为永不过期
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if got := readAPIKeyExpiry(t, 10); got.Valid {
		t.Fatalf("expires_at=%v, want NULL（永不过期）", got.Time)
	}
	if detail := latestAPIKeyUpdateAuditDetail(t); !strings.Contains(detail, "变更：过期：") || !strings.Contains(detail, "→永不过期") {
		t.Fatalf("audit detail=%q, want 含「过期：旧值→永不过期」", detail)
	}
}

// 未提交 expires_at = 不改：既有调用方（启停开关只发 is_enabled）不得把有效期改掉。
func TestUpdateAPIKeyStatus_omittedExpiryLeavesValue(t *testing.T) {
	// Given
	setupAPIKeyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	soon := time.Now().UTC().AddDate(0, 0, 7).Truncate(time.Second)
	seedAPIKeyExpiry(t, 10, &soon)

	// When
	recorder := patchAPIKeyStatus(t, false, 10, 1, "admin", `{"is_enabled":false}`)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if got := readAPIKeyExpiry(t, 10); !got.Valid || !got.Time.Equal(soon) {
		t.Fatalf("expires_at=%v, want 未改动的 %s", got.Time, soon)
	}
	if detail := latestAPIKeyUpdateAuditDetail(t); strings.Contains(detail, "过期：") {
		t.Fatalf("audit detail=%q，未提交过期时间不得记为变更", detail)
	}
}

// 审计在既有「变更：…」行里追加「过期：旧值→新值」，值按面板时区精确到秒：
// 只记日期时，同一天内改时刻会显示成「旧→新」同值，无法回溯。
func TestUpdateAPIKeyStatus_expiryChangeAuditRecordsOldAndNew(t *testing.T) {
	// Given
	panelTZ, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	previous := services.CurrentLocation()
	if _, err := services.ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = services.ConfigureLocation(previous.String()) })
	setupAPIKeyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	before := now.AddDate(0, 0, 7)
	after := now.AddDate(0, 0, 30)
	seedAPIKeyExpiry(t, 10, &before)

	// When
	recorder := patchAPIKeyStatus(t, false, 10, 1, "admin", `{"expires_at":"`+after.Format(time.RFC3339)+`"}`)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	want := "过期：" + before.In(panelTZ).Format("2006-01-02 15:04:05") + "→" + after.In(panelTZ).Format("2006-01-02 15:04:05")
	if detail := latestAPIKeyUpdateAuditDetail(t); !strings.Contains(detail, "变更："+want) {
		t.Fatalf("audit detail=%q, want 含 %q", detail, "变更："+want)
	}
}

// 编辑弹框每次保存都会带上当前过期时间：与库内相同不算变更，不得留下空转审计。
func TestUpdateAPIKeyStatus_sameExpiryIsNotAuditedAsChange(t *testing.T) {
	// Given
	setupAPIKeyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	soon := time.Now().UTC().AddDate(0, 0, 7).Truncate(time.Second)
	seedAPIKeyExpiry(t, 10, &soon)

	// When
	recorder := patchAPIKeyStatus(t, false, 10, 1, "admin", `{"expires_at":"`+soon.Format(time.RFC3339)+`"}`)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if detail := latestAPIKeyUpdateAuditDetail(t); strings.Contains(detail, "变更：") {
		t.Fatalf("audit detail=%q，过期时间未变不得记为变更", detail)
	}
}

// 校验与创建同口径：过期时间早于当前时间 → 400，且同批提交的其它字段不得部分写入。
func TestUpdateAPIKeyStatus_rejectsPastExpiry(t *testing.T) {
	// Given
	setupAPIKeyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	soon := time.Now().UTC().AddDate(0, 0, 7).Truncate(time.Second)
	seedAPIKeyExpiry(t, 10, &soon)
	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	// When 同时提交启用态与过去的过期时间
	recorder := patchAPIKeyStatus(t, false, 10, 1, "admin", `{"is_enabled":false,"expires_at":"`+past.Format(time.RFC3339)+`"}`)

	// Then
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "过期时间不能早于当前时间") {
		t.Fatalf("status=%d body=%s, want 400「过期时间不能早于当前时间」", recorder.Code, recorder.Body.String())
	}
	if got := readAPIKeyExpiry(t, 10); !got.Valid || !got.Time.Equal(soon) {
		t.Fatalf("expires_at=%v, want 未改动的 %s", got.Time, soon)
	}
	var enabled int
	if err := db.DB.QueryRow("SELECT is_enabled FROM api_keys WHERE id=10").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Fatalf("is_enabled=%d，被拒绝的请求不得部分写入", enabled)
	}
	if rows := countAPIKeyUpdateAudits(t); rows != 0 {
		t.Fatalf("audit rows=%d，被拒绝的请求不得留痕", rows)
	}
}

// expires_at 不是合法时间：与创建相同按「请求格式错误」400，库内不变。
func TestUpdateAPIKeyStatus_rejectsMalformedExpiry(t *testing.T) {
	for _, body := range []string{`{"expires_at":"not-a-time"}`, `{"expires_at":123}`, `{"expires_at":""}`} {
		t.Run(body, func(t *testing.T) {
			// Given
			setupAPIKeyTestDB(t)

			// When
			recorder := patchAPIKeyStatus(t, false, 10, 1, "admin", body)

			// Then
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "请求格式错误") {
				t.Fatalf("status=%d body=%s, want 400「请求格式错误」", recorder.Code, recorder.Body.String())
			}
			if got := readAPIKeyExpiry(t, 10); got.Valid {
				t.Fatalf("expires_at=%v, want 保持 NULL", got.Time)
			}
		})
	}
}

// 两个更新端点的文档示例与语义说明必须带上 expires_at——改有效期只开放给
// REST（MCP 工具未暴露），面板与脚本只能从 API 文档得知。
func TestAPIDocRoutes_keyUpdateRowsDocumentExpiry(t *testing.T) {
	checked := 0
	for _, route := range apiDocRoutes {
		if route.Method != http.MethodPatch ||
			(route.Path != "/users/me/api-keys/:id" && route.Path != "/api-keys/:id/status") {
			continue
		}
		checked++
		var example map[string]json.RawMessage
		if err := json.Unmarshal([]byte(route.Request), &example); err != nil {
			t.Fatalf("%s %s request example: %v", route.Method, route.Path, err)
		}
		if _, ok := example["expires_at"]; !ok {
			t.Errorf("%s %s 请求示例缺 expires_at: %s", route.Method, route.Path, route.Request)
		}
		description := operationDescription(route)
		if !strings.Contains(description, "null 表示改为永不过期") || !strings.Contains(description, "不提交则不改") {
			t.Errorf("%s %s 描述未说明 expires_at 三态: %q", route.Method, route.Path, description)
		}
	}
	if checked != 2 {
		t.Fatalf("checked=%d, want 2（路由改名会让本用例空转）", checked)
	}
}
