package handlers

// 写操作 step-up 判定的单源契约：路由守卫（middleware mfaStepUpGuard）与
// 特权 API Key 创建的内联副本此前各有一份判定。派生差异实测可见：内联副本
// 缺 OIDC 会话短路（守卫 fail-open 落穿时 OIDC 用户会被 428）、也缺只读语义
// 写路由豁免。现在两侧共用 DecideMFAStepUp，本文件钉住各短路条件与内联副本
// 的实际响应。

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// stepUpContext 构造不挂路由表的 gin 上下文（FullPath 为空，判定回退到
// Request.URL.Path——与守卫的 fallback 同口径）。
func stepUpContext(t *testing.T, method, path string, sets map[string]any) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, path, nil)
	for k, v := range sets {
		c.Set(k, v)
	}
	return c
}

// seedStepUpUsers 种启用/未启用 MFA 的两个用户（id=1 启用，id=2 未启用）。
func seedStepUpUsers(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled,auth_provider)
		VALUES (1,'stepup-mfa','x','admin',1,1,'local'),(2,'stepup-plain','x','admin',1,0,'local')`); err != nil {
		t.Fatal(err)
	}
}

func TestDecideMFAStepUp_shortCircuits(t *testing.T) {
	newBackupTestHandlers(t)
	seedStepUpUsers(t)
	setMfaWriteGuard(t, true)
	staleMap := func() map[string]any {
		return map[string]any{
			"auth_type": "jwt",
			"user_id":   float64(1),
			"mfa_ts":    float64(time.Now().Add(-10 * time.Minute).Unix()),
		}
	}

	cases := []struct {
		name         string
		covered      bool
		method, path string
		sets         map[string]any
		wantApplies  bool
		wantVerified bool
	}{
		{
			name:    "非覆盖面",
			covered: false, method: http.MethodGet, path: "/api/v1/rules",
			sets: staleMap(), wantApplies: false,
		},
		{
			name:    "机器身份（API Key/MCP）",
			covered: true, method: http.MethodPut, path: "/api/v1/config",
			sets: func() map[string]any {
				m := staleMap()
				m["auth_type"] = "api_key"
				return m
			}(), wantApplies: false,
		},
		{
			name:    "OIDC 会话与本地 MFA 解耦",
			covered: true, method: http.MethodPut, path: "/api/v1/config",
			sets: func() map[string]any {
				m := staleMap()
				m["auth_method"] = "oidc"
				return m
			}(), wantApplies: false,
		},
		{
			name:    "只读语义写路由豁免",
			covered: true, method: http.MethodPost, path: "/api/v1/rules/cert-info",
			sets: staleMap(), wantApplies: false,
		},
		{
			name:    "step-up 机制本体豁免",
			covered: true, method: http.MethodPost, path: "/api/v1/auth/mfa/verify-step",
			sets: staleMap(), wantApplies: false,
		},
		{
			name:    "未启用 MFA 的本地用户",
			covered: true, method: http.MethodPut, path: "/api/v1/config",
			sets: func() map[string]any {
				m := staleMap()
				m["user_id"] = float64(2)
				return m
			}(), wantApplies: false,
		},
		{
			name:    "陈旧 mfa_ts 需验码",
			covered: true, method: http.MethodPut, path: "/api/v1/config",
			sets: staleMap(), wantApplies: true, wantVerified: false,
		},
		{
			name:    "宽限窗内已验证",
			covered: true, method: http.MethodPut, path: "/api/v1/config",
			sets: func() map[string]any {
				m := staleMap()
				m["mfa_ts"] = float64(time.Now().Unix())
				return m
			}(), wantApplies: true, wantVerified: true,
		},
		{
			name:    "未来时间戳按未验证处理",
			covered: true, method: http.MethodPut, path: "/api/v1/config",
			sets: func() map[string]any {
				m := staleMap()
				// 时钟回拨/VM 快照恢复：负年龄不得等价于「刚验证」。
				m["mfa_ts"] = float64(time.Now().Add(10 * time.Minute).Unix())
				return m
			}(), wantApplies: true, wantVerified: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := stepUpContext(t, tc.method, tc.path, tc.sets)
			decision, err := DecideMFAStepUp(c, tc.covered, db.DB, services.MFAUserEnabled)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Applies != tc.wantApplies || decision.Verified != tc.wantVerified {
				t.Fatalf("decision=%+v, want applies=%v verified=%v", decision, tc.wantApplies, tc.wantVerified)
			}
			if decision.Verified && (decision.SecondsAgo < 0 || decision.SecondsAgo >= 60) {
				t.Fatalf("宽限窗内 SecondsAgo=%d, want [0,60)", decision.SecondsAgo)
			}
		})
	}
}

func TestDecideMFAStepUp_futureTimestampWarnIsThrottled(t *testing.T) {
	newBackupTestHandlers(t)
	seedStepUpUsers(t)
	setMfaWriteGuard(t, true)
	reset := func() {
		mfaFutureTimestampWarningLog.mu.Lock()
		mfaFutureTimestampWarningLog.last = time.Time{}
		mfaFutureTimestampWarningLog.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
	logs := captureLog(t)
	decide := func() {
		t.Helper()
		c := stepUpContext(t, http.MethodPut, "/api/v1/config", map[string]any{
			"auth_type": "jwt",
			"user_id":   float64(1),
			"mfa_ts":    float64(time.Now().Add(10 * time.Minute).Unix()),
		})
		decision, err := DecideMFAStepUp(c, true, db.DB, services.MFAUserEnabled)
		if err != nil || !decision.Applies || decision.Verified {
			t.Fatalf("future timestamp decision=%+v err=%v, want unverified applies", decision, err)
		}
	}

	// Given 同一时钟回拨状态下连续两个写请求。
	decide()
	decide()
	// Then 两个请求都被 fail-safe 拒绝，但 60 秒窗口内只留一条 warn。
	if got := strings.Count(logs.String(), "MFA step-up 时间戳在未来"); got != 1 {
		t.Fatalf("future timestamp warnings=%d, want 1; logs=%q", got, logs.String())
	}

	// When 上一告警已超过节流窗口。
	mfaFutureTimestampWarningLog.mu.Lock()
	mfaFutureTimestampWarningLog.last = time.Now().Add(-61 * time.Second)
	mfaFutureTimestampWarningLog.mu.Unlock()
	decide()
	// Then 新窗口重新留痕，避免永久静默。
	if got := strings.Count(logs.String(), "MFA step-up 时间戳在未来"); got != 2 {
		t.Fatalf("warnings after window=%d, want 2; logs=%q", got, logs.String())
	}
}

func TestDecideMFAStepUp_guardDisabled(t *testing.T) {
	newBackupTestHandlers(t)
	seedStepUpUsers(t)
	setMfaWriteGuard(t, false)

	c := stepUpContext(t, http.MethodPut, "/api/v1/config", map[string]any{
		"auth_type": "jwt",
		"user_id":   float64(1),
		"mfa_ts":    float64(time.Now().Add(-10 * time.Minute).Unix()),
	})
	decision, err := DecideMFAStepUp(c, true, db.DB, services.MFAUserEnabled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Applies {
		t.Fatalf("守卫关闭时不得要求验码: %+v", decision)
	}
}

func TestDecideMFAStepUp_distinguishesReadFailures(t *testing.T) {
	newBackupTestHandlers(t)
	seedStepUpUsers(t)
	setMfaWriteGuard(t, true)

	c := stepUpContext(t, http.MethodPut, "/api/v1/config", map[string]any{
		"auth_type": "jwt",
		"user_id":   float64(1),
		"mfa_ts":    float64(time.Now().Add(-10 * time.Minute).Unix()),
	})
	if _, err := DecideMFAStepUp(c, true, db.DB, func(int) (bool, error) { return false, errors.New("simulated state read failure") }); err == nil ||
		!strings.Contains(err.Error(), ErrMFAStepUpStateUnreadable.Error()) {
		t.Fatalf("MFA 状态读取失败必须可识别（守卫 500/fail-closed）: %v", err)
	}
}

// 内联副本（特权 API Key 创建）必须与守卫共享 OIDC 短路：OIDC 会话不落入
// 本地 MFA step-up（守卫 fail-open 落穿时也不会被 428）。
func TestCreateAPIKey_oidcSessionSkipsLocalStepUp(t *testing.T) {
	newBackupTestHandlers(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled,auth_provider)
		VALUES (1,'oidc-operator','x','admin',1,1,'oidc')`); err != nil {
		t.Fatal(err)
	}
	setMfaWriteGuard(t, true)

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"oidc-key"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", 1)
	c.Set("role", "admin")
	c.Set("auth_type", "jwt")
	c.Set("auth_method", "oidc")
	c.Set("mfa_ts", float64(time.Now().Add(-10*time.Minute).Unix()))

	createAPIKeyForUser(c, 1)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201（OIDC 会话不得落本地 step-up）", rec.Code, rec.Body.String())
	}
}

// 对照组：本地用户同条件仍必须 428——单源判定不得把内联副本的拦截面抹掉。
func TestCreateAPIKey_localUserStaleMfaTsStillChallenged(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled,auth_provider)
		VALUES (1,'local-operator','x','admin',1,1,'local')`); err != nil {
		t.Fatal(err)
	}
	setMfaWriteGuard(t, true)

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"local-key"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", 1)
	c.Set("role", "admin")
	c.Set("auth_type", "jwt")
	c.Set("mfa_ts", float64(time.Now().Add(-10*time.Minute).Unix()))

	createAPIKeyForUser(c, 1)

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status=%d body=%s, want 428", rec.Code, rec.Body.String())
	}
}

// 秒数换算必须向上取整：截断实现会把 15.9s 记成 15s，使拆除/重绑 MFA 的
// ≤15s 免码窗实际放宽到 16s。判定与响应头共用本换算，故直接钉边界值。
func TestMFAStepUpSecondsAgo_roundsUp(t *testing.T) {
	cases := []struct {
		elapsed time.Duration
		want    int64
	}{
		{15400 * time.Millisecond, 16},
		{15 * time.Second, 15},
		{200 * time.Millisecond, 1},
		{0, 0},
	}
	for _, tc := range cases {
		if got := mfaStepUpSecondsAgo(tc.elapsed); got != tc.want {
			t.Fatalf("mfaStepUpSecondsAgo(%s)=%d, want %d（截断实现会把 15.9s 记成 15s）", tc.elapsed, got, tc.want)
		}
	}
}

// 判定侧同样不得截断：mfa_ts 是整秒时间戳，判定时的年龄必带亚秒余量，
// 向上取整后至少为 1s——截断实现恒报 0，窄窗判定随之放宽。
func TestDecideMFAStepUp_freshTimestampReportsRoundedUpSeconds(t *testing.T) {
	newBackupTestHandlers(t)
	seedStepUpUsers(t)
	setMfaWriteGuard(t, true)

	mfaTs := time.Now().Unix()
	c := stepUpContext(t, http.MethodPut, "/api/v1/config", map[string]any{
		"auth_type": "jwt",
		"user_id":   float64(1),
		"mfa_ts":    float64(mfaTs),
	})
	decision, err := DecideMFAStepUp(c, true, db.DB, services.MFAUserEnabled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Applies || !decision.Verified {
		t.Fatalf("decision=%+v, want applies+verified（刚验码）", decision)
	}
	if decision.SecondsAgo < 1 {
		t.Fatalf("SecondsAgo=%d, want ≥1（截断实现报 0，窄窗边界被放宽）", decision.SecondsAgo)
	}
}
