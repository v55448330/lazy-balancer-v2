package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestJWTAuth_rejects_token_without_expiration(t *testing.T) {
	// Given
	cfg, token := newJWTContractFixture(t, jwt.SigningMethodHS256, false)
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", noContent)
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
	}
}

func TestJWTAuth_rejects_non_HS256_HMAC_algorithms(t *testing.T) {
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		t.Run(method.Alg(), func(t *testing.T) {
			// Given
			cfg, token := newJWTContractFixture(t, method, true)
			router := gin.New()
			router.Use(jwtAuth(db.DB, cfg))
			router.GET("/protected", noContent)
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
			}
		})
	}
}

func TestAdminOnly_records_rate_limited_security_event_without_credential(t *testing.T) {
	// Given
	const credential = "admin-jwt-plaintext"
	recorded := captureAuthenticationSecurityAudits(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("role", "user")
		c.Next()
	}, adminOnly())
	router.POST("/admin", noContent)

	// When
	serveRepeatedDeniedRequests(router, http.MethodPost, "/admin", "Authorization", "Bearer "+credential)

	// Then
	assertSingleSecurityAudit(t, *recorded, "admin_required", credential)
}

func TestAPIKeyReadOnlyGuard_records_rate_limited_security_event_without_credential(t *testing.T) {
	// Given
	const credential = "lb_sk_read-only-plaintext"
	recorded := captureAuthenticationSecurityAudits(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", true)
		c.Next()
	}, apiKeyReadOnlyGuard())
	router.POST("/write", noContent)

	// When
	serveRepeatedDeniedRequests(router, http.MethodPost, "/write", "X-API-Key", credential)

	// Then
	assertSingleSecurityAudit(t, *recorded, "api_key_read_only", credential)
}

func TestReadOnlyGuard_records_rate_limited_security_event_without_credential(t *testing.T) {
	// Given
	const credential = "slave-jwt-plaintext"
	recorded := captureAuthenticationSecurityAudits(t)
	database, err := sql.Open("sqlite", t.TempDir()+"/readonly-audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec("CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN); INSERT INTO global_config VALUES (1, 0)"); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(readOnlyGuard(database))
	router.POST("/api/v1/rules", noContent)

	// When
	serveRepeatedDeniedRequests(router, http.MethodPost, "/api/v1/rules", "Authorization", "Bearer "+credential)

	// Then
	assertSingleSecurityAudit(t, *recorded, "slave_write_denied", credential)
}

func newJWTContractFixture(t *testing.T, method jwt.SigningMethod, includeExpiration bool) (*config.Config, string) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,password_version) VALUES (41,'contract-user','hash','user',1,0)"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "contract-secret"}
	claims := jwt.MapClaims{"user_id": 41, "username": "contract-user", "pwd_ver": 0}
	if includeExpiration {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	token, err := jwt.NewWithClaims(method, claims).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, token
}

func captureAuthenticationSecurityAudits(t *testing.T) *[]string {
	t.Helper()
	oldRecorder := recordAuthenticationSecurityAudit
	securityAuditLimiter.reset()
	recorded := make([]string, 0, 1)
	recordAuthenticationSecurityAudit = func(username, action, resource, detail, ipAddress string) {
		recorded = append(recorded, strings.Join([]string{username, action, resource, detail, ipAddress}, " "))
	}
	t.Cleanup(func() {
		recordAuthenticationSecurityAudit = oldRecorder
		securityAuditLimiter.reset()
	})
	return &recorded
}

func serveRepeatedDeniedRequests(router *gin.Engine, method, path, header, credential string) {
	for range 2 {
		request := httptest.NewRequest(method, path, nil)
		request.RemoteAddr = "198.51.100.77:1234"
		request.Header.Set(header, credential)
		router.ServeHTTP(httptest.NewRecorder(), request)
	}
}

func assertSingleSecurityAudit(t *testing.T, recorded []string, reason, credential string) {
	t.Helper()
	if len(recorded) != 1 {
		t.Fatalf("security audit events=%d, want 1: %q", len(recorded), recorded)
	}
	if !strings.Contains(recorded[0], "原因类别："+reason) {
		t.Fatalf("security audit=%q, want reason %q", recorded[0], reason)
	}
	if strings.Contains(recorded[0], credential) {
		t.Fatalf("security audit leaked credential: %q", recorded[0])
	}
}

// 认证审计限流器容量硬上限——超过回收阈值后只按批回收 >=2min 的陈旧键，
// 洪水期（唯一 reason+path+ip 键高速涌入）全部键新鲜、回收零效果，map 曾
// 无界增长（对照 loginRateBuckets 1024 硬拒建桶的真上限）。修复=回收后仍达
// 硬上限（4096）则丢弃新键：不进 map 也不记审计（审计丢失可接受，内存必须
// 有界），与 loginRateBuckets「超限本轮放行不添桶」同族。
func TestAuthenticationAuditLimiter_floodHardCap(t *testing.T) {
	// Given：4096 个新鲜唯一键灌满（同分钟窗写入——清扫对新鲜键零效果）
	securityAuditLimiter.reset()
	t.Cleanup(securityAuditLimiter.reset)
	now := time.Now()
	for i := range 4096 {
		if !securityAuditLimiter.allow(fmt.Sprintf("flood-%d", i), now) {
			t.Fatalf("key %d within hard cap must be admitted", i)
		}
	}

	// When：第 4097 个新键（洪水形状）
	if securityAuditLimiter.allow("flood-overflow", now) {
		t.Fatal("硬上限已满，新键必须丢弃（不记 map 不记审计）")
	}

	// Then：map 规模封顶 4096
	securityAuditLimiter.mu.Lock()
	size := len(securityAuditLimiter.events)
	securityAuditLimiter.mu.Unlock()
	if size != 4096 {
		t.Fatalf("events size=%d, want hard cap 4096（洪水期内存必须有界）", size)
	}

	// And 回归形状：既有键超 1min 窗刷新不占新键额——照常放行记审计；
	// 61s 后清扫仍零效果（<2min），新键依旧拒。
	later := now.Add(61 * time.Second)
	if !securityAuditLimiter.allow("flood-0", later) {
		t.Fatal("既有键超窗刷新不得受容量上限影响")
	}
	if securityAuditLimiter.allow("flood-overflow-2", later) {
		t.Fatal("容量已满时新键仍须丢弃")
	}
	securityAuditLimiter.mu.Lock()
	size = len(securityAuditLimiter.events)
	securityAuditLimiter.mu.Unlock()
	if size != 4096 {
		t.Fatalf("events size after refresh=%d, want 4096（既有键刷新不扩容）", size)
	}
}

// 超阈值后的回收必须有界：一次 allow 只回收最陈旧的一批键，不得持全局锁
// 遍历整表（全图扫描在洪水期把锁持有时间与键规模绑死）。
func TestAuthenticationAuditLimiter_reclaimIsBoundedAndOldestFirst(t *testing.T) {
	// Given：硬上限灌满（同分钟窗写入）
	securityAuditLimiter.reset()
	t.Cleanup(securityAuditLimiter.reset)
	now := time.Now()
	for i := range 4096 {
		if !securityAuditLimiter.allow(fmt.Sprintf("oldest-%d", i), now) {
			t.Fatalf("key %d within hard cap must be admitted", i)
		}
	}

	// When：全部键越过回收线后放行一个新键
	later := now.Add(3 * time.Minute)
	if !securityAuditLimiter.allow("newest", later) {
		t.Fatal("过期的既有键必须腾出容量——新键照常放行")
	}

	// Then：只回收有界批次——全图清扫会把表清到 1 条。
	securityAuditLimiter.mu.Lock()
	size := len(securityAuditLimiter.events)
	_, hasNewest := securityAuditLimiter.events["newest"]
	kept := make(map[string]bool, size)
	for key := range securityAuditLimiter.events {
		kept[key] = true
	}
	securityAuditLimiter.mu.Unlock()
	if !hasNewest {
		t.Fatal("新键必须进表")
	}
	if size > 4096 {
		t.Fatalf("events size=%d 超过硬上限 4096", size)
	}
	if size < 2048 {
		t.Fatalf("events size=%d：单次 allow 回收了整表（有界回收应只删一批）", size)
	}

	// And：回收次序=最早优先——被删的键是 oldest-0 起的连续前缀。
	reclaimed := 0
	for i := range 4096 {
		if kept[fmt.Sprintf("oldest-%d", i)] {
			break
		}
		reclaimed++
	}
	if reclaimed == 0 {
		t.Fatal("过期键必须被回收，否则容量永不释放")
	}
	for i := reclaimed; i < 4096; i++ {
		if !kept[fmt.Sprintf("oldest-%d", i)] {
			t.Fatalf("oldest-%d 被回收却在 oldest-%d 之后——回收次序必须最早优先", i, reclaimed-1)
		}
	}
	if reclaimed != 4097-size {
		t.Fatalf("reclaimed=%d size=%d，账不符（有界回收只能删最陈旧前缀）", reclaimed, size)
	}

	// And：多次调用单调推进——阈值以上每次只推一批（新键数 ≤ 回收数），
	// 越过阈值后不再回收（低于阈值不做无用工作），但始终不越硬上限。
	previous := size
	for i := range 64 {
		if !securityAuditLimiter.allow(fmt.Sprintf("probe-%d", i), later) {
			t.Fatalf("probe-%d 必须放行（回收持续腾位）", i)
		}
		securityAuditLimiter.mu.Lock()
		current := len(securityAuditLimiter.events)
		securityAuditLimiter.mu.Unlock()
		if current > 4096 {
			t.Fatalf("probe-%d 后 events size=%d 超过硬上限", i, current)
		}
		if previous > authenticationAuditReclaimThreshold && current > previous {
			t.Fatalf("probe-%d 后 events size=%d > 前值 %d（阈值以上每次调用必须净回收）", i, current, previous)
		}
		previous = current
	}
}

// 时钟回拨后，新登记条目的时间戳会小于队头；回收队列必须重建升序，
// 否则新鲜队头会永久挡住其后已经过期的回拨条目。
func TestAuthenticationAuditLimiter_clockRollbackKeepsQueueReclaimable(t *testing.T) {
	// Given：阈值以上的新鲜键，随后主机时钟回拨 5 分钟并登记一个旧时间戳键。
	limiter := authenticationAuditLimiter{events: make(map[string]time.Time)}
	now := time.Now()
	for i := 0; i <= authenticationAuditReclaimThreshold; i++ {
		if !limiter.allow(fmt.Sprintf("fresh-%d", i), now) {
			t.Fatalf("fresh-%d must be admitted", i)
		}
	}
	if !limiter.allow("rolled-back", now.Add(-5*time.Minute)) {
		t.Fatal("clock-rollback key must be admitted")
	}

	// When：时钟恢复后，新鲜队头尚未满 2 分钟，但回拨条目已过期。
	if !limiter.allow("after-rollback", now.Add(time.Minute)) {
		t.Fatal("post-rollback key must be admitted")
	}

	// Then：过期回拨条目被回收，新鲜键不被误删。
	limiter.mu.Lock()
	_, rolledBackLive := limiter.events["rolled-back"]
	_, freshLive := limiter.events["fresh-0"]
	limiter.mu.Unlock()
	if rolledBackLive {
		t.Fatal("expired clock-rollback entry remains blocked behind fresh queue head")
	}
	if !freshLive {
		t.Fatal("fresh entry must survive reclaim")
	}
}

// 首次回拨重建后，时钟继续在回拨时间线上前进：后续旧时间戳仍可能小于
// 队尾的 pre-rollback 时间，必须逐次维护升序，而不是只检测一次 lastNow 回拨。
func TestAuthenticationAuditLimiter_rolledBackTimelineKeepsQueueOrdered(t *testing.T) {
	// Given：pre-rollback 新鲜键 + 回拨时间线上连续登记两个键。
	limiter := authenticationAuditLimiter{events: make(map[string]time.Time)}
	now := time.Now()
	for i := 0; i <= authenticationAuditReclaimThreshold; i++ {
		if !limiter.allow(fmt.Sprintf("fresh-%d", i), now) {
			t.Fatalf("fresh-%d must be admitted", i)
		}
	}
	rolledBack := now.Add(-5 * time.Minute)
	if !limiter.allow("rolled-back-first", rolledBack) {
		t.Fatal("first rollback key must be admitted")
	}
	if !limiter.allow("rolled-back-second", rolledBack.Add(time.Second)) {
		t.Fatal("second rollback-timeline key must be admitted")
	}

	// When：仍停留在回拨时间线，两个回拨键均过 TTL，pre-rollback 键仍在未来。
	if !limiter.allow("rollback-timeline-probe", rolledBack.Add(3*time.Minute)) {
		t.Fatal("rollback-timeline probe must be admitted")
	}

	// Then：第二个回拨键不能被新鲜 future 队头挡在队尾。
	limiter.mu.Lock()
	_, secondLive := limiter.events["rolled-back-second"]
	_, freshLive := limiter.events["fresh-0"]
	limiter.mu.Unlock()
	if secondLive {
		t.Fatal("expired second rollback-timeline entry remains blocked behind future queue head")
	}
	if !freshLive {
		t.Fatal("pre-rollback fresh entry must survive reclaim")
	}
}

// 刷新过的键不得因队列里残留的首次登记时间被回收——去重窗内二次记审计是回归。
func TestAuthenticationAuditLimiter_refreshedKeySurvivesReclaim(t *testing.T) {
	securityAuditLimiter.reset()
	t.Cleanup(securityAuditLimiter.reset)
	now := time.Now()
	for i := range 4096 {
		if !securityAuditLimiter.allow(fmt.Sprintf("oldest-%d", i), now) {
			t.Fatalf("key %d within hard cap must be admitted", i)
		}
	}
	// 越过 1min 去重窗后刷新队头键
	if !securityAuditLimiter.allow("oldest-0", now.Add(61*time.Second)) {
		t.Fatal("越过去重窗的既有键必须放行（刷新不占新键额）")
	}

	// When：推进足够多轮回收（队头条目被反复取出）
	later := now.Add(3 * time.Minute)
	for i := range 128 {
		if !securityAuditLimiter.allow(fmt.Sprintf("probe-%d", i), later) {
			t.Fatalf("probe-%d 必须放行", i)
		}
	}

	// Then：刷新过的键仍在表内，且仍在去重窗内继续抑制重复审计。
	securityAuditLimiter.mu.Lock()
	_, live := securityAuditLimiter.events["oldest-0"]
	securityAuditLimiter.mu.Unlock()
	if !live {
		t.Fatal("刷新过的键被陈旧队列条目误回收")
	}
	// 刷新发生在 now+61s：回到去重窗内（+30s）必须仍抑制。
	if securityAuditLimiter.allow("oldest-0", now.Add(91*time.Second)) {
		t.Fatal("刷新后的键仍在 1min 去重窗内，必须继续抑制")
	}
}

// 回收队列自身有界：洪水 + 反复刷新不得让内部队列无界增长。
func TestAuthenticationAuditLimiter_reclaimQueueStaysBounded(t *testing.T) {
	securityAuditLimiter.reset()
	t.Cleanup(securityAuditLimiter.reset)
	now := time.Now()
	for round := 0; round < 3; round++ {
		base := now.Add(time.Duration(round) * 3 * time.Minute)
		for i := range 4096 {
			securityAuditLimiter.allow(fmt.Sprintf("round-%d-key-%d", round, i), base)
		}
		securityAuditLimiter.mu.Lock()
		queue := securityAuditLimiter.reclaimQueueLenLocked()
		events := len(securityAuditLimiter.events)
		securityAuditLimiter.mu.Unlock()
		if queue > 4096 {
			t.Fatalf("round %d reclaim queue=%d 超过硬上限（队列必须与表规模同阶）", round, queue)
		}
		if queue > events+64 {
			t.Fatalf("round %d reclaim queue=%d 远大于表内键数 %d", round, queue, events)
		}
	}
}

// 环被冲刷后陈旧键必须仍可回收：环满覆盖队头时，若被覆盖条目是表内该键
// 仅存的登记，该键从此进不了回收视野——表撑到硬上限后新审计永久丢弃（只有
// 重启恢复）。覆盖即淘汰把这条丢失的回收点补回来。
func TestAuthenticationAuditLimiter_overwrittenEntryKeepsKeyReclaimable(t *testing.T) {
	limiter := &authenticationAuditLimiter{events: make(map[string]time.Time)}
	now := time.Now()
	// 一个键的唯一条目位于环头——后续登记全部来自另一个热键。
	if !limiter.allow("victim", now) {
		t.Fatal("victim 必须入表")
	}
	// 越过 1min 去重窗反复登记热键，把环填满并开始覆盖队头（表内键数恒 <2，
	// 不触发阈值回收，覆盖是本用例唯一的淘汰路径）。
	for i := range authenticationAuditQueueCapacity {
		now = now.Add(61 * time.Second)
		if !limiter.allow("hot", now) {
			t.Fatalf("hot 第 %d 次刷新必须放行", i)
		}
	}

	// Then 唯一登记被覆盖的键必须已被淘汰（否则它永不回收）。
	limiter.mu.Lock()
	_, live := limiter.events["victim"]
	size := len(limiter.events)
	limiter.mu.Unlock()
	if live {
		t.Fatalf("victim 的唯一条目被环覆盖后仍留在表内（size=%d）——该键从此不可回收", size)
	}
	if size > 2 {
		t.Fatalf("环覆盖期间表内键数=%d，want ≤2（覆盖即淘汰）", size)
	}
	if !limiter.allow("fresh", now) {
		t.Fatal("环覆盖后新键必须仍可入表")
	}
}

// 认证态每请求回读 DB——禁用立即 401、角色取自 DB 而非
// token claim（旧令牌提升权限必须失效）。
func TestJWTAuth_disabledUserRejectedImmediately(t *testing.T) {
	cfg, token := newJWTContractFixture(t, jwt.SigningMethodHS256, true)
	if _, err := db.DB.Exec("UPDATE users SET is_enabled=0 WHERE id=41"); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	router.GET("/protected", noContent)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "用户不存在或已禁用") {
		t.Fatalf("status=%d body=%s, want 401 用户不存在或已禁用", rec.Code, rec.Body.String())
	}
}

func TestJWTAuth_roleFromDBOverridesClaim(t *testing.T) {
	cfg, _ := newJWTContractFixture(t, jwt.SigningMethodHS256, true)
	// token 声称 admin，DB 仍是 user（fixture 写入 role='user'）。
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 41, "username": "contract-user", "role": "admin", "pwd_ver": 0,
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(jwtAuth(db.DB, cfg))
	admin := router.Group("/admin", adminOnly())
	admin.GET("/ping", noContent)
	req := httptest.NewRequest(http.MethodGet, "/admin/ping", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403 (role must come from DB, not the claim)", rec.Code, rec.Body.String())
	}
}
