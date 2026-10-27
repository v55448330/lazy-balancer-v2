package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// MFASetup 的 otpauth 账号位与 pending 密钥落库。
// 账号位此前用数字 ID（getContextUserID），所有用户的 Authenticator
//   条目都显示「LazyBalancer:1」不可区分；services/mfa.go 约定 accountName
//   即用户名，jwtAuth/apiKeyAuth 均已注入 c username。
// pending 密钥此前两段写（先清后设、第二段错误经 err==nil 门吞掉），
//   首成次败时已向客户端返回 200+secret 而 pending 为空——用户扫码后 activate
//   必报「没有待激活的 MFA 密钥」；且两语句间存在瞬时空窗。修复为单条
//   UPDATE 原子落库，失败显式 500。

// seedMfaSetupUser 种 id=1 未启用 MFA 的用户（mfa_pending_fails=3，用于验证
// setup 成功路径原子重置失败计数）。
func seedMfaSetupUser(t *testing.T) {
	t.Helper()
	// 登录后验码/pending 验码限流为进程内内存态——同 user id（均 id=1）的跨
	// 用例残留会让后序用例误中 429，播种即清并在用例结束时再清。
	services.MFAResetVerifyAttemptsForTest()
	t.Cleanup(services.MFAResetVerifyAttemptsForTest)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_pending_fails) VALUES (1,'operator','seed-hash','admin',1,3)"); err != nil {
		t.Fatalf("seed setup user: %v", err)
	}
}

// TestMFASetup_otpauthAccountNameUsesUsername：首绑 setup 返回的 otpauth URI
// 账号位应为用户名。修复前：LazyBalancer:1（数字 ID，全员同名）。
func TestMFASetup_otpauthAccountNameUsesUsername(t *testing.T) {
	// Given 未启用 MFA 的用户 operator（id=1）
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t)
	router := mfaSetupTestRouter(h)

	// When
	rec := postRaw(router, "/auth/mfa/setup", `{}`)

	// Then 200 且 URI 账号位为用户名
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Secret string `json:"secret"`
			URI    string `json:"uri"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body.Data.URI, "LazyBalancer:operator") {
		t.Fatalf("uri=%s, want 账号位含用户名 operator（历史修复：不应再用数字 ID）", body.Data.URI)
	}
	if strings.Contains(body.Data.URI, "LazyBalancer:1?") || strings.HasSuffix(body.Data.URI, "LazyBalancer:1") {
		t.Fatalf("uri=%s, want 不含数字 ID 账号位 LazyBalancer:1", body.Data.URI)
	}
}

// TestMFASetup_persistsPendingSecretAndResetsFailCounter：成功路径单响应窗口
// 内 secret 落库且失败计数清零。
func TestMFASetup_persistsPendingSecretAndResetsFailCounter(t *testing.T) {
	// Given 未启用 MFA、pending 失败计数=3 的用户
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t)
	router := mfaSetupTestRouter(h)

	// When
	rec := postRaw(router, "/auth/mfa/setup", `{}`)

	// Then 200 + pending=返回的 secret + fails=0
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var stored string
	var fails int
	if err := db.DB.QueryRow("SELECT mfa_pending_secret, COALESCE(mfa_pending_fails,0) FROM users WHERE id=1").Scan(&stored, &fails); err != nil {
		t.Fatalf("query pending state: %v", err)
	}
	if stored == "" || stored != body.Data.Secret {
		t.Fatalf("pending secret=%q response secret=%q, want 一致且非空", stored, body.Data.Secret)
	}
	if fails != 0 {
		t.Fatalf("mfa_pending_fails=%d, want 0（setup 应重置失败计数）", fails)
	}
}

// mfaPendingWriteFailingConnector 按 SQL 路由的假 db.DB：mfa_enabled 读返回
// 未启用行，pending 写注入故障（同假连接器模式）。
type mfaPendingWriteFailingConnector struct{}

func (mfaPendingWriteFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return mfaPendingWriteFailingConn{}, nil
}

func (mfaPendingWriteFailingConnector) Driver() driver.Driver { return mfaPendingWriteFailingDriver{} }

type mfaPendingWriteFailingDriver struct{}

func (mfaPendingWriteFailingDriver) Open(string) (driver.Conn, error) {
	return mfaPendingWriteFailingConn{}, nil
}

type mfaPendingWriteFailingConn struct{}

func (mfaPendingWriteFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (mfaPendingWriteFailingConn) Close() error { return nil }

func (mfaPendingWriteFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (mfaPendingWriteFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "mfa_enabled") {
		return &fakeQueryRows{values: [][]driver.Value{{int64(0)}}}, nil
	}
	if strings.Contains(query, "auth_provider") {
		// MFA 入口的 OIDC 身份判定读——本地用户形状
		return &fakeQueryRows{values: [][]driver.Value{{"local"}}}, nil
	}
	return &fakeQueryRows{}, nil
}

func (mfaPendingWriteFailingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "mfa_pending_secret") {
		return nil, errors.New("注入的 pending 写入故障")
	}
	return nil, errors.New("unexpected exec: " + query)
}

// TestMFASetup_pendingWriteFailure_returns500：pending 写入失败必须显式 500
// 「保存 MFA 密钥失败」，不得 200 返回 secret 而 pending 为空。
// 修复前：两段写的清空语句失败即整体跳过，200 + 空 pending + 用户扫码白扫。
func TestMFASetup_pendingWriteFailure_returns500(t *testing.T) {
	// Given 真库种子用户 + 写入路径注入故障的假 DB
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t)
	fake := sql.OpenDB(mfaPendingWriteFailingConnector{})
	t.Cleanup(func() { _ = fake.Close() })
	orig := db.DB
	db.DB = fake
	t.Cleanup(func() { db.DB = orig })
	router := mfaSetupTestRouter(h)

	// When
	rec := postRaw(router, "/auth/mfa/setup", `{}`)

	// Then 500 + 保存 MFA 密钥失败（修复前：200 + secret 但 pending 未落库）
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（pending 写入失败不得返回 200）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "保存 MFA 密钥失败") {
		t.Fatalf("body=%s, want 包含「保存 MFA 密钥失败」", rec.Body.String())
	}
}

// activate 的 pending 读取故障必须 500 且不得计入验证码失败；
// 普通错误验证码仍保持 400 + 计数的回归契约。
func TestMFAActivate_pendingFailureClassification(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t)
	if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='junk',mfa_pending_fails=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	router := mfaSetupTestRouter(h)
	router.POST("/auth/mfa/activate", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFAActivate(c)
	})

	wrong := postRaw(router, "/auth/mfa/activate", `{"code":"000000"}`)
	if wrong.Code != http.StatusBadRequest {
		t.Fatalf("wrong code status=%d body=%s, want 400", wrong.Code, wrong.Body.String())
	}
	var fails int
	if err := db.DB.QueryRow(`SELECT mfa_pending_fails FROM users WHERE id=1`).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 1 {
		t.Fatalf("wrong code fails=%d, want 1", fails)
	}

	if _, err := db.DB.Exec(`ALTER TABLE users DROP COLUMN mfa_pending_secret`); err != nil {
		t.Fatalf("break pending read: %v", err)
	}
	failure := postRaw(router, "/auth/mfa/activate", `{"code":"000000"}`)
	if failure.Code != http.StatusInternalServerError {
		t.Fatalf("pending DB failure status=%d body=%s, want 500", failure.Code, failure.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT mfa_pending_fails FROM users WHERE id=1`).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 1 {
		t.Fatalf("DB failure changed pending fails to %d, want unchanged 1", fails)
	}
}

// activate 的三态口径钉测：①无 pending 密钥（未 setup/已被并发覆盖）是业务态
// 哨兵 ErrMFANoPendingSecret——必须 400 业务文案，不得折叠成 500（与 verify
// 四入口的 ErrMFANotEnabled→400 同口径）；②真验证码错误 400 + 计数；
// ③pending 读取的基础设施故障 500 且不计数（后两形态为回归契约）。
func TestMFAActivate_noPendingSecretReturns400(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t)
	router := mfaSetupTestRouter(h)
	router.POST("/auth/mfa/activate", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFAActivate(c)
	})

	// 形态①：无 pending → 400 业务文案（哨兵不得折叠成 500），失败计数不动。
	if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_fails=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	noPending := postRaw(router, "/auth/mfa/activate", `{"code":"123456"}`)
	if noPending.Code != http.StatusBadRequest {
		t.Fatalf("no pending status=%d body=%s, want 400（业务哨兵不得报 500）", noPending.Code, noPending.Body.String())
	}
	if !strings.Contains(noPending.Body.String(), "没有待激活的 MFA 密钥") {
		t.Fatalf("body=%s, want 包含「没有待激活的 MFA 密钥」", noPending.Body.String())
	}
	var fails int
	if err := db.DB.QueryRow(`SELECT mfa_pending_fails FROM users WHERE id=1`).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 0 {
		t.Fatalf("no-pending rejection must not bump fails, got %d", fails)
	}

	// 形态②：有 pending + 错误验证码 → 400 验证码错误文案 + 计数。
	if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='junk',mfa_pending_fails=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	wrong := postRaw(router, "/auth/mfa/activate", `{"code":"000000"}`)
	if wrong.Code != http.StatusBadRequest || !strings.Contains(wrong.Body.String(), "验证码错误") {
		t.Fatalf("wrong code status=%d body=%s, want 400 验证码错误", wrong.Code, wrong.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT mfa_pending_fails FROM users WHERE id=1`).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 1 {
		t.Fatalf("wrong code fails=%d, want 1", fails)
	}

	// 形态③：pending 读取故障 → 500 且不计数。
	if _, err := db.DB.Exec(`ALTER TABLE users DROP COLUMN mfa_pending_secret`); err != nil {
		t.Fatalf("break pending read: %v", err)
	}
	failure := postRaw(router, "/auth/mfa/activate", `{"code":"000000"}`)
	if failure.Code != http.StatusInternalServerError {
		t.Fatalf("pending DB failure status=%d body=%s, want 500", failure.Code, failure.Body.String())
	}
}

// 已启用 MFA 的用户重绑成功（pending 密钥轮换）必须留审计——此前该步零
// 留痕，随后 activate 恒记「启用」，重绑与首绑在审计中不可区分；detail 不得
// 落 secret 任何片段。
func TestMFASetup_rebindSuccessWritesRotationAudit(t *testing.T) {
	h := newBackupTestHandlers(t)
	secret := seedMfaResetUsers(t, true) // operator(id=1) 已启用 MFA
	// 年龄键缺失 → mfaStepUpVerifiedForDestructiveOp 回落本层验码（fail-safe）。
	router := mfaSelfServiceRouterWithAge(h, -1)
	rec := postMfaSelfService(router, "/auth/mfa/setup", fmt.Sprintf(`{"code":%q}`, currentTOTPCode(t, secret)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data.Secret) < 8 {
		t.Fatalf("secret=%q, want 非空 pending secret", body.Data.Secret)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='重新绑定' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query audit: %v（重绑成功必须留「重新绑定」审计行）", err)
	}
	if !strings.Contains(detail, "pending 密钥已轮换") {
		t.Fatalf("detail=%q, want 含「pending 密钥已轮换」", detail)
	}
	if strings.Contains(detail, body.Data.Secret[:8]) {
		t.Fatalf("detail=%q 泄漏 pending secret 片段", detail)
	}
}

// 已启用 MFA 的用户重绑时验码失败属于高敏失败尝试，必须留审计。
func TestMFASetup_rebindVerificationFailureWritesAudit(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, true)
	router := mfaSetupTestRouter(h)
	response := postRaw(router, "/auth/mfa/setup", `{"code":"000000"}`)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", response.Code, response.Body.String())
	}
	var events int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%重绑 MFA 前验证失败%'`).Scan(&events); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if events != 1 {
		t.Fatalf("rebind failure audit events=%d, want 1", events)
	}
}
