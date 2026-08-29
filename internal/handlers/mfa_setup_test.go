package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// D5-S1 / D5-S4（N+11 轮）：MFASetup 的 otpauth 账号位与 pending 密钥落库。
// - D5-S1：账号位此前用数字 ID（getContextUserID），所有用户的 Authenticator
//   条目都显示「LazyBalancer:1」不可区分；services/mfa.go 约定 accountName
//   即用户名，jwtAuth/apiKeyAuth 均已注入 c username。
// - D5-S4：pending 密钥此前两段写（先清后设、第二段错误经 err==nil 门吞掉），
//   首成次败时已向客户端返回 200+secret 而 pending 为空——用户扫码后 activate
//   必报「没有待激活的 MFA 密钥」；且两语句间存在瞬时空窗。修复为单条
//   UPDATE 原子落库，失败显式 500。

// seedMfaSetupUser 种 id=1 未启用 MFA 的用户（mfa_pending_fails=3，用于验证
// setup 成功路径原子重置失败计数）。
func seedMfaSetupUser(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_pending_fails) VALUES (1,'operator','seed-hash','admin',1,3)"); err != nil {
		t.Fatalf("seed setup user: %v", err)
	}
}

// TestMFASetup_otpauthAccountNameUsesUsername：首绑 setup 返回的 otpauth URI
// 账号位应为用户名（D5-S1）。修复前：LazyBalancer:1（数字 ID，全员同名）。
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
		t.Fatalf("uri=%s, want 账号位含用户名 operator（D5-S1：不应再用数字 ID）", body.Data.URI)
	}
	if strings.Contains(body.Data.URI, "LazyBalancer:1?") || strings.HasSuffix(body.Data.URI, "LazyBalancer:1") {
		t.Fatalf("uri=%s, want 不含数字 ID 账号位 LazyBalancer:1", body.Data.URI)
	}
}

// TestMFASetup_persistsPendingSecretAndResetsFailCounter：成功路径单响应窗口
// 内 secret 落库且失败计数清零（D5-S4 原子形状的可观测面）。
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
// 未启用行，pending 写注入故障（同 R55/R37 假连接器模式）。
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
	return &fakeQueryRows{}, nil
}

func (mfaPendingWriteFailingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "mfa_pending_secret") {
		return nil, errors.New("注入的 pending 写入故障")
	}
	return nil, errors.New("unexpected exec: " + query)
}

// TestMFASetup_pendingWriteFailure_returns500：pending 写入失败必须显式 500
// 「保存 MFA 密钥失败」，不得 200 返回 secret 而 pending 为空（D5-S4）。
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
