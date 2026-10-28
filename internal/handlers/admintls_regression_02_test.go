package handlers

// 读取失败时中止写操作，而不是把读 API 的降级默认值（selfsigned + 空
// cert/key）当作读-改-写基线（瞬时读失败 + 随后的 UPDATE 成功会清空已上传
// 证书/私钥）。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

type brokenQueryConnector struct{}

func (brokenQueryConnector) Connect(context.Context) (driver.Conn, error) {
	return brokenQueryConn{}, nil
}
func (brokenQueryConnector) Driver() driver.Driver { return brokenQueryDriver{} }

type brokenQueryDriver struct{}

func (brokenQueryDriver) Open(string) (driver.Conn, error) { return brokenQueryConn{}, nil }

type brokenQueryConn struct{}

func (brokenQueryConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (brokenQueryConn) Close() error                        { return nil }
func (brokenQueryConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }
func (brokenQueryConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.New("注入的查询失败")
}

func withBrokenDB(t *testing.T) {
	t.Helper()
	newBackupTestHandlers(t)
	broken := sql.OpenDB(brokenQueryConnector{})
	old := db.DB
	db.DB = broken
	t.Cleanup(func() {
		db.DB = old
		_ = broken.Close()
	})
}

func TestUpdateAdminTLS_abortsWhenCurrentConfigReadFails(t *testing.T) {
	withBrokenDB(t)
	h := newAdminTLSHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/admin-tls", h.UpdateAdminTLS)

	request := httptest.NewRequest(http.MethodPut, "/admin-tls", strings.NewReader(`{"enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（读失败必须中止写）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取当前") {
		t.Fatalf("body=%s, want 明确「读取当前配置失败」中止文案（不得进入 UPDATE 写路径）", response.Body.String())
	}
}

func TestValidateV2BackupAdminTLS_abortsWhenCurrentReadFails(t *testing.T) {
	withBrokenDB(t)
	err := validateV2BackupAdminTLS(map[string]any{"admin_tls_enabled": true})
	if err == nil {
		t.Fatal("备份合并路径在读失败时必须中止（不得用降级默认值校验）")
	}
	// 读的是**当前库**而不是备份内容：必须归入基础设施读失败族，由导入入口
	// 映射为 500 固定文案——否则管理员把库故障误判为备份损坏并反复更换文件，
	// 且 400 响应会把底层驱动文本回给客户端。
	var infraErr *importInfraReadError
	if !errors.As(err, &infraErr) {
		t.Fatalf("err=%v, want *importInfraReadError（现状读取失败 ≠ 备份内容错误）", err)
	}
	if strings.Contains(err.Error(), "database") || strings.Contains(err.Error(), "no such") {
		t.Fatalf("err=%q 不得回显底层驱动文本", err.Error())
	}
	// 真正损坏的 admin TLS 备份仍按 400（校验失败，非基础设施）。
	initializeRuleFeatureTestDB(t)
	if err := validateV2BackupAdminTLS(map[string]any{"admin_tls_enabled": true, "admin_tls_mode": "upload", "admin_tls_cert": "not-a-cert", "admin_tls_key": ""}); err == nil {
		t.Fatal("损坏的 upload 备份必须校验失败")
	} else if errors.As(err, &infraErr) {
		t.Fatalf("损坏备份不得归为基础设施读失败: %v", err)
	}
}
