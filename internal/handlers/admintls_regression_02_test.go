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
	if err == nil || !strings.Contains(err.Error(), "读取当前") {
		t.Fatalf("err=%v, want 备份合并路径在读失败时中止（不得用降级默认值校验）", err)
	}
}
