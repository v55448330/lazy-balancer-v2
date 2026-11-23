package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// rowsErrConnector 返回一行后在下一次 Next 抛错，模拟游标中途失败。
// 数据库读故障必须整页 500，不得把半页 200 当成完整列表。
type rowsErrConnector struct{}

func (rowsErrConnector) Connect(context.Context) (driver.Conn, error) { return rowsErrConn{}, nil }
func (rowsErrConnector) Driver() driver.Driver                        { return rowsErrDriver{} }

type rowsErrDriver struct{}

func (rowsErrDriver) Open(string) (driver.Conn, error) { return rowsErrConn{}, nil }

type rowsErrConn struct{}

func (rowsErrConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unsupported")
}
func (rowsErrConn) Close() error              { return nil }
func (rowsErrConn) Begin() (driver.Tx, error) { return nil, errors.New("begin unsupported") }

func (rowsErrConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &rowsErrRows{}, nil
}

type rowsErrRows struct {
	sent bool
}

func (*rowsErrRows) Columns() []string {
	return []string{"id", "user_id", "type", "name", "target", "style_config", "enabled", "last_test_at", "last_test_ok"}
}

func (*rowsErrRows) Close() error { return nil }

func (r *rowsErrRows) Next(dest []driver.Value) error {
	if r.sent {
		return errors.New("forced rows iteration error")
	}
	r.sent = true
	dest[0] = int64(1)
	dest[1] = int64(1)
	dest[2] = "webhook"
	dest[3] = "rows-err"
	dest[4] = "https://example.test/hook"
	dest[5] = "{}"
	dest[6] = int64(1)
	dest[7] = ""
	dest[8] = int64(0)
	return nil
}

func TestListNotificationChannels_rowsErrReturns500(t *testing.T) {
	oldDB := db.DB
	db.DB = sql.OpenDB(rowsErrConnector{})
	t.Cleanup(func() {
		_ = db.DB.Close()
		db.DB = oldDB
	})

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/notification/channels", nil)
	c.Set("role", "admin")
	c.Set("user_id", 1)

	(&Handlers{}).ListNotificationChannels(c)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（rows.Err 必须显性化，不得半页 200）", recorder.Code, recorder.Body.String())
	}
}
