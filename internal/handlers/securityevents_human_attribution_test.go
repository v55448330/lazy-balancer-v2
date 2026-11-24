package handlers

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 人机事件归属查询失败必须以错误上抛（调用方据此留痕）：静默返回零值归属
// 会让合法的 CC 挑战事件被落成「本次事件无策略归属」，且日志里没有任何
// 线索说明这是查询失败而不是真的没绑定策略。
func TestLookupHumanEventAttribution_reportsQueryFailure(t *testing.T) {
	newBackupTestHandlers(t)
	// 已关闭的句柄：任何查询都失败（等价于查询期 DB 故障）。
	closed, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Ping(); err != nil {
		t.Fatal(err)
	}
	// 保活一个连接再整库关闭，确保后续查询拿到的是真实错误而非重新拨号成功。
	conn, err := closed.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	realDB := db.DB
	db.DB = closed
	t.Cleanup(func() { db.DB = realDB })

	done := make(chan error, 1)
	go func() {
		_, lerr := lookupHumanEventAttribution("lb-rule-1")
		done <- lerr
	}()
	select {
	case lerr := <-done:
		if lerr == nil {
			t.Fatal("归属查询失败必须返回错误，不得静默返回零值归属")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookupHumanEventAttribution 未返回")
	}

	// 无规则 ID / 无句柄不是「查询失败」：仍是零值且无错误（调用方无需留痕）。
	db.DB = nil
	if _, lerr := lookupHumanEventAttribution("  "); lerr != nil {
		t.Fatalf("空规则 ID 不得报错: %v", lerr)
	}
	if _, lerr := lookupHumanEventAttribution("lb-rule-1"); lerr != nil {
		t.Fatalf("无数据库句柄按零值无错误处理: %v", lerr)
	}
}
