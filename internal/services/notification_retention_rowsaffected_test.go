package services

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// rowsAffectedFailureResult 是 RowsAffected 返回错误的真实 Result 形态：驱动
// 无法给出删除行数时，清理轮次必须按失败上报，不得当作「0 行=已清完」。
type rowsAffectedFailureResult struct{}

var errRowsAffectedUnavailable = errors.New("driver does not support RowsAffected")

func (rowsAffectedFailureResult) LastInsertId() (int64, error) { return 0, nil }
func (rowsAffectedFailureResult) RowsAffected() (int64, error) {
	return 0, errRowsAffectedUnavailable
}

func TestNotificationDeliveryRetentionCleanup_rowsAffectedErrorReportsFailure(t *testing.T) {
	initRetentionCleanupDB(t)

	previous := notificationRetentionDeleteExec
	notificationRetentionDeleteExec = func(database *sql.DB, query string, args ...any) (sql.Result, error) {
		return rowsAffectedFailureResult{}, nil
	}
	t.Cleanup(func() { notificationRetentionDeleteExec = previous })

	result, err := NotificationDeliveryRetentionCleanup(context.Background())
	if err == nil {
		t.Fatalf("RowsAffected 错误必须上抛（不得按清理完成收尾），got result=%+v", result)
	}
	if !errors.Is(err, errRowsAffectedUnavailable) {
		t.Fatalf("err=%v, want wrapped %v", err, errRowsAffectedUnavailable)
	}
}
