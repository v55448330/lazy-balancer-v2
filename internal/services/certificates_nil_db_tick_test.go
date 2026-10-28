package services

import (
	"context"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 同包 nil DB 口径统一：证书域全部周期入口在 db.DB 未装配时必须「跳过」而不是
// nil dereference。此前一半路径返回安全默认（certJobsActive 等），另一半直接
// deref——启动装配顺序或测试直构顺序一变就从可解释降级变成 panic。
func TestCertTicks_nilDatabaseSkipsWithoutPanic(t *testing.T) {
	oldMain, oldMetrics, oldAudit := db.DB, db.MetricsDB, db.AuditDB
	db.DB, db.MetricsDB, db.AuditDB = nil, nil, nil
	t.Cleanup(func() { db.DB, db.MetricsDB, db.AuditDB = oldMain, oldMetrics, oldAudit })

	t.Run("CertRenewalScanOnce", func(t *testing.T) {
		if err := CertRenewalScanOnce(context.Background()); !errors.Is(err, taskengine.ErrTaskSkipped) {
			t.Fatalf("err=%v, want ErrTaskSkipped（nil DB 必须跳过）", err)
		}
	})
	t.Run("CertManualCheckOnce", func(t *testing.T) {
		if err := CertManualCheckOnce(); !errors.Is(err, taskengine.ErrTaskSkipped) {
			t.Fatalf("err=%v, want ErrTaskSkipped（nil DB 必须跳过）", err)
		}
	})
	t.Run("CertReconcileOnce", func(t *testing.T) {
		if err := CertReconcileOnce(context.Background()); !errors.Is(err, taskengine.ErrTaskSkipped) {
			t.Fatalf("err=%v, want ErrTaskSkipped（nil DB 必须跳过）", err)
		}
	})
	t.Run("CertWaitingCATickOnce", func(t *testing.T) {
		// 该入口经 certJobsActive() 的 nil DB 门跳过：同样不得 panic。
		if err := CertWaitingCATickOnce(context.Background()); err != nil {
			t.Fatalf("err=%v, want nil（无待办任务时补扫为空轮）", err)
		}
	})
}
