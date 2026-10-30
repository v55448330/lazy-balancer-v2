// 配置导入/还原提交后（importQueueRecovery.finish），备份携带的 waiting_ca
// 存量必须保窗归一为 failed：waiting_ca 停车状态已退役，启动迁移只覆盖启动
// 路径，导入/还原是第二个带入面——恢复重排（requeueNonTerminalCertJobs）消费
// 前不归一，退役状态就会重新进入活库并绕过 failed+窗口的重排门。

package handlers

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestConfigImportFinish_normalizesWaitingCACertJobs(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, renewal_attempts, ca_available_after, last_error_code) VALUES
		('lb_imp', 'imp.example', 'waiting_ca', '等待 CA 冷却', 2, datetime('now','+1 hour'), '429')`); err != nil {
		t.Fatalf("seed waiting_ca job: %v", err)
	}

	recovery := &importQueueRecovery{}
	if err := recovery.finish(); err != nil {
		t.Fatalf("finish: %v", err)
	}

	var status, message, errorCode string
	var attempts int
	var window any
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,''), COALESCE(renewal_attempts,0), COALESCE(last_error_code,''), ca_available_after FROM cert_jobs WHERE rule_id='lb_imp'`).Scan(&status, &message, &attempts, &errorCode, &window); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" || message != "等待 CA 冷却" || attempts != 2 || errorCode != "429" || window == nil {
		t.Fatalf("job=(status=%s message=%s attempts=%d code=%s window=%v), want failed 且保窗保字段", status, message, attempts, errorCode, window)
	}
}
