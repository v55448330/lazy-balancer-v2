// 配置导入/还原提交后（importQueueRecovery.finish），备份带入的「冷却窗口
// 已过期」failed 行必须与启动迁移同口径追加终态注记——导入路径不经过启动
// 迁移，库文案停留冷却语境会让「冷却明明已过」的行继续显示等待。

package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestConfigImportFinish_annotatesExpiredCooldownMessages(t *testing.T) {
	newBackupTestHandlers(t)
	// Given：四种形态——过期窗 waiting_ca（归一后加注）、过期窗 failed
	// （直接加注）、未来窗 failed（不加注）、NULL 窗 failed（上限终态不加注）。
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, renewal_attempts, ca_available_after, last_error_code) VALUES
		('lb_ann_w', 'ann-w.example', 'waiting_ca', '等待 CA 冷却', 2, datetime('now','-1 hour'), '429'),
		('lb_ann_f', 'ann-f.example', 'failed', '退避窗口到期未重排', 1, datetime('now','-1 minute'), NULL),
		('lb_ann_future', 'ann-future.example', 'failed', '等待冷却', 1, datetime('now','+1 hour'), '429'),
		('lb_ann_null', 'ann-null.example', 'failed', '已达最大重试次数', 5, NULL, '429')`); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}

	recovery := &importQueueRecovery{}
	if err := recovery.finish(); err != nil {
		t.Fatalf("finish: %v", err)
	}

	readMessage := func(ruleID string) string {
		t.Helper()
		var status, message string
		if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM cert_jobs WHERE rule_id=?`, ruleID).Scan(&status, &message); err != nil {
			t.Fatalf("read %s: %v", ruleID, err)
		}
		if status != "failed" {
			t.Fatalf("%s status=%q, want failed", ruleID, status)
		}
		return message
	}
	if got := readMessage("lb_ann_w"); got != "等待 CA 冷却（冷却已过期，可直接重试）" {
		t.Fatalf("过期窗 waiting_ca 归一后未加注: message=%q", got)
	}
	if got := readMessage("lb_ann_f"); got != "退避窗口到期未重排（冷却已过期，可直接重试）" {
		t.Fatalf("过期窗 failed 未加注: message=%q", got)
	}
	if got := readMessage("lb_ann_future"); got != "等待冷却" {
		t.Fatalf("未来窗行不得加注: message=%q", got)
	}
	if got := readMessage("lb_ann_null"); got != "已达最大重试次数" {
		t.Fatalf("NULL 窗（上限终态）行不得加注: message=%q", got)
	}

	// 幂等：二次 finish（新 recovery）不得重复追加。
	again := &importQueueRecovery{}
	if err := again.finish(); err != nil {
		t.Fatalf("second finish: %v", err)
	}
	for _, ruleID := range []string{"lb_ann_w", "lb_ann_f"} {
		if got := readMessage(ruleID); strings.Count(got, "（冷却已过期，可直接重试）") != 1 {
			t.Fatalf("%s 二次 finish 后注记重复: message=%q", ruleID, got)
		}
	}

	// 注记动作必须留操作审计（与归一留痕同通道）。
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='导入注记' AND resource='证书任务'`).Scan(&auditCount); err != nil {
		t.Fatalf("read annotation audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("过期注记审计行=%d, want 1", auditCount)
	}
}
