package db

import (
	"fmt"
	"log"
)

// migrateCertJobsWaitingCA 实现 ACME 失败语义统一（B2）的存量迁移：waiting_ca
// 停车状态退役——429 与其它失败统一落 failed，不再产生 waiting_ca。存量
// waiting_ca 行转为 failed，保留 message/renewal_attempts/ca_available_after/
// last_error_code：
//   - 窗口仍在未来的行由 cert-waiting-ca 30s 补扫按到期重排（scanWaitingCACandidates
//     新谓词 failed+窗口到期）；
//   - 窗口 NULL（已达上限）的行停留 failed，仅手动重试；
//   - 手动重试/强制重试的冷却门按 failed+窗口同语义生效。
//
// 幂等：WHERE status='waiting_ca' 保证二次执行零命中；updated_at 不改写
// （failed 行的通用重试冷却按 updated_at 起算，保留原值让存量行立即可手动重试）。
func migrateCertJobsWaitingCA() error {
	// 经 updateWhere 单源登记（探测零命中即跳过，避免收敛库上的固定写锁成本）；
	// 与 runMigrations 其余状态归一迁移同一惯用法。
	result, err := execMigrationWriteIfNeeded(updateWhere("cert_jobs", "status='failed'", "status='waiting_ca'"))
	if err != nil {
		return fmt.Errorf("failed to migrate waiting_ca certificate jobs: %w", err)
	}
	if result != nil {
		if n, err := result.RowsAffected(); err == nil && n > 0 {
			detail := fmt.Sprintf("启动迁移：证书任务失败语义统一，存量 waiting_ca 行转为 failed（保留消息/重试次数/退避窗口）：%d 条", n)
			log.Print(detail)
			recordSystemAudit("启动迁移", "证书任务", detail)
		}
	}
	return nil
}
