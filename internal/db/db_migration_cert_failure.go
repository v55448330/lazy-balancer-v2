package db

import (
	"fmt"
	"log"
)

// certCooldownExpiredNote 追加到「冷却窗口已过期」失败行 message 的终态标记。
// 追加幂等判据同用此串（message 已含标记不重复加）。
const certCooldownExpiredNote = "（冷却已过期，可直接重试）"

// normalizeWaitingCAWrite 登记 waiting_ca→failed 的保窗归一（启动迁移与配置
// 导入提交后共用，见 NormalizeWaitingCACertJobs）。
func normalizeWaitingCAWrite() migrationWrite {
	return updateWhere("cert_jobs", "status='failed'", "status='waiting_ca'")
}

// expiredCooldownMessageWrite 登记「冷却窗口已过期的 failed 行 message 追加
// 终态说明」：消除「message 说等待冷却、冷却却已过」的显示滞后。幂等：
// message 已含标记（或为 NULL/空串走覆盖分支）不重复追加；NULL 窗口
// （已达上限仅手动重试）与窗口仍在未来的行不加注。
func expiredCooldownMessageWrite() migrationWrite {
	where := "status='failed' AND ca_available_after IS NOT NULL AND datetime(ca_available_after) <= datetime('now')" +
		" AND (message IS NULL OR message NOT LIKE '%" + certCooldownExpiredNote + "%')"
	write := "UPDATE cert_jobs SET message = CASE WHEN COALESCE(message,'')='' THEN '冷却已过期，可直接重试'" +
		" ELSE message || '" + certCooldownExpiredNote + "' END WHERE " + where
	return migrationWrite{table: "cert_jobs", where: where, write: write}
}

// NormalizeWaitingCACertJobs 将 cert_jobs 中残留的 waiting_ca 行保窗归一为
// failed（仅改 status，保留 message/renewal_attempts/ca_available_after/
// last_error_code，与启动迁移同谓词同字段集）。两个消费方：
//   - 启动迁移 migrateCertJobsWaitingCA（存量库存量）；
//   - 配置导入/还原提交后（旧备份可能携带 waiting_ca 存量——导入路径不经过
//     启动迁移，必须在恢复重排 requeueNonTerminalCertJobs 之前归一，退役状态
//     不得重新进入活库）。
//
// 返回归一行数；失败上抛。
func NormalizeWaitingCACertJobs() (int64, error) {
	result, err := execMigrationWriteIfNeeded(normalizeWaitingCAWrite())
	if err != nil {
		return 0, fmt.Errorf("failed to normalize waiting_ca certificate jobs: %w", err)
	}
	if result == nil {
		return 0, nil
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read waiting_ca normalization count: %w", err)
	}
	return n, nil
}

// migrateCertJobsWaitingCA 实现 ACME 失败语义统一（B2）的存量迁移：waiting_ca
// 停车状态退役——429 与其它失败统一落 failed，不再产生 waiting_ca。存量
// waiting_ca 行转为 failed，保留 message/renewal_attempts/ca_available_after/
// last_error_code：
//   - 窗口仍在未来的行由 cert-waiting-ca 30s 补扫按到期重排（scanWaitingCACandidates
//     新谓词 failed+窗口到期）；
//   - 窗口 NULL（已达上限）的行停留 failed，仅手动重试；
//   - 手动重试/强制重试的冷却门按 failed+窗口同语义生效。
//
// 窗口已过期的行同步把 message 追加终态说明（certCooldownExpiredNote）——
// 等待行由补扫按到期重排，库文案停留冷却语境会让「冷却明明已过」的行继续
// 显示等待（导入/旧备份带入的过期行尤其如此）。
//
// 幂等：WHERE status='waiting_ca' 保证二次执行零命中；message 追加按标记
// 去重；updated_at 不改写（failed 行的通用重试冷却按 updated_at 起算，
// 保留原值让存量行立即可手动重试）。
func migrateCertJobsWaitingCA() error {
	normalized, err := NormalizeWaitingCACertJobs()
	if err != nil {
		return fmt.Errorf("failed to migrate waiting_ca certificate jobs: %w", err)
	}
	if normalized > 0 {
		detail := fmt.Sprintf("启动迁移：证书任务失败语义统一，存量 waiting_ca 行转为 failed（保留消息/重试次数/退避窗口）：%d 条", normalized)
		log.Print(detail)
		recordSystemAudit("启动迁移", "证书任务", detail)
	}
	// 经 execMigrationWriteIfNeeded 同一惯用法（探测零命中即跳过）；追加按
	// 标记去重，收敛库上二次启动零命中。
	annotated, err := execMigrationWriteIfNeeded(expiredCooldownMessageWrite())
	if err != nil {
		return fmt.Errorf("failed to annotate expired ca cooldown messages: %w", err)
	}
	if annotated != nil {
		if n, err := annotated.RowsAffected(); err == nil && n > 0 {
			detail := fmt.Sprintf("启动迁移：%d 条失败证书任务的冷却窗口已过期，message 追加终态说明「%s」", n, certCooldownExpiredNote)
			log.Print(detail)
			recordSystemAudit("启动迁移", "证书任务", detail)
		}
	}
	return nil
}
