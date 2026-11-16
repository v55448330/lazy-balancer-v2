package db

import (
	"database/sql/driver"
	"fmt"
	"log"
	"strconv"
	"sync"
	"unicode/utf8"

	gosqlite "github.com/glebarez/go-sqlite"
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
// （已达上限仅手动重试）与窗口仍在未来的行不加注。启动迁移与配置导入
// 提交后共用（见 AnnotateExpiredCooldownMessages）。
//
// 长度契约与 services.maxJobMessageBytes（1024 字节）同口径：先把 base 截到
// 「上限-说明长度」字节预算再追加。截断经驱动级 UDF lb_trunc_utf8（Go 字节
// 语义+UTF-8 边界回退）——纯 SQL 无法可靠表达：TEXT substr 按字符计（多字节
// base 超限），BLOB substr 按字节但 modernc 的 CAST/length 对非法 UTF-8 尾部
// 不做逐字节替换，边界判定不可靠（实测 v1.56.0）。裸 `message || note` 会让
// 带外/旧备份的超长 message 绕过上限。
func expiredCooldownMessageWrite() migrationWrite {
	where := "status='failed' AND ca_available_after IS NOT NULL AND datetime(ca_available_after) <= datetime('now')" +
		" AND (message IS NULL OR message NOT LIKE '%" + certCooldownExpiredNote + "%')"
	baseBudget := strconv.Itoa(1024 - len(certCooldownExpiredNote))
	write := "UPDATE cert_jobs SET message = CASE WHEN COALESCE(message,'')='' THEN '" + certCooldownExpiredNote + "'" +
		" ELSE lb_trunc_utf8(message, " + baseBudget + ") || '" + certCooldownExpiredNote + "' END WHERE " + where
	return migrationWrite{table: "cert_jobs", where: where, write: write}
}

var registerTruncUDFOnce sync.Once

// ensureTruncUTF8UDF 注册 lb_trunc_utf8(text, maxBytes)：按字节预算截断并回退
// 合法 UTF-8 边界（与 services.truncateJobMessage 同语义）。驱动级注册对所有
// 此后新建连接生效（主库/审计/metrics 与测试库同驱动）；重复注册会报错，
// sync.Once 保证进程内只注册一次。
func ensureTruncUTF8UDF() {
	registerTruncUDFOnce.Do(func() {
		gosqlite.MustRegisterDeterministicScalarFunction("lb_trunc_utf8", 2, func(_ *gosqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("lb_trunc_utf8 expects 2 arguments")
			}
			var text string
			switch v := args[0].(type) {
			case string:
				text = v
			case []byte:
				text = string(v)
			case nil:
				return "", nil
			default:
				return nil, fmt.Errorf("lb_trunc_utf8: unsupported text type %T", args[0])
			}
			budget, ok := args[1].(int64)
			if !ok {
				return nil, fmt.Errorf("lb_trunc_utf8: unsupported budget type %T", args[1])
			}
			if budget <= 0 {
				return "", nil
			}
			if int64(len(text)) <= budget {
				return text, nil
			}
			b := []byte(text[:budget])
			for len(b) > 0 && !utf8.Valid(b) {
				b = b[:len(b)-1]
			}
			return string(b), nil
		})
	})
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

// AnnotateExpiredCooldownMessages 给「冷却窗口已过期」的 failed 行 message
// 追加终态说明（certCooldownExpiredNote），返回追加行数。两个消费方：
//   - 启动迁移 migrateCertJobsWaitingCA（存量库）；
//   - 配置导入/还原提交后（importQueueRecovery.finish）——旧备份带入的过期
//     冷却行不经过启动迁移，库文案停留冷却语境会让「冷却明明已过」的行继续
//     显示等待。
//
// 幂等：message 已含标记不重复追加；经 execMigrationWriteIfNeeded 探测，
// 零命中即跳过。失败上抛。
func AnnotateExpiredCooldownMessages() (int64, error) {
	ensureTruncUTF8UDF()
	result, err := execMigrationWriteIfNeeded(expiredCooldownMessageWrite())
	if err != nil {
		return 0, fmt.Errorf("failed to annotate expired ca cooldown messages: %w", err)
	}
	if result == nil {
		return 0, nil
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read expired cooldown annotation count: %w", err)
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
	// 追加按标记去重（AnnotateExpiredCooldownMessages 单源，与导入 finish
	// 共用），收敛库上二次启动零命中。
	annotated, err := AnnotateExpiredCooldownMessages()
	if err != nil {
		return err
	}
	if annotated > 0 {
		detail := fmt.Sprintf("启动迁移：%d 条失败证书任务的冷却窗口已过期，message 追加终态说明「%s」", annotated, certCooldownExpiredNote)
		log.Print(detail)
		recordSystemAudit("启动迁移", "证书任务", detail)
	}
	return nil
}
