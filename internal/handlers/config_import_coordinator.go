package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

type importPhase string

const (
	importPhaseSnapshot    importPhase = "snapshot"
	importPhaseCertificate importPhase = "certificate"
	importPhaseCaddy       importPhase = "caddy"
	importPhaseVersion     importPhase = "version"
	importPhaseCommit      importPhase = "commit"
	importPhaseQueue       importPhase = "queue"
)

type importCoordinatorError struct {
	phase importPhase
	err   error
}

func (err *importCoordinatorError) Error() string { return importFailureAuditDescription(err) }
func (err *importCoordinatorError) Unwrap() error { return err.err }

func importFailureAuditDescription(err error) string {
	var coordinatorErr *importCoordinatorError
	if !errors.As(err, &coordinatorErr) {
		return "导入失败：" + err.Error()
	}
	var description string
	switch coordinatorErr.phase {
	case importPhaseSnapshot:
		description = "导入失败（运行配置快照失败，数据库未变更）"
	case importPhaseCertificate:
		description = "导入失败（证书准备失败，数据库未变更）"
	case importPhaseCaddy:
		description = "导入失败（Caddy 验证失败，数据库未变更）"
	case importPhaseVersion:
		description = "导入失败（集群版本更新失败，数据库未变更）"
	case importPhaseCommit:
		description = "导入失败（数据库提交失败，数据库未变更）"
	case importPhaseQueue:
		description = "导入部分失败（数据库已提交，证书任务恢复失败）"
	default:
		description = "导入失败"
	}
	return description + "：" + coordinatorErr.err.Error()
}

type configImportSession struct {
	h               *Handlers
	ctx             context.Context
	tx              *sql.Tx
	recovery        importQueueRecovery
	existingRuleIDs []string
	runtime         *importRuntimeSnapshot
	committed       bool
	finished        bool
}

func (h *Handlers) beginConfigImport(ctx context.Context) (*configImportSession, error) {
	h.caddyOpMu.Lock()
	session := &configImportSession{h: h, ctx: ctx, recovery: importQueueRecovery{manager: services.GetCAQueueManager()}}
	ruleIDs, err := currentRuleIDs(ctx)
	if err != nil {
		h.caddyOpMu.Unlock()
		return nil, fmt.Errorf("读取现有规则: %w", err)
	}
	session.existingRuleIDs = ruleIDs
	if session.recovery.manager != nil {
		session.recovery.manager.PauseAndDrain()
	}
	session.tx, err = db.DB.BeginTx(ctx, nil)
	if err != nil {
		err = finishImportFailure(nil, &session.recovery, err)
		h.caddyOpMu.Unlock()
		return nil, fmt.Errorf("开始导入事务: %w", err)
	}
	return session, nil
}

func (session *configImportSession) close() {
	if !session.finished {
		_ = session.abort(errors.New("导入流程未完成"))
	}
	session.h.caddyOpMu.Unlock()
}

func (session *configImportSession) abort(importErr error) error {
	if session.finished {
		return importErr
	}
	if session.runtime != nil {
		if restoreErr := session.h.restoreImportRuntime(*session.runtime); restoreErr != nil {
			importErr = errors.Join(importErr, fmt.Errorf("恢复运行配置失败: %w", restoreErr))
		}
	}
	session.finished = true
	return finishImportFailure(session.tx, &session.recovery, importErr)
}

func (session *configImportSession) commit(affectedRuleIDs []string, certificates []importCertificate) error {
	runtime, err := session.h.snapshotImportRuntime(affectedRuleIDs)
	if err != nil {
		return &importCoordinatorError{phase: importPhaseSnapshot, err: session.abort(err)}
	}
	session.runtime = &runtime
	if err := materializeImportCertificates(certificates); err != nil {
		return &importCoordinatorError{phase: importPhaseCertificate, err: session.abort(err)}
	}
	// R65 A-N1：v2 导入事务全量重插 cert_jobs（restoreTable 保留原 id），证书
	// 候选必须读事务自身——经已提交视图会拿到将被替换的旧行，旧 PEM 覆写导入
	// 刚落盘的新证书文件。导入期 CA 队列已 PauseAndDrain，无并发证书提交。
	if err := session.h.caddyService.ApplyConfigFromTxCertAware(session.tx); err != nil {
		return &importCoordinatorError{phase: importPhaseCaddy, err: session.abort(err)}
	}
	if err := services.BumpClusterVersion(session.ctx, session.tx); err != nil {
		return &importCoordinatorError{phase: importPhaseVersion, err: session.abort(err)}
	}
	if err := session.tx.Commit(); err != nil {
		return &importCoordinatorError{phase: importPhaseCommit, err: session.abort(err)}
	}
	session.committed = true
	session.runtime = nil
	// R66 C-F1/C-F2：全量替换导入对消失规则的产物清理。v2/v1 导入均清光
	// lb_rules 后重插（v1 还换新 caddy_id），但产物轴此前只写不删：消失规则的
	// 证书文件（含 ACME 私钥）在 /app/certs 无限残留——与 DeleteRule「规则消失
	// → 密钥删除」的约定矛盾，卷读权限者可恢复管理员以为已删除的密钥；v1 路径
	// 还遗留指向已删 caddy_id 的孤儿 cert_jobs 行（终态行永不清理，任务列表
	// 噪音）。提交成功后按 begin 期收集的 existingRuleIDs 求差清理（v2 的
	// 事务内孤儿 SQL 幂等重复无害）。清理失败不否决导入（数据已提交），
	// 留痕审计 + 日志。
	session.cleanupDisappearedRuleArtifacts()
	if err := session.recovery.finish(); err != nil {
		session.finished = true
		return &importCoordinatorError{phase: importPhaseQueue, err: err}
	}
	session.finished = true
	return nil
}

func importFailurePhase(err error) importPhase {
	var coordinatorErr *importCoordinatorError
	if errors.As(err, &coordinatorErr) {
		return coordinatorErr.phase
	}
	return ""
}

// cleanupDisappearedRuleArtifacts 清理本次导入中消失规则的产物（R66 C-F1/F2）：
// 证书文件 + 孤儿 cert_jobs 行。提交成功后调用；失败仅审计留痕，不否决导入。
func (session *configImportSession) cleanupDisappearedRuleArtifacts() {
	currentIDs, err := currentRuleIDs(session.ctx)
	if err != nil {
		services.Logf("error", "导入清理：读取当前规则失败（跳过孤儿清理）: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理消失规则产物失败（读取规则集）：%v", err), "")
		return
	}
	current := make(map[string]struct{}, len(currentIDs))
	for _, id := range currentIDs {
		current[id] = struct{}{}
	}
	var disappeared []string
	for _, id := range session.existingRuleIDs {
		if _, alive := current[id]; !alive {
			disappeared = append(disappeared, id)
		}
	}
	if len(disappeared) == 0 {
		return
	}
	for _, id := range disappeared {
		if err := services.RemoveCertFiles(id); err != nil {
			services.Logf("warn", "导入清理：删除消失规则 %s 的证书文件失败: %v", id, err)
		}
	}
	// 与 v2 导入事务内的孤儿清理同语句（幂等重复无害）；覆盖 v1 路径与
	// 理论上的绕过路径。
	if _, err := db.DB.ExecContext(session.ctx,
		`DELETE FROM cert_jobs WHERE rule_id NOT IN (SELECT caddy_id FROM lb_rules)`); err != nil {
		services.Logf("error", "导入清理：删除孤儿证书任务失败: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书任务", fmt.Sprintf("导入后清理孤儿证书任务失败：%v", err), "")
		return
	}
	services.RecordAuditLog("system", "清理", "证书产物", fmt.Sprintf("导入移除 %d 条规则，已清理其证书文件与任务行", len(disappeared)), "")
}
