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

func (err *importCoordinatorError) Error() string { return err.err.Error() }
func (err *importCoordinatorError) Unwrap() error { return err.err }

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
	if err := session.h.caddyService.ApplyConfigFromTx(session.tx); err != nil {
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
