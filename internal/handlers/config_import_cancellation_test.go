package handlers

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/services"
)

func TestConfigImportPostApplyWorkSurvivesRequestCancellation(t *testing.T) {
	h := newBackupTestHandlers(t)
	ctx, cancel := context.WithCancel(context.Background())
	session, err := h.beginConfigImport(ctx, "导入")
	if err != nil {
		t.Fatalf("begin import: %v", err)
	}
	defer func() {
		if !session.finished {
			_ = session.tx.Rollback()
			_ = session.recovery.finish()
			session.finished = true
		}
		session.close()
	}()

	cancel()
	if err := services.BumpClusterVersion(session.ctx, session.tx); err != nil {
		t.Fatalf("post-apply cluster version write used canceled request context: %v", err)
	}
	session.replaceRuleArtifacts = true
	if _, err := session.collectPostCommitCleanup(); err != nil {
		t.Fatalf("post-apply cleanup collection used canceled request context: %v", err)
	}
	if err := commitTx(session.tx); err != nil {
		t.Fatalf("commit after client cancellation: %v", err)
	}
	if err := session.recovery.finish(); err != nil {
		t.Fatalf("finish import recovery: %v", err)
	}
	session.finished = true
}
