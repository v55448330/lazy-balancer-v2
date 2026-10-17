package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"
)

func TestImportFailureAuditDescriptionReflectsFailurePhase(t *testing.T) {
	tests := []struct {
		name  string
		phase importPhase
		want  string
	}{
		{name: "queue recovery after commit is partial", phase: importPhaseQueue, want: "导入部分失败"},
		{name: "Caddy validation preserves database", phase: importPhaseCaddy, want: "数据库未变更"},
		{name: "certificate failure identifies preparation", phase: importPhaseCertificate, want: "证书准备失败"},
		{name: "commit failure identifies database commit", phase: importPhaseCommit, want: "数据库提交失败"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			err := &importCoordinatorError{phase: test.phase, err: errors.New("injected")}

			// When
			detail := importFailureAuditDescription(err)

			// Then
			if !strings.Contains(detail, test.want) {
				t.Fatalf("detail=%q want fragment=%q", detail, test.want)
			}
		})
	}
}

func TestBeginConfigImport_preservesStoppedCAQueue(t *testing.T) {
	// Given：cert-issuance 已被停止，CA 队列为 inactive。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	manager := services.GetCAQueueManager()
	manager.PauseAndDrain()
	if manager.IsActive() {
		t.Fatal("前置态错误：CA 队列应为 inactive")
	}

	// When：执行导入 begin/close（含 PauseAndDrain 与恢复收尾）。
	session, err := h.beginConfigImport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session.close()

	// Then：恢复不得把 inactive 队列重新激活或启动真实签发。
	if manager.IsActive() {
		t.Fatal("导入恢复了用户停止的 CA 队列（cert-issuance 生命周期被旁路）")
	}
}
