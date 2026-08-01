package handlers

import (
	"errors"
	"strings"
	"testing"
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
