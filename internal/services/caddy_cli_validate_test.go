package services

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecCaddyValidate_classifiesSuccessRejectAndUnavailable(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "caddy")
	writeScript := func(body string) {
		t.Helper()
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("success", func(t *testing.T) {
		writeScript("#!/bin/sh\nexit 0\n")
		t.Setenv("PATH", dir)
		if err := execCaddyValidate([]byte(`{"apps":{}}`)); err != nil {
			t.Fatalf("validate success: %v", err)
		}
	})

	t.Run("reject", func(t *testing.T) {
		writeScript("#!/bin/sh\necho 'provision failed' >&2\nexit 1\n")
		t.Setenv("PATH", dir)
		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if err == nil || errors.Is(err, ErrCLIValidatorUnavailable) || !strings.Contains(err.Error(), "拒绝配置") || !strings.Contains(err.Error(), "provision failed") {
			t.Fatalf("validate reject error=%v, want rejected with stderr", err)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if !errors.Is(err, ErrCLIValidatorUnavailable) {
			t.Fatalf("missing caddy error=%v, want ErrCLIValidatorUnavailable", err)
		}
	})
}
