package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// forceRenameFailure makes every rename fail, simulating Docker overlayfs
// EXDEV when the source lives in an image-baked lower layer.
func forceRenameFailure(t *testing.T) {
	t.Helper()
	old := osRename
	osRename = func(_, _ string) error { return errors.New("forced: invalid cross-device link") }
	t.Cleanup(func() { osRename = old })
}

func TestMoveTree_renameSucceeds(t *testing.T) {
	// Given a source tree with a nested file
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	writeTestFile(t, filepath.Join(src, "sub", "a.conf"), "SecRule 1")

	// When moving the tree
	if err := moveTree(src, dst); err != nil {
		t.Fatal(err)
	}

	// Then the content lands at dst and src is gone
	data, err := os.ReadFile(filepath.Join(dst, "sub", "a.conf"))
	if err != nil || string(data) != "SecRule 1" {
		t.Fatalf("dst content=%q,%v", data, err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("src should be gone after moveTree")
	}
}

func TestMoveTree_fallsBackToCopyWhenRenameFails(t *testing.T) {
	// Given a source tree and a rename that always fails (overlayfs EXDEV)
	forceRenameFailure(t)
	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	writeTestFile(t, filepath.Join(src, "rules", "REQUEST-900.conf"), "SecRule 1")
	writeTestFile(t, filepath.Join(src, "rules", "REQUEST-901.conf"), "SecRule 2")

	// When moving the tree
	if err := moveTree(src, dst); err != nil {
		t.Fatal(err)
	}

	// Then every file was copied and the source was removed
	for _, rel := range []string{"rules/REQUEST-900.conf", "rules/REQUEST-901.conf"} {
		if _, err := os.Stat(filepath.Join(dst, rel)); err != nil {
			t.Fatalf("expected %s copied: %v", rel, err)
		}
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("src should be removed after copy fallback")
	}
}

func TestCRSUpdateRun_successWhenRenameUnavailable(t *testing.T) {
	// Given an environment where rename always fails (Docker overlayfs)
	forceRenameFailure(t)
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When a manual update runs to completion
	m.run("manual")

	// Then the update succeeds despite rename being unavailable
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); err != nil {
		t.Fatal("new rules not in place")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); !os.IsNotExist(err) {
		t.Fatal("old rules should be replaced")
	}
}
