package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCRSUpdateRun_versionMarkerFailureRollsBackTreeAndVersion(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# old setup")
	writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.14.0\n")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":                "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901-INITIALIZATION.conf": "SecRule new\n",
	})
	oldWrite := crsVersionMarkerWrite
	crsVersionMarkerWrite = func(path string, data []byte, mode os.FileMode) error {
		if string(data) == "v4.15.0\n" {
			return errors.New("version marker write blocked")
		}
		return oldWrite(path, data, mode)
	}
	t.Cleanup(func() { crsVersionMarkerWrite = oldWrite })

	m.run("manual", nil)

	version, status, message, _, _, _, _ := crsVersionRow(t)
	if status == "success" || version != "v4.14.0" {
		t.Fatalf("marker failure produced version=%q status=%q message=%q, want rolled-back failed update", version, status, message)
	}
	data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("rules were not restored: data=%q err=%v", data, err)
	}
	if got := readCRSVersionMarker(m.crsDir); got != "v4.14.0" {
		t.Fatalf("marker=%q, want old version", got)
	}
}

func TestPersistCRSSnapshot_versionMismatchReturnsErrorAndKeepsOldSnapshot(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "live")
	snapshotDir := filepath.Join(root, "snapshot")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "other\n")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "previous\n")

	err := persistCRSSnapshotFrom(liveDir, snapshotDir, "expected")
	if !errors.Is(err, errCRSSnapshotVersionMismatch) {
		t.Fatalf("snapshot generation mismatch must fail with its typed error, got %v", err)
	}
	if got := readCRSVersionMarker(snapshotDir); got != "previous" {
		t.Fatalf("old snapshot was changed: marker=%q", got)
	}
}
