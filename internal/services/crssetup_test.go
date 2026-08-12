package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSetupDiff(t *testing.T) {
	cases := []struct {
		name  string
		stock []string
		live  []string
		want  []string
	}{
		{"identical returns empty", []string{"a", "b"}, []string{"a", "b"}, nil},
		{"live additions are returned", []string{"a"}, []string{"a", "SecRule custom"}, []string{"SecRule custom"}},
		{"modified line is returned", []string{"SecRuleEngine On"}, []string{"SecRuleEngine DetectionOnly"}, []string{"SecRuleEngine DetectionOnly"}},
		{"comments are significant", []string{"SecRule id:1"}, []string{"# SecRule id:1"}, []string{"# SecRule id:1"}},
		{"order is preserved", []string{"a"}, []string{"z", "a", "y", "x"}, []string{"z", "y", "x"}},
		{"blank lines are skipped", []string{"a"}, []string{"a", "", "   ", "b"}, []string{"b"}},
		{"empty live returns empty", []string{"a"}, nil, nil},
		{"stock superset returns empty", []string{"a", "b", "c"}, []string{"a", "c"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSetupDiff(tc.stock, tc.live)
			if len(got) != len(tc.want) {
				t.Fatalf("extractSetupDiff()=%v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("extractSetupDiff()[%d]=%q, want %q (got %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestCRSUpdateRun_migratesSetupCustomizationsAndInstallsNewStock(t *testing.T) {
	// Given a live setup that diverges from the installed stock baseline
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "stock-a\nstock-b\nstock-c\n")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "stock-a\nstock-b-modified\nstock-c\nuser-custom\n")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "new-stock-1\nnew-stock-2\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When the update runs to completion
	m.run("manual")

	// Then the new stock setup is installed and recorded as the next baseline
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf"} {
		data, err := os.ReadFile(filepath.Join(m.crsDir, name))
		if err != nil || string(data) != "new-stock-1\nnew-stock-2\n" {
			t.Fatalf("%s=%q,%v, want new stock setup", name, data, err)
		}
	}

	// And the customizations were carried into the overrides file with a header
	overrides, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil {
		t.Fatalf("zz-user-overrides.conf missing: %v", err)
	}
	content := string(overrides)
	if !strings.Contains(content, "# 由 CRS 更新自动迁移的用户自定义配置") {
		t.Fatalf("overrides missing migration header: %q", content)
	}
	for _, line := range []string{"stock-b-modified", "user-custom"} {
		if !strings.Contains(content, line) {
			t.Fatalf("overrides missing %q: %q", line, content)
		}
	}
	if strings.Contains(content, "stock-a") {
		t.Fatalf("overrides should not contain stock lines: %q", content)
	}

	// And the migration was logged with the extracted line count
	logData, err := os.ReadFile(CRSUpdateLogPath())
	if err != nil || !strings.Contains(string(logData), "已迁移 2 行用户自定义配置到 zz-user-overrides.conf") {
		t.Fatalf("crs-update.log=%q,%v, want migration entry with count", logData, err)
	}
}

func TestCRSUpdateRun_firstMigrationDiffsAgainstDistBaseline(t *testing.T) {
	// Given no stock baseline file (pre-migration install) but the image dist copy
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	distDir := t.TempDir()
	oldDistDir := crsDistDir
	crsDistDir = distDir
	t.Cleanup(func() { crsDistDir = oldDistDir })
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "SecRuleEngine On\nSecRequestBodyAccess On\n")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"),
		"SecRuleEngine On\nSecRequestBodyAccess On\nSecRule ARGS \"@rx attack\" \"id:1001,deny\"\n")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "SecRuleEngine On\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When the update runs
	m.run("manual")

	// Then only the user line was migrated, proving the dist baseline was used
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	overrides, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil {
		t.Fatalf("zz-user-overrides.conf missing: %v", err)
	}
	content := string(overrides)
	if !strings.Contains(content, `SecRule ARGS "@rx attack" "id:1001,deny"`) {
		t.Fatalf("overrides missing user rule: %q", content)
	}
	if strings.Contains(content, "SecRequestBodyAccess") {
		t.Fatalf("overrides should not contain dist baseline lines: %q", content)
	}
}

func TestCRSUpdateRun_rollbackRestoresPreviousLiveSetup(t *testing.T) {
	// Given a stock baseline path blocked by a stray directory, so the
	// baseline rewrite fails after the new setup was installed
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")
	if err := os.MkdirAll(filepath.Join(m.crsDir, "crs-setup.stock.conf"), 0755); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "# new setup",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the update fails during the baseline write
	m.run("manual")

	// Then the previous live setup and rules are restored
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# tweaked" {
		t.Fatalf("crs-setup.conf=%q, want restored previous setup", setup)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("rules backup should have been restored")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); !os.IsNotExist(err) {
		t.Fatal("new rules should be rolled back")
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (reload after restore)", reloads)
	}

	// And the overrides written during the attempt is left in place
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf")); err != nil {
		t.Fatal("zz-user-overrides.conf should survive rollback")
	}
}

func TestCRSUpdateRun_installsStockSetupWhenNoneExists(t *testing.T) {
	// Given a live rules tree without any crs-setup.conf
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example": "stock-setup\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})

	// When the update runs
	m.run("manual")

	// Then the stock setup is installed and recorded as baseline, no overrides
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q (%s), want success", status, message)
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf"} {
		data, err := os.ReadFile(filepath.Join(m.crsDir, name))
		if err != nil || string(data) != "stock-setup\n" {
			t.Fatalf("%s=%q,%v, want stock setup", name, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "zz-user-overrides.conf")); !os.IsNotExist(err) {
		t.Fatal("no overrides file should be written when there is nothing to migrate")
	}
}

func TestRestoreBackup_restoresSetupAndLeavesMigrationArtifacts(t *testing.T) {
	// Given backups in place, clobbered live files, and migration artifacts
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules.bak", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf.bak"), "# previous")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-NEW.conf"), "SecRule new")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# clobbered")
	writeTestFile(t, filepath.Join(m.crsDir, "zz-user-overrides.conf"), "# migrated")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# stock")

	// When the backup is restored
	m.restoreBackup()

	// Then rules and setup are back and the backups consumed
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("rules backup not restored")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-NEW.conf")); !os.IsNotExist(err) {
		t.Fatal("clobbered rules should be gone")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
		t.Fatal("rules.bak should be consumed")
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# previous" {
		t.Fatalf("crs-setup.conf=%q, want restored backup", setup)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "crs-setup.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("crs-setup.conf.bak should be consumed")
	}

	// And the migration artifacts are untouched
	for name, want := range map[string]string{
		"zz-user-overrides.conf": "# migrated",
		"crs-setup.stock.conf":   "# stock",
	} {
		data, err := os.ReadFile(filepath.Join(m.crsDir, name))
		if err != nil || string(data) != want {
			t.Fatalf("%s=%q,%v, want untouched %q", name, data, err, want)
		}
	}
}
