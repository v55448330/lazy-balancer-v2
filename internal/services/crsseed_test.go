package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecideCRSSeedSource(t *testing.T) {
	cases := []struct {
		name            string
		distVersion     string
		snapshotVersion string
		snapshotExists  bool
		want            string
	}{
		{"snapshot carrying a newer version wins", "v4.14.0", "v4.15.0", true, crsSeedFromSnapshot},
		{"snapshot carrying any different version wins", "v4.14.0", "v4.13.0", true, crsSeedFromSnapshot},
		{"missing snapshot falls back to dist", "v4.14.0", "", false, crsSeedFromDist},
		{"snapshot equal to bundled falls back to dist", "v4.14.0", "v4.14.0", true, crsSeedFromDist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideCRSSeedSource(tc.distVersion, tc.snapshotVersion, tc.snapshotExists)
			if got != tc.want {
				t.Fatalf("decideCRSSeedSource(%q, %q, %v)=%q, want %q",
					tc.distVersion, tc.snapshotVersion, tc.snapshotExists, got, tc.want)
			}
		})
	}
}

func TestSeedCRSRules_liveRulesPresentIsNoOp(t *testing.T) {
	// Given a live CRS dir that already has rules
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", "REQUEST-900.conf"), "SecRule live")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the live tree is untouched
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule live" {
		t.Fatalf("live rules=%q,%v, want untouched", data, err)
	}
	if _, err := os.Stat(filepath.Join(liveDir, "crs-setup.conf")); !os.IsNotExist(err) {
		t.Fatal("no crs-setup.conf should appear when rules already exist")
	}
}

func TestSeedCRSRules_seedsFromSnapshotWhenVersionDiffers(t *testing.T) {
	// Given an empty live dir, a snapshot with a user-updated version, and a dist copy
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-901.conf"), "SecRule snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "crs-setup.conf"), "# snapshot setup")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then rules and setup come from the snapshot, and the waf skeleton exists
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-901.conf"))
	if err != nil || string(data) != "SecRule snapshot" {
		t.Fatalf("seeded rules=%q,%v, want snapshot content", data, err)
	}
	setup, _ := os.ReadFile(filepath.Join(liveDir, "crs-setup.conf"))
	if string(setup) != "# snapshot setup" {
		t.Fatalf("crs-setup.conf=%q, want snapshot setup", setup)
	}
	for _, sub := range []string{"custom", "audit"} {
		if info, err := os.Stat(filepath.Join(root, "waf", sub)); err != nil || !info.IsDir() {
			t.Fatalf("waf/%s missing after seed: %v", sub, err)
		}
	}
}

func TestSeedCRSRules_seedsFromDistWhenSnapshotMissing(t *testing.T) {
	// Given an empty live dir and a dist copy, but no snapshot at all
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the live tree comes from the dist copy
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("seeded rules=%q,%v, want dist content", data, err)
	}
	setup, _ := os.ReadFile(filepath.Join(liveDir, "crs-setup.conf"))
	if string(setup) != "# dist setup" {
		t.Fatalf("crs-setup.conf=%q, want dist setup", setup)
	}
}

func TestSeedCRSRules_seedsFromDistWhenSnapshotMatchesBundled(t *testing.T) {
	// Given a snapshot whose VERSION equals the bundled version (no user update)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-900.conf"), "SecRule snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), CRSBundledVersion+"\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the pristine dist copy wins over the identical snapshot
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("seeded rules=%q,%v, want dist content", data, err)
	}
}

func TestSeedCRSRules_fallsBackToDistWhenSnapshotHasNoRules(t *testing.T) {
	// Given a snapshot with a differing VERSION but no rules tree (unusable)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the dist copy is used instead of the broken snapshot
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("seeded rules=%q,%v, want dist content", data, err)
	}
}

func TestSeedCRSRules_writesVersionMarker(t *testing.T) {
	// Given an empty live dir and a snapshot carrying a user-updated version
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-901.conf"), "SecRule snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "crs-setup.conf"), "# snapshot setup")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding from the snapshot
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the live dir carries the snapshot version marker
	if got := readCRSVersionMarker(liveDir); got != "v4.15.0" {
		t.Fatalf("live marker=%q, want v4.15.0", got)
	}
}

func TestPlanCRSReconcile_matrix(t *testing.T) {
	cases := []struct {
		name                             string
		liveV, snapV, dbV, bundledV      string
		snapshotRulesExist, probeMatches bool
		want                             crsReconcileAction
		wantAmbiguous                    bool
	}{
		{"steady state: marker equals DB", "v4.15.0", "v4.15.0", "v4.15.0", "v4.14.0", true, true, crsReconcileNone, false},
		{"disk reverted: DB matches snapshot", "v4.14.0", "v4.15.0", "v4.15.0", "v4.14.0", true, false, crsReconcileRestoreSnapshot, false},
		{"no snapshot: disk is truth", "v4.28.0", "", "v4.14.0", "v4.28.0", false, false, crsReconcileCorrectDB, false},
		{"legacy marker-less disk matches snapshot content", "", "v4.15.0", "v4.15.0", "v4.14.0", true, true, crsReconcileWriteMarker, false},
		{"legacy marker-less disk differs from snapshot", "", "v4.15.0", "v4.15.0", "v4.14.0", true, false, crsReconcileRestoreSnapshot, false},
		{"legacy marker-less pristine disk", "", "", "v4.14.0", "v4.14.0", false, false, crsReconcileWriteMarker, false},
		{"legacy marker-less unknown version stays hands-off", "", "", "v4.15.0", "v4.14.0", false, false, crsReconcileNone, true},
		{"snapshot disagrees with DB: disk is truth", "v4.14.0", "v4.13.0", "v4.15.0", "v4.14.0", true, false, crsReconcileCorrectDB, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planCRSReconcile(tc.liveV, tc.snapV, tc.dbV, tc.bundledV, tc.snapshotRulesExist, tc.probeMatches)
			if plan.action != tc.want || plan.ambiguous != tc.wantAmbiguous {
				t.Fatalf("planCRSReconcile(%q,%q,%q,%q,%v,%v)=%+v, want action=%v ambiguous=%v",
					tc.liveV, tc.snapV, tc.dbV, tc.bundledV, tc.snapshotRulesExist, tc.probeMatches, plan, tc.want, tc.wantAmbiguous)
			}
		})
	}
}

func TestRestoreCRSFromSnapshot_recoversUserUpdatedTree(t *testing.T) {
	// Given a reverted live tree (image-bundled rules) and a persisted snapshot
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsProbeFile), "SecRule bundled")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsProbeFile), "SecRule updated")
	writeTestFile(t, filepath.Join(snapshotDir, "crs-setup.conf"), "# updated setup")
	writeTestFile(t, filepath.Join(snapshotDir, "zz-user-overrides.conf"), "# user lines")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.15.0\n")

	// When restoring
	if err := restoreCRSFromSnapshot(liveDir, snapshotDir, "v4.15.0"); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Then rules, setup and overrides come from the snapshot and the marker is refreshed
	rule, _ := os.ReadFile(filepath.Join(liveDir, "rules", crsProbeFile))
	if string(rule) != "SecRule updated" {
		t.Fatalf("restored rules=%q, want snapshot content", rule)
	}
	setup, _ := os.ReadFile(filepath.Join(liveDir, "crs-setup.conf"))
	if string(setup) != "# updated setup" {
		t.Fatalf("restored setup=%q, want snapshot setup", setup)
	}
	overrides, err := os.ReadFile(filepath.Join(liveDir, "zz-user-overrides.conf"))
	if err != nil || string(overrides) != "# user lines" {
		t.Fatalf("restored overrides=%q,%v, want snapshot copy", overrides, err)
	}
	if got := readCRSVersionMarker(liveDir); got != "v4.15.0" {
		t.Fatalf("live marker=%q, want v4.15.0", got)
	}
}

func TestPersistCRSSnapshotFrom_roundTrip(t *testing.T) {
	// Given an installed live tree with user overrides
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsProbeFile), "SecRule installed")
	writeTestFile(t, filepath.Join(liveDir, "crs-setup.conf"), "# installed setup")
	writeTestFile(t, filepath.Join(liveDir, "zz-user-overrides.conf"), "# user lines")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")

	// When persisting the snapshot
	if err := persistCRSSnapshotFrom(liveDir, snapshotDir, "v4.15.0"); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Then the snapshot carries rules, setup, overrides and the version marker
	for _, rel := range []string{
		filepath.Join("rules", crsProbeFile),
		"crs-setup.conf",
		"zz-user-overrides.conf",
		crsVersionFile,
	} {
		if _, err := os.Stat(filepath.Join(snapshotDir, rel)); err != nil {
			t.Fatalf("snapshot missing %s: %v", rel, err)
		}
	}
	if got := readCRSVersionMarker(snapshotDir); got != "v4.15.0" {
		t.Fatalf("snapshot marker=%q, want v4.15.0", got)
	}
}
