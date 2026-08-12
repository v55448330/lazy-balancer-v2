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
