package services

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// CRS seed sources for an empty live rules tree.
const (
	crsSeedFromSnapshot = "snapshot"
	crsSeedFromDist     = "dist"
)

// decideCRSSeedSource picks where an empty live CRS tree is seeded from: the
// persisted snapshot wins only when it carries a version different from the
// image-bundled rules (i.e. the user installed an update at some point);
// anything else falls back to the pristine image copy.
func decideCRSSeedSource(distVersion, snapshotVersion string, snapshotExists bool) string {
	if snapshotExists && snapshotVersion != distVersion {
		return crsSeedFromSnapshot
	}
	return crsSeedFromDist
}

// SeedCRSRules populates the live CRS dir when a fresh /app/waf bind mount
// hides the image-baked rules: seed from the persisted snapshot when it
// carries user-updated rules, otherwise from the pristine waf.dist copy.
func SeedCRSRules() {
	seedCRSRulesFrom(crsLiveDir, crsSnapshotDir, crsDistDir)
}

func seedCRSRulesFrom(liveDir, snapshotDir, distDir string) {
	if _, err := os.Stat(filepath.Join(liveDir, "rules")); err == nil {
		return
	}
	// The bind mount also hides the aux dirs referenced by the generated WAF
	// config (SecAuditLog lives under waf/audit), so recreate the skeleton.
	wafDir := filepath.Dir(liveDir)
	for _, sub := range []string{"custom", "audit"} {
		if err := os.MkdirAll(filepath.Join(wafDir, sub), 0755); err != nil {
			log.Printf("crs seed: failed to create %s: %v", filepath.Join(wafDir, sub), err)
		}
	}

	snapshotVersion := ""
	if data, err := os.ReadFile(filepath.Join(snapshotDir, "VERSION")); err == nil {
		snapshotVersion = strings.TrimSpace(string(data))
	}
	if _, err := os.Stat(filepath.Join(snapshotDir, "rules")); err != nil {
		snapshotVersion = "" // a snapshot without a rules tree is unusable
	}
	src := distDir
	if decideCRSSeedSource(CRSBundledVersion, snapshotVersion, snapshotVersion != "") == crsSeedFromSnapshot {
		src = snapshotDir
	}
	if err := copyDir(filepath.Join(src, "rules"), filepath.Join(liveDir, "rules")); err != nil {
		log.Printf("crs seed: failed to seed rules from %s: %v", src, err)
		return
	}
	setupPath := filepath.Join(liveDir, "crs-setup.conf")
	if _, err := os.Stat(setupPath); os.IsNotExist(err) {
		if err := copyFile(filepath.Join(src, "crs-setup.conf"), setupPath); err != nil {
			log.Printf("crs seed: failed to seed crs-setup.conf from %s: %v", src, err)
		}
	}
	log.Printf("crs seed: seeded %s from %s", liveDir, src)
}
