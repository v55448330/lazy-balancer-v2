package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWafFileBundleRoundTrip(t *testing.T) {
	src := t.TempDir()
	rules := filepath.Join(src, "crs", "rules")
	os.MkdirAll(rules, 0755)
	os.WriteFile(filepath.Join(rules, "a.conf"), []byte("SecRule X 1"), 0644)
	os.WriteFile(filepath.Join(rules, "sub", "b.conf"), []byte("SecRule X 2"), 0644)
	os.WriteFile(filepath.Join(src, "crs", "VERSION"), []byte("v4.14.0"), 0644)

	oldLive := crsLiveDir
	oldXdb := ip2regionLivePath
	crsLiveDir = filepath.Join(src, "crs")
	ip2regionLivePath = filepath.Join(src, "ip2region.xdb")
	defer func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb }()
	os.WriteFile(ip2regionLivePath, []byte("fake-xdb-bytes"), 0644)

	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGzB64) == 0 || len(bundle.XdbB64) == 0 {
		t.Fatalf("bundle incomplete: %+v", bundle)
	}
	ref := BuildWafFileRef()
	if ref == nil || ref.CRSSha256 != bundle.CRSSha256 || ref.IP2RegionSha != bundle.IP2RegionSha {
		t.Fatalf("ref/hash mismatch: %+v vs %+v", ref, bundle)
	}
	if wafFilesRefDiffers(ref) {
		t.Fatalf("ref should match local after build")
	}
	if !wafFilesRefMatchesBundle(ref, bundle) {
		t.Fatalf("bundle must match its ref")
	}

	// First apply to an empty live dir → changed
	os.RemoveAll(filepath.Join(src, "crs"))
	os.MkdirAll(filepath.Join(src, "crs"), 0755)
	os.Remove(ip2regionLivePath)
	changed, err := ApplyWafFileBundle(bundle)
	if err != nil || !changed {
		t.Fatalf("first apply changed=%v err=%v", changed, err)
	}
	if got, _ := os.ReadFile(filepath.Join(rules, "a.conf")); string(got) != "SecRule X 1" {
		t.Fatalf("rules not restored: %q", got)
	}
	if got, _ := os.ReadFile(ip2regionLivePath); string(got) != "fake-xdb-bytes" {
		t.Fatalf("xdb not restored: %q", got)
	}

	// Identical content → differs=false and apply is a no-op
	if wafFilesRefDiffers(ref) {
		t.Fatalf("identical files must not be re-fetched")
	}
	changed, err = ApplyWafFileBundle(bundle)
	if err != nil || changed {
		t.Fatalf("idempotent apply changed=%v err=%v", changed, err)
	}
}
