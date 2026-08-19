package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeBundleVersion(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{name: "empty", input: "", want: ""},
		{name: "valid semver", input: "v4.28.0", want: "v4.28.0"},
		{name: "valid with separators", input: "v4.28.0-beta.1+x86_64", want: "v4.28.0-beta.1+x86_64"},
		{name: "valid max length", input: strings.Repeat("v", 64), want: strings.Repeat("v", 64)},
		{name: "too long", input: strings.Repeat("v", 65), want: ""},
		{name: "newline injection", input: "v4.28.0\nINJECTED", want: ""},
		{name: "control char", input: "v4.28.0\x01", want: ""},
		{name: "trailing space", input: "v4.28.0 ", want: ""},
		{name: "slash", input: "v4/28", want: ""},
		{name: "chinese", input: "v4.版本", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeBundleVersion(tt.input); got != tt.want {
				t.Fatalf("sanitizeBundleVersion(%q)=%q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

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

	// First apply to an empty live dir → both components changed
	os.RemoveAll(filepath.Join(src, "crs"))
	os.MkdirAll(filepath.Join(src, "crs"), 0755)
	os.Remove(ip2regionLivePath)
	crsChanged, xdbChanged, err := ApplyWafFileBundle(bundle)
	if err != nil || !crsChanged || !xdbChanged {
		t.Fatalf("first apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
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
	crsChanged, xdbChanged, err = ApplyWafFileBundle(bundle)
	if err != nil || crsChanged || xdbChanged {
		t.Fatalf("idempotent apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
}

func TestApplyWafFileBundleRejectsTamperedBytes(t *testing.T) {
	src := t.TempDir()
	srcRules := filepath.Join(src, "crs", "rules")
	os.MkdirAll(srcRules, 0755)
	os.WriteFile(filepath.Join(srcRules, "a.conf"), []byte("SecRule X 1"), 0644)
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

	// Target live tree: empty, ready to receive the sync.
	dst := t.TempDir()
	dstRules := filepath.Join(dst, "crs", "rules")
	crsLiveDir = filepath.Join(dst, "crs")
	ip2regionLivePath = filepath.Join(dst, "ip2region.xdb")
	os.MkdirAll(crsLiveDir, 0755)

	// Tampered CRS tar.gz: declared hash unchanged, bytes differ.
	tampered := *bundle
	tamperDir := t.TempDir()
	if err := untarGzTo(bundle.CRSTarGzB64, tamperDir, ""); err != nil {
		t.Fatalf("untar bundle: %v", err)
	}
	os.WriteFile(filepath.Join(tamperDir, "rules", "a.conf"), []byte("SecRule X EVIL"), 0644)
	data, _, err := tarGzDir(tamperDir)
	if err != nil {
		t.Fatalf("re-archive tampered: %v", err)
	}
	tampered.CRSTarGzB64 = data
	tampered.XdbB64 = nil
	if _, _, err := ApplyWafFileBundle(&tampered); err == nil {
		t.Fatalf("tampered CRS must be rejected")
	}
	if _, err := os.Stat(filepath.Join(dstRules, "a.conf")); !os.IsNotExist(err) {
		t.Fatalf("tampered CRS must not be written to live tree")
	}

	// Tampered xdb: declared hash unchanged, bytes differ.
	tamperedXdb := *bundle
	tamperedXdb.CRSTarGzB64 = nil
	tamperedXdb.XdbB64 = append([]byte(nil), bundle.XdbB64...)
	tamperedXdb.XdbB64[0] ^= 0xFF
	if _, _, err := ApplyWafFileBundle(&tamperedXdb); err == nil {
		t.Fatalf("tampered xdb must be rejected")
	}
	if _, err := os.Stat(ip2regionLivePath); !os.IsNotExist(err) {
		t.Fatalf("tampered xdb must not be written to live path")
	}

	// Untampered bundle still applies cleanly.
	crsChanged, xdbChanged, err := ApplyWafFileBundle(bundle)
	if err != nil || !crsChanged || !xdbChanged {
		t.Fatalf("valid bundle apply crsChanged=%v xdbChanged=%v err=%v", crsChanged, xdbChanged, err)
	}
}
