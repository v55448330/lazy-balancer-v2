package services

import (
	"path/filepath"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

func TestConfigureWafDirs_propagatesThreatWafDir(t *testing.T) {
	oldWafDir, oldIPDir, oldPrefix := wafDir, IPListDataDir, wafiplist.AllowedPathPrefix
	t.Cleanup(func() {
		wafDir, IPListDataDir, wafiplist.AllowedPathPrefix = oldWafDir, oldIPDir, oldPrefix
	})

	dataDir := filepath.Join(t.TempDir(), "custom-data")
	ConfigureWafDirs(dataDir)
	wantWaf := filepath.Join(filepath.Dir(dataDir), "waf")
	if wafDir != wantWaf {
		t.Fatalf("wafDir=%q, want %q (threat files must follow data_dir)", wafDir, wantWaf)
	}
	if IPListDataDir != filepath.Join(wantWaf, "ip-lists") {
		t.Fatalf("IPListDataDir=%q", IPListDataDir)
	}
	if wafiplist.AllowedPathPrefix != wantWaf+string(filepath.Separator) {
		t.Fatalf("AllowedPathPrefix=%q", wafiplist.AllowedPathPrefix)
	}
}
