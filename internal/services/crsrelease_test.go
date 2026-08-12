package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildCRSTarball builds an in-memory tar.gz mimicking a GitHub release
// tarball: every entry is prefixed with a single root directory.
func buildCRSTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Write(%s): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCRSStaging_valid(t *testing.T) {
	// Given a staging dir with crs-setup.conf.example and rules/*.conf
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "crs-setup.conf.example"), "# setup")
	writeTestFile(t, filepath.Join(dir, "rules", "REQUEST-900.conf"), "SecRule 1")

	// When validating
	// Then no error
	if err := validateCRSStaging(dir); err != nil {
		t.Fatalf("validateCRSStaging()=%v, want nil", err)
	}
}

func TestValidateCRSStaging_missingSetupExample(t *testing.T) {
	// Given a staging dir with rules but no crs-setup.conf.example
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "rules", "REQUEST-900.conf"), "SecRule 1")

	// When validating
	// Then it fails
	if err := validateCRSStaging(dir); err == nil {
		t.Fatal("validateCRSStaging()=nil, want error for missing crs-setup.conf.example")
	}
}

func TestValidateCRSStaging_missingRules(t *testing.T) {
	// Given a staging dir with setup example but an empty rules dir
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "crs-setup.conf.example"), "# setup")
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}

	// When validating
	// Then it fails
	if err := validateCRSStaging(dir); err == nil {
		t.Fatal("validateCRSStaging()=nil, want error for rules dir without .conf files")
	}
}

func TestCountSecRules_countsDirectivesAcrossFiles(t *testing.T) {
	// Given two rule files with SecRule directives, comments, and lookalikes
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a.conf"), strings.Join([]string{
		"# SecRule mentioned in a comment does not count",
		`SecRule REQUEST_URI "@rx attack" "id:1001,deny"`,
		`	SecRule ARGS "@rx x" "id:1002,deny"`,
		`SecRuleUpdateTargetById 1001 "!ARGS:safe"`,
		`SecMarker "ENDPOINT"`,
	}, "\n"))
	writeTestFile(t, filepath.Join(dir, "b.conf"), `SecRule REQUEST_HEADERS "x" "id:2001,pass"`+"\n")
	writeTestFile(t, filepath.Join(dir, "c.txt"), `SecRule NOT_A_CONF "x" "id:9999"`)

	// When counting
	got, err := countSecRules(dir)

	// Then only real directives in .conf files are counted
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Fatalf("countSecRules()=%d, want 3", got)
	}
}

func TestCompareCRSVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v4.14.0", "v4.14.0", 0},
		{"v4.14.0", "v4.15.0", -1},
		{"v4.15.0", "v4.14.0", 1},
		{"4.14.0", "v4.14.0", 0},
		{"v4.9", "v4.9.0", 0},
		{"v4.9.1", "v4.9", 1},
		{"v10.0.0", "v9.99.0", 1},
	}
	for _, tc := range cases {
		got, err := compareCRSVersions(tc.a, tc.b)
		if err != nil {
			t.Fatalf("compareCRSVersions(%q,%q) error=%v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Fatalf("compareCRSVersions(%q,%q)=%d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if _, err := compareCRSVersions("bogus", "v4.14.0"); err == nil {
		t.Fatal("compareCRSVersions(bogus) error=nil, want parse error")
	}
}

func TestParseGitHubLatestTag(t *testing.T) {
	// Given a GitHub releases/latest response body
	body := []byte(`{"tag_name":"v4.15.0","name":"OWASP CRS v4.15.0"}`)

	// When parsing
	tag, err := parseGitHubLatestTag(body)

	// Then the tag is returned
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v4.15.0" {
		t.Fatalf("parseGitHubLatestTag()=%q, want v4.15.0", tag)
	}

	if _, err := parseGitHubLatestTag([]byte(`{"message":"rate limited"}`)); err == nil {
		t.Fatal("parseGitHubLatestTag() error=nil, want error for missing tag_name")
	}
	if _, err := parseGitHubLatestTag([]byte(`not json`)); err == nil {
		t.Fatal("parseGitHubLatestTag() error=nil, want error for invalid JSON")
	}
}

func TestExtractCRSTarball_stripsRootAndExtracts(t *testing.T) {
	// Given a GitHub-style tarball with a single root directory
	tarball := buildCRSTarball(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":    "# setup",
		"coreruleset-4.15.0/rules/REQUEST-900.conf":    "SecRule 1",
		"coreruleset-4.15.0/rules/RESPONSE-999.conf":   "SecRule 2",
		"coreruleset-4.15.0/plugins/empty-config.conf": "# plugin",
	})
	src := filepath.Join(t.TempDir(), "crs.tar.gz")
	if err := os.WriteFile(src, tarball, 0644); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()

	// When extracting
	if err := extractCRSTarball(src, dest); err != nil {
		t.Fatal(err)
	}

	// Then files land without the root prefix
	for _, rel := range []string{"crs-setup.conf.example", "rules/REQUEST-900.conf", "rules/RESPONSE-999.conf", "plugins/empty-config.conf"} {
		if _, err := os.Stat(filepath.Join(dest, rel)); err != nil {
			t.Fatalf("expected %s extracted: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "coreruleset-4.15.0")); !os.IsNotExist(err) {
		t.Fatal("root directory should have been stripped")
	}
}

func TestExtractCRSTarball_rejectsPathTraversal(t *testing.T) {
	// Given a tarball containing a path traversal entry
	tarball := buildCRSTarball(t, map[string]string{
		"root/../../evil.conf": "pwned",
	})
	src := filepath.Join(t.TempDir(), "crs.tar.gz")
	if err := os.WriteFile(src, tarball, 0644); err != nil {
		t.Fatal(err)
	}

	// When extracting
	// Then it fails instead of escaping dest
	if err := extractCRSTarball(src, t.TempDir()); err == nil {
		t.Fatal("extractCRSTarball()=nil, want error for path traversal entry")
	}
}
