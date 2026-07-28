package acme

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestACMEAccountKeyPath_includes_EAB_KID_and_full_hash(t *testing.T) {
	// Given
	directoryURL := "https://acme.example/directory"
	email := "admin@example.com"

	// When
	first := acmeAccountKeyPath(directoryURL, email, "kid-a")
	repeated := acmeAccountKeyPath(directoryURL, email, "kid-a")
	second := acmeAccountKeyPath(directoryURL, email, "kid-b")

	// Then
	if first != repeated {
		t.Fatalf("stable account identity produced %q and %q", first, repeated)
	}
	if first == second {
		t.Fatalf("different EAB KIDs share account key path %q", first)
	}
	base := strings.TrimSuffix(filepath.Base(first), ".key")
	if len(base) != 64 {
		t.Fatalf("account hash length=%d, want 64", len(base))
	}
}
