package handlers

import (
	"testing"
	"time"
)

func TestShouldRenewIssuedCert(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	expires := now.AddDate(0, 0, 60)
	if ShouldRenewIssuedCert(now, expires, 30) {
		t.Fatal("certificate outside renewal window must not renew")
	}
	expires = now.AddDate(0, 0, 20)
	if !ShouldRenewIssuedCert(now, expires, 30) {
		t.Fatal("certificate inside renewal window must renew")
	}
	if !ShouldRenewIssuedCert(now, now.Add(-time.Hour), 30) {
		t.Fatal("expired certificate must renew")
	}
}

func TestResolveEnableCertJobAction(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	validExpiry := now.AddDate(0, 0, 60)
	if action := ResolveEnableCertJobAction(false, "", nil, now, 30); action != EnableCertJobCreate {
		t.Fatalf("missing job action = %v, want create", action)
	}
	if action := ResolveEnableCertJobAction(true, "issued", &validExpiry, now, 30); action != EnableCertJobKeep {
		t.Fatalf("valid issued action = %v, want keep", action)
	}
	if action := ResolveEnableCertJobAction(true, "disabled", &validExpiry, now, 30); action != EnableCertJobResume {
		t.Fatalf("disabled valid action = %v, want resume", action)
	}
	if action := ResolveEnableCertJobAction(true, "failed", &validExpiry, now, 30); action != EnableCertJobResume {
		t.Fatalf("failed valid action = %v, want resume", action)
	}
	if action := ResolveEnableCertJobAction(true, "disabled", nil, now, 30); action != EnableCertJobRetry {
		t.Fatalf("disabled without cert action = %v, want retry", action)
	}
	expiring := now.AddDate(0, 0, 10)
	if action := ResolveEnableCertJobAction(true, "issued", &expiring, now, 30); action != EnableCertJobRenew {
		t.Fatalf("expiring issued action = %v, want renew", action)
	}
}
