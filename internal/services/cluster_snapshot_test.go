package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func TestNearestSnapshotCertificateExpiry_missingExpiryDoesNotMaskNearerRealExpiry(t *testing.T) {
	// Given
	now := time.Now().UTC().Truncate(time.Second)
	near := now.Add(5 * time.Second).Format(time.RFC3339)

	// When
	got := nearestSnapshotCertificateExpiry([]models.ClusterCertificate{
		{RuleID: "lb_near", Domain: "near.example.com", CertPEM: "pem", ExpiresAt: near},
		{RuleID: "lb_acme_missing", Domain: "missing.example.com", CertPEM: "pem", ExpiresAt: ""},
	}, now)

	// Then：缺失证书的重建窗口（30s）不得覆盖更近的 5s 真实到期时间
	if want := now.Add(5 * time.Second); !got.Equal(want) {
		t.Fatalf("expiry=%v, want %v (missing-expiry window must not mask nearer expiry)", got, want)
	}
}
