package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestClusterCredentialResponsesAreNotStored(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const registrationSecret = "registration-secret-for-cache-test"
	const clusterToken = "cluster-token-for-cache-test"
	registrationHash := sha256.Sum256([]byte(registrationSecret))
	clusterHash := sha256.Sum256([]byte(clusterToken))
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,status,is_approved,registration_secret,registration_secret_expires_at)
		VALUES (41,'pending-node','10.0.0.41','pending',0,?,datetime('now','+1 hour'))`, hex.EncodeToString(registrationHash[:])); err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,status,is_approved,cluster_token_hash)
		VALUES (42,'approved-node','10.0.0.42','online',1,?)`, hex.EncodeToString(clusterHash[:])); err != nil {
		t.Fatalf("seed cluster node: %v", err)
	}

	for _, tc := range []struct {
		name, path, header, credential string
	}{
		{name: "registration status", path: "/api/v1/cluster/register/41/status", header: "X-Registration-Secret", credential: registrationSecret},
		{name: "sync snapshot", path: "/api/v1/cluster/sync/snapshot", header: "X-Cluster-Token", credential: clusterToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			request.Header.Set(tc.header, tc.credential)
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q, want no-store", got)
			}
		})
	}

	token, _ := seedNoStoreAuthUser(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ordinary nodes response status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("ordinary nodes Cache-Control=%q, want empty", got)
	}
}
