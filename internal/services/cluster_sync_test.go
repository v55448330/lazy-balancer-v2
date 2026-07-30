package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

type blockingRoundTripper struct {
	entered chan struct{}
}

func (r blockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	close(r.entered)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestSyncService_RegisterWithMaster_parent_cancellation_returns_immediately(t *testing.T) {
	entered := make(chan struct{})
	service := &SyncService{client: &http.Client{Transport: blockingRoundTripper{entered: entered}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := service.RegisterWithMaster(ctx, "http://master.example", models.ClusterRegisterRequest{})
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("registration error=%v, want context canceled", err)
	}
}

func TestSyncService_Pull_rejects_old_response_after_new_snapshot_applied(t *testing.T) {
	_, database := newClusterTestService(t)
	const token = "cluster-token"
	oldRequestEntered := make(chan struct{})
	releaseOldResponse := make(chan struct{})
	requestNumber := make(chan int, 2)
	var requests atomic.Int32
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		request := int(requests.Add(1))
		requestNumber <- request
		version := 2
		if request == 1 {
			version = 1
			close(oldRequestEntered)
			<-releaseOldResponse
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"data": signedTestSnapshot(version, token)})
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	oldPull := NewSyncService(database, &config.Config{CaddyAdminURL: caddy.URL}, NewCaddyService(caddy.URL))
	newPull := NewSyncService(database, &config.Config{CaddyAdminURL: caddy.URL}, NewCaddyService(caddy.URL))
	oldDone := make(chan error, 1)
	go func() {
		_, err := oldPull.Pull(context.Background())
		oldDone <- err
	}()
	<-oldRequestEntered
	newDone := make(chan error, 1)
	go func() {
		_, err := newPull.Pull(context.Background())
		newDone <- err
	}()
	if got := <-requestNumber; got != 1 {
		t.Fatalf("first request number=%d", got)
	}
	if got := <-requestNumber; got != 2 {
		t.Fatalf("second request number=%d", got)
	}
	if err := <-newDone; err != nil {
		t.Fatalf("apply newer snapshot: %v", err)
	}
	close(releaseOldResponse)

	if err := <-oldDone; err == nil {
		t.Fatal("late older snapshot was accepted")
	}
	var appliedVersion int
	if err := database.QueryRow("SELECT applied_version FROM global_config WHERE id=1").Scan(&appliedVersion); err != nil {
		t.Fatalf("read applied version: %v", err)
	}
	if appliedVersion != 2 {
		t.Fatalf("applied version=%d, want 2", appliedVersion)
	}
}

func signedTestSnapshot(version int, token string) models.ClusterSnapshot {
	snapshot := models.ClusterSnapshot{Version: version}
	content, err := json.Marshal(snapshot)
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(content)
	snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
	return snapshot
}
