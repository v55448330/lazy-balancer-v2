package services

import (
	"context"
	"errors"
	"net/http"
	"testing"

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
