package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/config"
)

func newCrawlerRetryFixture(t *testing.T, rebuild func() error) (*SyncService, *atomic.Int32) {
	t.Helper()
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	oldRebuild := rebuildCrawlerSnapshotForSync
	var calls atomic.Int32
	rebuildCrawlerSnapshotForSync = func() error {
		calls.Add(1)
		return rebuild()
	}
	t.Cleanup(func() { rebuildCrawlerSnapshotForSync = oldRebuild })
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(caddy.Close)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddy.URL}, NewCaddyService(caddy.URL))
	t.Cleanup(func() { unregisterSyncDrainer(service) })
	snapshot, err := service.cluster.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	snapshot.Version = 7
	if err := service.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	if drifted := service.driftedSections(context.Background()); drifted != "" {
		t.Fatalf("fixture drifted: %s", drifted)
	}
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/branding" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(master.Close)
	if _, err := database.Exec(`UPDATE global_config SET master_url=?, cluster_token='token' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	return service, &calls
}

func TestSyncService_stableSyncRetriesAndRecoversCrawlerSnapshot(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	service, calls := newCrawlerRetryFixture(t, func() error {
		if fail.Load() {
			return errors.New("injected snapshot write failure")
		}
		return nil
	})
	if got := calls.Load(); got != 1 {
		t.Fatalf("initial rebuild calls=%d, want 1", got)
	}
	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("retry pull: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("stable 304 rebuild calls=%d, want 2", got)
	}
	fail.Store(false)
	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("recovery pull: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("recovery rebuild calls=%d, want 3", got)
	}
	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("steady pull: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("converged steady state rewrote snapshot: calls=%d", got)
	}
}

func TestSyncService_crawlerSnapshotRetriesBackOffAndRemainVisible(t *testing.T) {
	service, calls := newCrawlerRetryFixture(t, func() error { return errors.New("persistent snapshot write failure") })
	for range 4 {
		if _, err := service.Pull(context.Background()); err != nil {
			t.Fatalf("pull to failure threshold: %v", err)
		}
	}
	if got := calls.Load(); got != 5 {
		t.Fatalf("calls at threshold=%d, want 5", got)
	}
	var stored string
	if err := service.db.QueryRow(`SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "爬虫运行快照重建失败") {
		t.Fatalf("last_sync_error=%q, want persistent crawler rebuild failure", stored)
	}
	for range 4 {
		if _, err := service.Pull(context.Background()); err != nil {
			t.Fatalf("backoff pull: %v", err)
		}
	}
	if got := calls.Load(); got != 5 {
		t.Fatalf("backoff rounds performed writes: calls=%d, want 5", got)
	}
	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("next scheduled retry: %v", err)
	}
	if got := calls.Load(); got != 6 {
		t.Fatalf("scheduled retry calls=%d, want 6", got)
	}
}

func TestSyncService_crawlerSnapshotRetryHonorsSecuritySwitch(t *testing.T) {
	service, calls := newCrawlerRetryFixture(t, func() error { return errors.New("persistent snapshot write failure") })
	if _, err := service.db.Exec(`UPDATE global_config SET sync_security=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("pull with security disabled: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("security-disabled retry calls=%d, want 1", got)
	}
}
