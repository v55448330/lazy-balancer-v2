package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestSyncService_trackReloadRepullConvergence_preservesAnyPostCommitFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewSyncService(database, nil, nil)

	for _, marker := range []string{
		syncReloadFailureMarkerPrefix,
		syncBrandingFailureMarkerPrefix,
		syncCommitUncertainMarkerPrefix,
	} {
		t.Run(marker, func(t *testing.T) {
			service.reloadRepullFailures.Store(4)
			stored := encodeSyncError(marker+": post-commit action failed", models.SyncErrorCodeApplyFailed)
			if _, err := database.Exec("UPDATE global_config SET last_sync_error=? WHERE id=1", stored); err != nil {
				t.Fatal(err)
			}

			service.trackReloadRepullConvergence(context.Background())

			if got := service.reloadRepullFailures.Load(); got != 4 {
				t.Fatalf("repull failures=%d, want 4 while %s remains pending", got, marker)
			}
		})
	}

	t.Run("converged", func(t *testing.T) {
		service.reloadRepullFailures.Store(4)
		if _, err := database.Exec("UPDATE global_config SET last_sync_error='' WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		service.trackReloadRepullConvergence(context.Background())
		if got := service.reloadRepullFailures.Load(); got != 0 {
			t.Fatalf("repull failures=%d, want reset after all post-commit work converged", got)
		}
	})
}
