package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func applyUserIdentitySnapshot(t *testing.T, localID int, localName string, incoming models.ClusterUser) {
	t.Helper()
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,login_failed_attempts,login_locked_until,last_login)
		VALUES (?,?,'hash','admin',1,4,'2099-01-01 00:00:00','2026-10-01 00:00:00')`, localID, localName); err != nil {
		t.Fatal(err)
	}
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddy.URL}, NewCaddyService(caddy.URL))
	t.Cleanup(func() { unregisterSyncDrainer(service) })
	logLevel, timezone := "info", "Asia/Shanghai"
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version:       8,
		Users:         []models.ClusterUser{incoming},
		BasicSettings: models.ClusterBasicSettings{LogLevel: &logLevel, Timezone: &timezone},
	})
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := service.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	var attempts int
	var locked, lastLogin string
	if err := database.QueryRow(`SELECT COALESCE(login_failed_attempts,0), COALESCE(login_locked_until,''), COALESCE(last_login,'')
		FROM users WHERE id=?`, incoming.ID).Scan(&attempts, &locked, &lastLogin); err != nil {
		t.Fatal(err)
	}
	if incoming.ID != localID {
		if attempts != 0 || locked != "" || lastLogin != "" {
			t.Fatalf("new identity inherited local state: attempts=%d lock=%q last_login=%q", attempts, locked, lastLogin)
		}
		return
	}
	if attempts != 4 || locked != "2099-01-01 00:00:00" || lastLogin != "2026-10-01T00:00:00Z" {
		t.Fatalf("same identity lost local state after rename: attempts=%d lock=%q last_login=%q", attempts, locked, lastLogin)
	}
}

func TestApplySnapshot_usernameReuseDoesNotInheritLocalLoginState(t *testing.T) {
	applyUserIdentitySnapshot(t, 1, "recreated", models.ClusterUser{
		ID: 2, Username: "recreated", PasswordHash: "new-hash", Role: "admin", IsEnabled: true,
	})
}

func TestApplySnapshot_sameUserRenamePreservesLocalLoginState(t *testing.T) {
	applyUserIdentitySnapshot(t, 1, "before-rename", models.ClusterUser{
		ID: 1, Username: "after-rename", PasswordHash: "new-hash", Role: "admin", IsEnabled: true,
	})
}
