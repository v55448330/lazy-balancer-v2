package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestSecurityEventsLoadMappings_cachedByClusterVersion(t *testing.T) {
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	resetSecurityEventsMappingsCacheForTest()
	base := securityEventsMappingLoadsForTest.Load()
	for range 2 {
		if _, _, _, err := securityEventsLoadMappings(); err != nil {
			t.Fatal(err)
		}
	}
	if got := securityEventsMappingLoadsForTest.Load() - base; got != 1 {
		t.Fatalf("unchanged cluster version performed %d mapping loads, want 1", got)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := securityEventsLoadMappings(); err != nil {
		t.Fatal(err)
	}
	if got := securityEventsMappingLoadsForTest.Load() - base; got != 2 {
		t.Fatalf("cluster version change performed %d total mapping loads, want 2", got)
	}
}
