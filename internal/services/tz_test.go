package services

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestRefreshLocation_updates_current_location_without_mutating_timeLocal(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := db.DB.Exec("UPDATE global_config SET timezone='UTC' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}
	localBefore := time.Local

	// When
	err := refreshLocation()

	// Then
	if err != nil {
		t.Fatalf("refresh location: %v", err)
	}
	if time.Local != localBefore {
		t.Fatal("runtime timezone refresh mutated time.Local")
	}
	if CurrentLocation() != time.UTC {
		t.Fatalf("current location=%v, want UTC", CurrentLocation())
	}
}

func TestTimezoneRefresh_stops_and_waits_when_context_is_canceled(t *testing.T) {
	// Given
	StopTimezoneRefresh()
	ctx, cancel := context.WithCancel(context.Background())
	done := StartTimezoneRefresh(ctx)

	// When
	cancel()
	<-done

	// Then
	select {
	case <-done:
	default:
		t.Fatal("timezone refresh did not stop")
	}
	t.Cleanup(func() { StartTimezoneRefresh(context.Background()) })
}

func TestApplicationLogWriterFiltersRawStandardLogsAtConfiguredThreshold(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		message string
		want    bool
	}{
		{name: "info allows ordinary lines", level: "info", message: "startup complete", want: true},
		{name: "warn drops ordinary lines", level: "warn", message: "startup complete", want: false},
		{name: "warn allows warning lines", level: "warn", message: "Warning: degraded startup", want: true},
		{name: "error drops warning lines", level: "error", message: "Warning: degraded startup", want: false},
		{name: "error allows error lines", level: "error", message: "ERROR: startup failed", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var output bytes.Buffer
			if err := ConfigureLogLevel(test.level); err != nil {
				t.Fatal(err)
			}
			logger := log.New(NewApplicationLogWriter(&output), "", 0)

			// When
			logger.Print(test.message)

			// Then
			if strings.Contains(output.String(), test.message) != test.want {
				t.Fatalf("output=%q want_visible=%v", output.String(), test.want)
			}
		})
	}
	t.Cleanup(func() { _ = ConfigureLogLevel("info") })
}
