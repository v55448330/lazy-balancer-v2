package middleware

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
)

func TestShouldLogRequestAppliesConfiguredThreshold(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		status  int
		latency time.Duration
		want    bool
	}{
		{name: "info records successful request", level: "info", status: 200, want: true},
		{name: "warn filters routine success", level: "warn", status: 200, want: false},
		{name: "warn records client error", level: "warn", status: 404, want: true},
		{name: "warn records slow success", level: "warn", status: 200, latency: time.Second, want: true},
		{name: "error filters client error", level: "error", status: 404, want: false},
		{name: "error records server error", level: "error", status: 500, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			if err := services.ConfigureLogLevel(test.level); err != nil {
				t.Fatal(err)
			}

			// When
			got := shouldLogRequest(test.status, test.latency)

			// Then
			if got != test.want {
				t.Fatalf("shouldLogRequest(%d,%v)=%v, want %v", test.status, test.latency, got, test.want)
			}
		})
	}
	t.Cleanup(func() { _ = services.ConfigureLogLevel("info") })
}
