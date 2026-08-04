package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_parses_metrics_interval_with_safe_minimum(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	tests := []struct {
		name     string
		interval int
		want     int
	}{
		{name: "configured interval", interval: 12, want: 12},
		{name: "positive interval below minimum", interval: 1, want: 5},
		{name: "zero keeps default", interval: 0, want: 30},
		{name: "negative keeps default", interval: -10, want: 30},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			configPath := filepath.Join(t.TempDir(), "config.json")
			content := fmt.Sprintf(`{"metrics_interval":%d}`, test.interval)
			if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			// When
			loaded := Load(configPath)

			// Then
			if loaded.MetricsInterval != test.want {
				t.Fatalf("metrics interval=%d, want %d", loaded.MetricsInterval, test.want)
			}
		})
	}
}

func TestLoad_resolves_log_file_with_default(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	tests := []struct {
		name        string
		envValue    string
		wantPath    string
		wantEnabled bool
	}{
		{name: "env override", envValue: "/tmp/custom.log", wantPath: "/tmp/custom.log", wantEnabled: true},
		{name: "empty env falls back to default", envValue: "", wantPath: "/app/logs/lazy-balancer.log", wantEnabled: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			t.Setenv("LOG_FILE", test.envValue)

			// When
			loaded := Load("")

			// Then
			if loaded.LogFile != test.wantPath {
				t.Fatalf("log file=%q, want %q", loaded.LogFile, test.wantPath)
			}
			if loaded.LogFileEnabled != test.wantEnabled {
				t.Fatalf("log file enabled=%v, want %v", loaded.LogFileEnabled, test.wantEnabled)
			}
		})
	}
}
