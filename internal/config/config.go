package config

import (
	"encoding/json"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Server
	Port      int    `json:"port"`
	DataDir   string `json:"data_dir"`
	StaticDir string `json:"static_dir"`
	Version   string `json:"version"`

	// Caddy
	CaddyAdminURL   string `json:"caddy_admin_url"`
	CaddyMetricsURL string `json:"caddy_metrics_url"`

	// Metrics
	MetricsInterval int `json:"metrics_interval"` // seconds

	// Node
	NodeName string `json:"node_name"`

	// Log

	// JWT
	JWTSecret string        `json:"jwt_secret"`
	JWTExpire time.Duration `json:"jwt_expire"`

	// Admin
}

func Load(path string) *Config {
	// Default values
	cfg := &Config{
		Port:            8000,
		DataDir:         "/app/data",
		StaticDir:       "/app/ui",
		CaddyAdminURL:   "http://localhost:2019",
		CaddyMetricsURL: "http://localhost:2019/metrics",
		MetricsInterval: 30,
		NodeName:        getEnv("NODE_NAME", "node-1"),
		JWTSecret:       getEnv("JWT_SECRET", ""),
		Version:         getEnv("APP_VERSION", "2.0.0"),
		JWTExpire:       24 * time.Hour,
	}

	// Load from config file if provided
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			// Try to parse as JSON (simple approach)
			var fileCfg map[string]interface{}
			if err := json.Unmarshal(data, &fileCfg); err == nil {
				if v, ok := fileCfg["data_dir"].(string); ok && v != "" {
					cfg.DataDir = v
				}
				if v, ok := fileCfg["static_dir"].(string); ok && v != "" {
					cfg.StaticDir = v
				}
				if v, ok := fileCfg["port"].(float64); ok {
					cfg.Port = int(v)
				}
				if v, ok := fileCfg["caddy_admin_url"].(string); ok && v != "" {
					cfg.CaddyAdminURL = v
				}
				if v, ok := fileCfg["caddy_metrics_url"].(string); ok && v != "" {
					cfg.CaddyMetricsURL = v
				}
			}
		}
	}

	// Generate JWT secret if not set
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = generateSecret()
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

func generateSecret() string {
	// Simple secret generation - in production use crypto/rand
	return "lb_secret_" + strconv.FormatInt(time.Now().Unix(), 10)
}
