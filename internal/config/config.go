package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Server
	Port      int    `json:"port"`
	DataDir   string `json:"data_dir"`
	StaticDir string `json:"static_dir"`

	// Caddy
	CaddyAdminURL   string `json:"caddy_admin_url"`
	CaddyMetricsURL string `json:"caddy_metrics_url"`

	// Metrics
	MetricsInterval int `json:"metrics_interval"` // seconds

	// Node
	NodeName     string `json:"node_name"`
	NodeMode     string `json:"node_mode"` // master | slave
	MasterURL    string `json:"master_url"`
	SyncEnabled  bool   `json:"sync_enabled"`
	SyncInterval int    `json:"sync_interval"` // seconds

	// Log
	LogLevel string `json:"log_level"`

	// JWT
	JWTSecret string        `json:"jwt_secret"`
	JWTExpire time.Duration `json:"jwt_expire"`

	// Admin
	InitialAdminUser     string `json:"initial_admin_user"`
	InitialAdminPassword string `json:"initial_admin_password"`
}

func Load(path string) *Config {
	// Default values
	cfg := &Config{
		Port:                 8000,
		DataDir:              "/app/data",
		StaticDir:            "/app/ui",
		CaddyAdminURL:        "http://localhost:2019",
		CaddyMetricsURL:      "http://localhost:2019/metrics",
		MetricsInterval:      30,
		NodeName:             getEnv("NODE_NAME", "node-1"),
		NodeMode:             getEnv("NODE_MODE", "master"),
		MasterURL:            getEnv("MASTER_URL", ""),
		SyncEnabled:          getEnvBool("SYNC_ENABLED", false),
		SyncInterval:         getEnvInt("SYNC_INTERVAL", 60),
		LogLevel:             getEnv("LOG_LEVEL", "info"),
		JWTSecret:            getEnv("JWT_SECRET", ""),
		JWTExpire:            24 * time.Hour,
		InitialAdminUser:     getEnv("ADMIN_USER", "admin"),
		InitialAdminPassword: getEnv("ADMIN_PASSWORD", "admin123"),
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
