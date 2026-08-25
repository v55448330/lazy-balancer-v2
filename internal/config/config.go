package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

const defaultLogFile = "/app/logs/lazy-balancer.log"

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
	LogFile        string `json:"log_file"` // effective runtime log path (LOG_FILE env or default)
	LogFileEnabled bool   `json:"-"`        // true only when LOG_FILE is explicitly set

	// JWT
	JWTSecret string `json:"jwt_secret"`

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
		Version:         getEnv("APP_VERSION", "2.1.9"),
		LogFile:         getEnv("LOG_FILE", defaultLogFile),
		LogFileEnabled:  os.Getenv("LOG_FILE") != "",
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
				if v, ok := fileCfg["metrics_interval"].(float64); ok && v > 0 {
					cfg.MetricsInterval = max(5, int(v))
				}
			}
		}
	}

	// JWT secret: env wins; otherwise persist a random one so tokens survive
	// restarts and the secret is never predictable.
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = loadOrCreateJWTSecret(cfg.DataDir)
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadOrCreateJWTSecret(dataDir string) string {
	secretPath := filepath.Join(dataDir, "jwt_secret")
	if data, err := os.ReadFile(secretPath); err == nil && len(data) >= 32 {
		return string(data)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("生成 JWT 密钥失败: %v", err)
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0755); err == nil {
		if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
			log.Printf("JWT 密钥写入 %s 失败（重启后令牌将失效）: %v", secretPath, err)
		}
	}
	return secret
}
