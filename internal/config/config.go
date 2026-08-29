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
		if err != nil {
			// S-3：配置文件读取失败必须可见（与下方解析失败分支对称）——静默回落
			// 默认值会让「指定了 -config 却没生效」排查无门。
			log.Printf("config: failed to read config file %s (%v); using defaults", path, err)
		} else {
			// Try to parse as JSON (simple approach)
			var fileCfg map[string]interface{}
			if jerr := json.Unmarshal(data, &fileCfg); jerr != nil {
				// R72 二十六次 W3-3：文件存在但解析失败必须可见——静默回落
				// 默认值会让「改了配置没生效」排查无门。
				log.Printf("config: file %s exists but failed to parse (%v); using defaults", path, jerr)
			} else {
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

	// R72 二十六次 W3-3：端口范围校验——port=0 会绑随机端口、>65535 只在
	// 监听时才报错，均早失败为佳。
	if cfg.Port < 1 || cfg.Port > 65535 {
		log.Printf("config: invalid port %d (config file port field); falling back to 8000", cfg.Port)
		cfg.Port = 8000
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
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		// N-6：目录创建失败必须可见——此前静默跳过写入，JWT 密钥每次启动
		// 随机重生成（旧令牌全部失效）且零日志信号；与下方写失败分支对称。
		log.Printf("JWT 密钥目录 %s 创建失败（重启后令牌将失效）: %v", dataDir, err)
	} else if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		log.Printf("JWT 密钥写入 %s 失败（重启后令牌将失效）: %v", secretPath, err)
	}
	return secret
}
