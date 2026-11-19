package notify

// 通知凭据静态加密（unify_all）：notify_settings 敏感键 AES-256-GCM 落库。
// 主密钥文件 <data>/.notify_secret_key（32 字节随机，0600，首次使用生成，随
// data 卷持久化）。密文格式 enc:v1:<base64(nonce||sealed)>，前缀区分加密值与
// 遗留明文（OpenSecret 无前缀=透传，兼容未迁移值）。API 本就不回明文（只回
// 「已配置」布尔），本层是静态落库口径。主密钥丢失=凭据不可恢复，须随 DB 备份。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"lazy-balancer-v2/internal/db"
)

const secretPrefix = "enc:v1:"

// secretSettingKeys 需静态加密的 notify_settings 键集合。qq_appid 是标识符
// 非密不加密；通道 target 的 per-bot 凭据因等值去重约束不在本期范围（见设计稿）。
var secretSettingKeys = map[string]bool{
	KeySMTPPass:  true,
	KeyQQSecret:  true,
	KeyWxBotCred: true,
}

func isSecretSettingKey(key string) bool { return secretSettingKeys[key] }

// secretKeyPath 主密钥文件路径（var 供测试覆写）。data dir 未初始化返回空。
var secretKeyPath = func() string {
	d := db.DataDir()
	if d == "" {
		return ""
	}
	return filepath.Join(d, ".notify_secret_key")
}

var (
	secretKeyMu    sync.Mutex
	secretKeyCache = map[string][]byte{} // path -> key（按路径缓存，兼容多测试临时目录）
)

// masterKey 加载/创建主密钥（按路径缓存）。
func masterKey() ([]byte, error) {
	path := secretKeyPath()
	if path == "" {
		return nil, errors.New("数据目录未初始化，无法定位凭据加密主密钥")
	}
	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()
	if k, ok := secretKeyCache[path]; ok {
		return k, nil
	}
	k, err := loadOrCreateKey(path)
	if err != nil {
		return nil, err
	}
	secretKeyCache[path] = k
	return k, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("凭据加密主密钥长度非法（%d，want 32）: %s", len(b), path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// SealSecret 加密敏感值（空串原样返回——SetSettings 空串=清除配置语义不变）。
func SealSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	key, err := masterKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return secretPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenSecret 解密敏感值；无 enc:v1: 前缀=遗留明文透传（兼容未迁移值）。
// 解密失败（密钥不匹配/损坏）返回错误（fail-loud，调用方留痕）。
func OpenSecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil
	}
	key, err := masterKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("凭据密文 base64 解码失败: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("凭据密文过短")
	}
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("凭据解密失败（主密钥不匹配或数据损坏）: %w", err)
	}
	return string(plain), nil
}

// MigrateSecretSettings 启动一次性存量迁移：敏感键值无 enc:v1: 前缀（遗留
// 明文）→ 原地重加密。幂等（已加密/空值跳过）。读路径兼容遗留明文，写路径恒加密。
func MigrateSecretSettings() error {
	if db.DB == nil {
		return nil
	}
	for k := range secretSettingKeys {
		var v string
		if err := db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, k).Scan(&v); err != nil {
			continue // 缺行=未配置
		}
		if v == "" || strings.HasPrefix(v, secretPrefix) {
			continue
		}
		sealed, err := SealSecret(v)
		if err != nil {
			return fmt.Errorf("迁移凭据 %s 加密失败: %w", k, err)
		}
		if _, err := db.DB.Exec(`UPDATE notify_settings SET value=? WHERE key=?`, sealed, k); err != nil {
			return fmt.Errorf("迁移凭据 %s 落库失败: %w", k, err)
		}
		log.Printf("INFO: notify 凭据 %s 已静态加密迁移", k)
	}
	return nil
}

// resetSecretKeyCache 测试缝：清空主密钥缓存（多测试临时目录隔离）。
func resetSecretKeyCache() {
	secretKeyMu.Lock()
	secretKeyCache = map[string][]byte{}
	secretKeyMu.Unlock()
}
