package notify

// 凭据静态加密回归（unify_all）：Seal/Open 往返、遗留明文透传、错密钥
// fail-loud、敏感键密文落库（非敏感键不受影响）、QQ raw 路径改造后加密、
// 存量迁移幂等。测试 DB 经 newNotifyConnectorDB（sql.Open，不设 DataDir），
// 故覆写 secretKeyPath 接缝指向临时密钥文件。

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func useTempSecretKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".notify_secret_key")
	old := secretKeyPath
	secretKeyPath = func() string { return path }
	resetSecretKeyCache()
	t.Cleanup(func() { secretKeyPath = old; resetSecretKeyCache() })
	return path
}

func TestSecretBox_RoundTrip(t *testing.T) {
	useTempSecretKey(t)
	// Given/When 加密敏感值
	sealed, err := SealSecret("smtp-pass-秘密")
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	// Then 密文带前缀且不含明文，解密还原
	if !strings.HasPrefix(sealed, secretPrefix) {
		t.Errorf("密文应带 %s 前缀, got %q", secretPrefix, sealed)
	}
	if strings.Contains(sealed, "smtp-pass-秘密") {
		t.Errorf("密文不得含明文")
	}
	plain, err := OpenSecret(sealed)
	if err != nil || plain != "smtp-pass-秘密" {
		t.Fatalf("OpenSecret = %q, %v; want 原文", plain, err)
	}
	// 空串原样（清除配置语义）
	if s, _ := SealSecret(""); s != "" {
		t.Errorf("空串加密应原样返回, got %q", s)
	}
}

func TestSecretBox_LegacyPlaintextPassthrough(t *testing.T) {
	useTempSecretKey(t)
	// 无前缀=遗留明文透传（兼容未迁移值）
	if p, err := OpenSecret("legacy-plain"); err != nil || p != "legacy-plain" {
		t.Fatalf("遗留明文应透传, got %q, %v", p, err)
	}
}

func TestSecretBox_WrongKeyFailLoud(t *testing.T) {
	path := useTempSecretKey(t)
	sealed, err := SealSecret("secret")
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	// When 主密钥被替换为不同 32 字节 + 清缓存
	other := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatalf("写密钥: %v", err)
	}
	resetSecretKeyCache()
	// Then 解密 fail-loud
	if _, err := OpenSecret(sealed); err == nil {
		t.Errorf("错密钥解密应返回错误（fail-loud）")
	}
}

func TestSettings_SecretEncryptedAtRest(t *testing.T) {
	newNotifyConnectorDB(t)
	useTempSecretKey(t)
	// When 写入敏感键 + 非敏感键
	if err := SetSettings(map[string]string{KeySMTPPass: "p@ss", KeySMTPHost: "smtp.example.com"}); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	// Then 敏感键密文落库，非敏感键明文
	var pass, host string
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, KeySMTPPass).Scan(&pass)
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, KeySMTPHost).Scan(&host)
	if !strings.HasPrefix(pass, secretPrefix) || strings.Contains(pass, "p@ss") {
		t.Errorf("smtp_pass 应密文落库, got %q", pass)
	}
	if host != "smtp.example.com" {
		t.Errorf("非敏感键 smtp_host 应明文, got %q", host)
	}
	// 读路径解密还原
	if GetSetting(KeySMTPPass) != "p@ss" {
		t.Errorf("GetSetting 应解密还原 p@ss, got %q", GetSetting(KeySMTPPass))
	}
	if GetSettings(KeySMTPPass, KeySMTPHost)[KeySMTPPass] != "p@ss" {
		t.Errorf("GetSettings 应解密还原")
	}
}

func TestSettings_QQCredentialsEncrypted(t *testing.T) {
	newNotifyConnectorDB(t)
	useTempSecretKey(t)
	// When 经改造后的 SaveQQBotCredentials 落库
	if err := SaveQQBotCredentials("APP_X", "SEC_Y"); err != nil {
		t.Fatalf("SaveQQBotCredentials: %v", err)
	}
	// Then qq_secret 密文、qq_appid 明文
	var secret, appid string
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, KeyQQSecret).Scan(&secret)
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, KeyQQAppID).Scan(&appid)
	if !strings.HasPrefix(secret, secretPrefix) || strings.Contains(secret, "SEC_Y") {
		t.Errorf("qq_secret 应密文落库, got %q", secret)
	}
	if appid != "APP_X" {
		t.Errorf("qq_appid 标识符应明文, got %q", appid)
	}
	// 读路径解密还原
	a, s, ok := QQBotCredentialsPair()
	if !ok || a != "APP_X" || s != "SEC_Y" {
		t.Errorf("QQBotCredentialsPair = %q,%q,%v; want APP_X,SEC_Y,true", a, s, ok)
	}
}

func TestMigrateSecretSettings_Idempotent(t *testing.T) {
	newNotifyConnectorDB(t)
	useTempSecretKey(t)
	// Given 遗留明文敏感键 + 非敏感键（raw 写入模拟存量）
	if _, err := db.DB.Exec(`INSERT INTO notify_settings (key,value) VALUES (?,?),(?,?)`,
		KeySMTPPass, "legacy-pass", KeySMTPHost, "h"); err != nil {
		t.Fatalf("播种: %v", err)
	}
	// When 迁移
	if err := MigrateSecretSettings(); err != nil {
		t.Fatalf("MigrateSecretSettings: %v", err)
	}
	var pass string
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, KeySMTPPass).Scan(&pass)
	if !strings.HasPrefix(pass, secretPrefix) {
		t.Fatalf("迁移后 smtp_pass 应密文, got %q", pass)
	}
	if GetSetting(KeySMTPPass) != "legacy-pass" {
		t.Errorf("迁移后读路径应还原 legacy-pass")
	}
	// When 再次迁移（幂等）
	if err := MigrateSecretSettings(); err != nil {
		t.Fatalf("二次迁移: %v", err)
	}
	var pass2 string
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, KeySMTPPass).Scan(&pass2)
	if pass2 != pass {
		t.Errorf("幂等迁移不得改变已加密值")
	}
	if GetSetting(KeySMTPPass) != "legacy-pass" {
		t.Errorf("二次迁移后仍应还原")
	}
}
