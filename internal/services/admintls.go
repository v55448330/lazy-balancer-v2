package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

// AdminTLSConfig holds the admin-panel HTTPS settings stored in global_config.
type AdminTLSConfig struct {
	Enabled bool
	Mode    string // selfsigned | upload（acme 未实现：handlers/admintls.go:91,309 仅放行这两者）
	Cert    string
	Key     string
}

type adminTLSFingerprint struct {
	Enabled     bool
	Mode        string
	Certificate [sha256.Size]byte
}

var runtimeAdminTLS atomic.Pointer[adminTLSFingerprint]

func fingerprintAdminTLS(cfg AdminTLSConfig) adminTLSFingerprint {
	return adminTLSFingerprint{
		Enabled: cfg.Enabled,
		Mode:    cfg.Mode,
		// \x00 分隔消除 cert/key 无分隔拼接的理论双解
		// （"A"+"BC" 与 "AB"+"C" 同串同哈希，真实轮换会被误判为未变化）；
		// PEM 内容不含 NUL，分隔符不引入新的碰撞面。
		Certificate: sha256.Sum256([]byte(cfg.Cert + "\x00" + cfg.Key)),
	}
}

// RecordRuntimeAdminTLS captures the state the process actually started with;
// the sync applier compares later states against it.
func RecordRuntimeAdminTLS(cfg AdminTLSConfig) {
	fingerprint := fingerprintAdminTLS(cfg)
	runtimeAdminTLS.Store(&fingerprint)
}

// RuntimeAdminTLSChanged reports whether the given config differs from the
// state the process started with, meaning a restart is required to apply it.
func RuntimeAdminTLSChanged(cfg AdminTLSConfig) bool {
	v := runtimeAdminTLS.Load()
	if v == nil {
		return false
	}
	return *v != fingerprintAdminTLS(cfg)
}

// ResetRuntimeAdminTLSForTest 清空运行态快照（测试缝，生产不调用）：进程级
// 快照会在用例间继承，若写入者不复位，-shuffle 下后续 admin-tls 用例会读到
// 前一用例的快照而产生顺序依赖。与 ResetLogStateTransitionForTest 同族。
func ResetRuntimeAdminTLSForTest() { runtimeAdminTLS.Store(nil) }

// LoadAdminTLSConfigE 是唯一读入口：读取失败（db 未初始化、查询错误、行缺失）
// 一律返回 error，由调用方按场景处置。
//   - 写/合并路径必须中止：把降级默认值当现有配置合并，会在「本次 SELECT
//     失败、随后 UPDATE 成功」的时序里把已上传证书/私钥改写为空，且接口仍可能
//     返回成功；
//   - 启动监听必须拒绝启动：降级默认值 Enabled=false 会让进程以明文 HTTP 提供
//     管理面（安全属性静默丢失，而不是「HTTPS 关闭」）；
//   - 展示与重启判定必须显式披露/跳过：不得把降级值当真值比对（假「需重启」）。
//
// 不再提供「读失败回退 selfsigned/未启用」的宽容变体——它的三类消费方都会
// 把「读不到」误解成一条真实配置。
func LoadAdminTLSConfigE() (AdminTLSConfig, error) {
	return LoadAdminTLSConfigEFrom(db.DB)
}

// LoadAdminTLSConfigEFrom 是 LoadAdminTLSConfigE 的句柄显式变体：持有自身
// 句柄的服务（多库形态，如集群从端 SyncService.applySnapshot）必须按服务
// 句柄读，不得回落包级 db.DB——多库下「提交 A 库快照、按 B 库配置判重启」
// 的静默错配即源于此。
func LoadAdminTLSConfigEFrom(handle *sql.DB) (AdminTLSConfig, error) {
	cfg := AdminTLSConfig{Mode: "selfsigned"}
	if handle == nil {
		return cfg, fmt.Errorf("数据库未初始化")
	}
	var enabled int
	var mode, cert, key string
	err := handle.QueryRow(`SELECT COALESCE(admin_tls_enabled,0), COALESCE(admin_tls_mode,'selfsigned'),
		COALESCE(admin_tls_cert,''), COALESCE(admin_tls_key,'')
		FROM global_config WHERE id=1`).Scan(&enabled, &mode, &cert, &key)
	if err != nil {
		return cfg, fmt.Errorf("读取管理面板 HTTPS 配置失败: %w", err)
	}
	cfg.Enabled = enabled == 1
	cfg.Mode = mode
	cfg.Cert = cert
	cfg.Key = key
	return cfg, nil
}

// ResolveCertificate returns the TLS certificate for the admin panel,
// generating a self-signed one on first use when configured so.
func (c AdminTLSConfig) ResolveCertificate(dataDir string) (tls.Certificate, error) {
	switch c.Mode {
	case "upload":
		if c.Cert == "" || c.Key == "" {
			return tls.Certificate{}, fmt.Errorf("上传证书模式但未提供证书内容")
		}
		return tls.X509KeyPair([]byte(c.Cert), []byte(c.Key))
	case "selfsigned":
		return selfSignedCert(dataDir)
	default:
		// 白名单外 mode（历史库值/带外改库）按自签名回落：坏值不得让面板
		// 启动进入崩溃循环（既有裁定），但静默回落会让「配置了 upload 却
		// 跑成自签名」无信号——每次解析都 warn（启动期一次，不刷屏）。
		Logf("warn", "admintls: 管理面板 TLS 模式 %q 不在白名单内，按自签名回落", c.Mode)
		return selfSignedCert(dataDir)
	}
}

// selfSignedCert loads or generates a self-signed admin certificate so it is
// stable across restarts; cluster peers skip verification for it anyway.
func selfSignedCert(dataDir string) (tls.Certificate, error) {
	certPath := filepath.Join(dataDir, "admin_tls.crt")
	keyPath := filepath.Join(dataDir, "admin_tls.key")
	// 先读后验——「双文件可读」不代表是合法证书对；
	// 存在但损坏的对（截断/换位/垃圾内容）原样上抛会让启动进入崩溃循环且
	// 面板无清除入口。X509KeyPair 验证通过才复用，否则记 warn 落既有重生成
	// 路径自愈。
	if certPEM, err1 := os.ReadFile(certPath); err1 == nil {
		keyPEM, err2 := os.ReadFile(keyPath)
		if err2 == nil {
			cert, err3 := tls.X509KeyPair(certPEM, keyPEM)
			if err3 == nil {
				return cert, nil
			}
			Logf("warn", "管理面板自签名证书对损坏（%s / %s），将重新生成: %v", certPath, keyPath, err3)
		} else {
			// 证书在场而私钥读失败（缺失/权限/挂载漂移）与「首次生成」不同：
			// 静默落入重生成分支会以新密钥对覆盖既有 crt，已导入浏览器/系统的
			// 信任失效且日志无线索指向真实原因（私钥缺失是最常见形态：卷只挂了
			// crt / 人工删除）。此处一律 warn，文案点名「私钥缺失」与否。
			Logf("warn", "管理面板自签名私钥不可读（%s，缺失=%t），将重新生成证书对（既有证书信任需重建）: %v",
				keyPath, os.IsNotExist(err2), err2)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成自签名私钥失败: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Lazy Balancer V2", Organization: []string{"XiaoBao"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(50, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成自签名证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("编码私钥失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeAdminTLSCertPair(certPath, keyPath, certPEM, keyPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存自签名证书: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func writeAdminTLSCertPair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	return writeCertPair(certPath, keyPath, string(certPEM), string(keyPEM))
}
