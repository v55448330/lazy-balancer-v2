package services

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// cl1TimestampSnapshot 构造五表时间列同一时刻的快照；nullable 同时用于 users/
// api_keys/certs/certificate_configs 的可空列，便于分别覆盖有值与 NULL 形态。
func cl1TimestampSnapshot(stamp time.Time, nullable models.JSONNullTime) models.ClusterSnapshot {
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version: 7,
		Rules: []models.LbRule{{
			ID: 1, CaddyID: "lb_cl1acme", Name: "cl1-acme", Protocol: "http",
			Domain: "cl1.example.test", ListenPort: 8443, Enabled: true,
			EnableTLS: true, TLSSource: "acme_dns",
		}},
		Users: []models.ClusterUser{{
			ID: 5, Username: "cl1-user", PasswordHash: "hash", Role: "admin",
			IsEnabled: true, CreatedAt: stamp, LastLogin: nullable,
		}},
		APIKeys: []models.ClusterAPIKey{{
			ID: 9, Name: "cl1-key", KeyHash: "hash", KeyPrefix: "lb_", CreatedBy: 5,
			IsEnabled: true, LastUsed: nullable, CreatedAt: stamp,
		}},
		Certs: []models.ClusterCertificate{{
			RuleID: "lb_cl1acme", CertPEM: "cert", KeyPEM: "key",
			CAAvailableAfter: nullable,
		}},
	})
	snapshot.ACME.CAProviders = append(snapshot.ACME.CAProviders, models.CAProvider{
		ID: 1, Name: "cl1-ca", Provider: "letsencrypt", Enabled: true,
		CreatedAt: stamp, UpdatedAt: stamp,
	})
	snapshot.ACME.CertificateConfigs = append(snapshot.ACME.CertificateConfigs, models.CertificateConfig{
		ID: 1, Name: "cl1-dns", Enabled: true, CreatedAt: stamp, UpdatedAt: nullable,
	})
	return snapshot
}

// lb_rules/path_rules 两表——cluster_apply.go 内 certificate_configs/cert_jobs/
// users/api_keys 的时间列（含同族 ca_providers，兄弟位点）仍直写 time.Time，
// 驱动序列化为带时区后缀形态（'+00:00'/RFC3339），与主端 datetime('now') 平面
// 格式三态并存。修复=全部写点统一平面格式（nullableTimeFlat / UTC().Format；
// 空值路径保持 NULL）。
func TestReplaceSnapshot_writes_flat_timestamps_on_slave_tables(t *testing.T) {
	// Given：快照携带 acme_dns 规则（供 cert_jobs 回插命中）、CA 提供商、
	// 证书配置、用户、API 密钥、证书（ca_available_after）——时间列统一同一
	// UTC 时刻，可空列 Valid=true。
	_, database := newClusterTestService(t)
	stamp := time.Date(2026, 10, 11, 8, 9, 10, 0, time.UTC)
	notNull := models.JSONNullTime{NullTime: sql.NullTime{Time: stamp, Valid: true}}
	snapshot := cl1TimestampSnapshot(stamp, notNull)

	// When：从端全量重放快照（replaceSnapshotDB=无 skips 全节重放）
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：五表时间列存储值均为 SQLite 平面格式——断言用 SQL 谓词
	// 「存储值 = strftime 平面化自身」直判存储字节（驱动对 DATETIME 列会把
	// 文本解析回 time.Time，Go 侧 Scan *string 会再格式化为 RFC3339，无法
	// 反映真实落库形态）。
	assertFlat := func(table, col, where string) {
		t.Helper()
		var flat sql.NullInt64
		if err := database.QueryRow(`SELECT (` + col + ` = strftime('%Y-%m-%d %H:%M:%S', ` + col + `)) FROM ` + table + ` WHERE ` + where).Scan(&flat); err != nil {
			t.Fatalf("read %s.%s: %v", table, col, err)
		}
		if !flat.Valid || flat.Int64 != 1 {
			t.Fatalf("%s.%s 存储值非平面格式（want 'YYYY-MM-DD HH:MM:SS'）", table, col)
		}
	}
	assertFlat("ca_providers", "created_at", "id=1")
	assertFlat("ca_providers", "updated_at", "id=1")
	assertFlat("certificate_configs", "created_at", "id=1")
	assertFlat("certificate_configs", "updated_at", "id=1")
	assertFlat("cert_jobs", "ca_available_after", "rule_id='lb_cl1acme'")
	assertFlat("users", "created_at", "id=5")
	assertFlat("users", "last_login", "id=5")
	assertFlat("api_keys", "created_at", "id=9")
	assertFlat("api_keys", "last_used", "id=9")
}

// 可空列的零值必须落 NULL，而不是 "0001-01-01 00:00:00" 或同步时刻；
// 必须从空库重放验证——已有非空值后的快照 NULL 按本地记账语义保留旧值。
func TestReplaceSnapshot_writes_null_for_unset_nullable_timestamps(t *testing.T) {
	_, database := newClusterTestService(t)
	stamp := time.Date(2026, 10, 11, 8, 9, 10, 0, time.UTC)
	snapshot := cl1TimestampSnapshot(stamp, models.JSONNullTime{})
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot with null timestamps: %v", err)
	}
	assertNull := func(table, col, where string) {
		t.Helper()
		var isNull bool
		if err := database.QueryRow(`SELECT (` + col + ` IS NULL) FROM ` + table + ` WHERE ` + where).Scan(&isNull); err != nil {
			t.Fatalf("read %s.%s NULL shape: %v", table, col, err)
		}
		if !isNull {
			t.Fatalf("%s.%s 零值必须保留 NULL", table, col)
		}
	}
	assertNull("certificate_configs", "updated_at", "id=1")
	assertNull("cert_jobs", "ca_available_after", "rule_id='lb_cl1acme'")
	assertNull("users", "last_login", "id=5")
	assertNull("api_keys", "last_used", "id=9")
}
