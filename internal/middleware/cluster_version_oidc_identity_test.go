package middleware

// OIDC 身份三列（auth_provider/oidc_subject/oidc_issuer）的 UPDATE 必须独立
// bump cluster_version：issuer 归一迁移（auth_oidc.go migrateOIDCIdentityIssuer）
// 是真实 UPDATE 写路径，此前仅靠同事务 oidc_config 写回 bump 掩盖——直接改写
// 身份列（不伴随配置写）时稳态变更永不传播到从节点。

import (
	"testing"
)

func TestClusterVersionTrigger_oidcIdentityUpdateBumpsVersion(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := InstallClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
		VALUES (77,'oidc-user','','user',1,'oidc','subject-77','https://old.example')`); err != nil {
		t.Fatalf("seed oidc user: %v", err)
	}
	// 版本基线（INSERT 已 bump，重置便于断言）
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=100 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When：仅迁移 oidc_issuer（不伴随 oidc_config 写回）
	if _, err := database.Exec(`UPDATE users SET oidc_issuer='https://new.example' WHERE id=77`); err != nil {
		t.Fatalf("migrate issuer: %v", err)
	}

	// Then：版本必须 bump（身份列在 OF 列表内）
	if got := clusterVersion(t, database); got != 101 {
		t.Fatalf("issuer 迁移后 cluster_version=%d, want 101（身份列 UPDATE 必须独立 bump）", got)
	}

	// 回归：同值写不 bump（值变化守卫）
	if _, err := database.Exec(`UPDATE users SET oidc_issuer='https://new.example' WHERE id=77`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 101 {
		t.Fatalf("同值写后 cluster_version=%d, want 101（值变化守卫不得抖动）", got)
	}

	// auth_provider/oidc_subject 同样入 OF
	if _, err := database.Exec(`UPDATE users SET oidc_subject='subject-77-renamed' WHERE id=77`); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 102 {
		t.Fatalf("subject 改写后 cluster_version=%d, want 102", got)
	}
}
