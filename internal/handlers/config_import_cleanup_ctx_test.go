package handlers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given 导入已提交（事务落地）但请求 ctx 已被取消——前端超时/用户关页/网关
// 断连的真实形态。
// When 提交后产物清理（锁外执行的删文件阶段）运行。
// Then 清理必须照常完成：已不在库内的规则私钥/证书文件要删掉。
// 旧实现直接消费请求 ctx，取消后在读取规则集处早退，整段清理一次不执行
// ——数据卷里保留管理员以为已随规则删除的 ACME 私钥。
func TestImportCommitCleanupSurvivesCanceledRequestContext(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	// 库中只剩 lb_clean_keep；lb_clean_gone 已被导入整体替换掉。
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_clean_keep','keep','keep.example.test','http',8180,1,1,'manual','CERT','KEY')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if err := services.WriteCertFiles("lb_clean_gone", "CERT", "KEY"); err != nil {
		t.Fatalf("write gone rule cert files: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel() // 请求生命周期已结束（客户端断开）
	session := &configImportSession{ctx: canceled}

	// When：提交前收集的待删集（事务视图）在锁外按计划删除
	session.runPostCommitCleanup(&importArtifactCleanupPlan{disappeared: []string{"lb_clean_gone"}})

	// Then 消失规则的证书/私钥文件已清理
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, "lb_clean_gone"+suffix)); err == nil {
			t.Fatalf("消失规则 %s 的私钥材料残留（清理受请求 ctx 取消影响）", "lb_clean_gone"+suffix)
		}
	}
}

// Given 导入事务视图内收集提交后清理计划。
// When collectPostCommitCleanup 执行。
// Then cert_jobs 的必要删除在事务内完成（孤儿行 + 已非 ACME 签发态的行），
// 判定集只记录待删产物（消失规则/无材料规则），不在锁内删任何文件或行。
func TestCollectPostCommitCleanupWritesCertJobRowsInTransaction(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	ctx := context.Background()
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_collect_acme','acme','acme.example.test','http',8281,1,1,'acme_dns','',''),
		('lb_collect_manual','manual','manual.example.test','http',8282,1,1,'manual','CERT','KEY'),
		('lb_collect_null_source','null source','null-source.example.test','http',8283,1,1,NULL,'',''),
		('lb_collect_null_tls','null tls','null-tls.example.test','http',8284,1,NULL,'acme_dns','','')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := db.DB.Exec(`
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_collect_acme','acme.example.test','issued','CERT','KEY'),
		('lb_collect_manual','manual.example.test','issued','CERT','KEY'),
		('lb_collect_null_source','null-source.example.test','issued','CERT','KEY'),
		('lb_collect_null_tls','null-tls.example.test','issued','CERT','KEY'),
		('lb_collect_orphan','orphan.example.test','issued','CERT','KEY')`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	if err := services.WriteCertFiles("lb_collect_orphan", "CERT", "KEY"); err != nil {
		t.Fatalf("write orphan cert files: %v", err)
	}

	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	session := &configImportSession{
		ctx: ctx, tx: tx, replaceRuleArtifacts: true,
		existingRuleIDs: []string{"lb_collect_acme", "lb_collect_manual", "lb_collect_gone"},
	}

	// When
	plan, err := session.collectPostCommitCleanup()
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("collect cleanup plan: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	// Then ① 孤儿行与失效（非 ACME，含 NULL 存量形态）行在事务内删除，ACME 行保留
	var orphan, manual, nullSource, nullTLS, acme int
	if err := db.DB.QueryRow(`SELECT
		(SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_collect_orphan'),
		(SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_collect_manual'),
		(SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_collect_null_source'),
		(SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_collect_null_tls'),
		(SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_collect_acme')`).Scan(&orphan, &manual, &nullSource, &nullTLS, &acme); err != nil {
		t.Fatalf("count cert jobs: %v", err)
	}
	if orphan != 0 || manual != 0 || nullSource != 0 || nullTLS != 0 || acme != 1 {
		t.Fatalf("cert_jobs 行 orphan=%d manual=%d null_source=%d null_tls=%d acme=%d, want 0/0/0/0/1", orphan, manual, nullSource, nullTLS, acme)
	}
	// Then ② 判定集记录消失规则；锁内不删文件（孤儿行对应的文件仍在磁盘，
	// 删除动作归锁外执行）
	if len(plan.disappeared) != 1 || plan.disappeared[0] != "lb_collect_gone" {
		t.Fatalf("plan.disappeared=%v, want [lb_collect_gone]", plan.disappeared)
	}
	if _, err := os.Stat(filepath.Join(certDir, "lb_collect_orphan.crt")); err != nil {
		t.Fatalf("锁内收集阶段不得删除证书文件: %v", err)
	}
}
