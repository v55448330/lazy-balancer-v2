package handlers

// 第 77 轮审计修复钉测（HP77-1/HP77-5/T1，TDD RED 先行）。
//
// HP77-1【P2】：拒绝路径投影未回滚——渲染副作用（稳定命名投影写盘）在
// ConfigRejected/ErrUnvalidatedApply 分支只回滚证书不回滚投影，DB 回滚但
// 投影文件=未提交内容，控制面与库分叉至下次成功渲染。修复：拒绝分支以
// 已提交库值重渲染一次仅重写投影文件（零 /load）。
//
// HP77-5【P3】：NeedForce 强制被拒时的证书/投影材料回退——与 HP77-1 同一
// 机制收口（拒绝=磁盘回滚到已提交态；证书物化内容=已提交 PEM，物化落盘
// 本身即已提交态，需回退的是投影与 DB 侧）。
//
// T1（测试盲区）：handler tryIPListHotPathApply NeedForce 分支零覆盖。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// r77TestCertPEM 生成自签证书+私钥 PEM（ECDSA P-256，serial 取纳秒保证多次
// 调用内容互异——NeedForce 场景 v1/v2 材料必须字节不同）。与 services 侧
// r76TestCertPEM 同形（测试助手不可跨包引用，各自持有）。
func r77TestCertPEM(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		DNSNames:              []string{cn},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// seedR77InlineACLPolicy 建「http 规则 + deny ACL 策略（inline 条目，不经
// 名单引用）+ 绑定」，返回策略 id（投影文件名 p<id>-acl.txt 的身份段）。
func seedR77InlineACLPolicy(t *testing.T, entries string) int64 {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb-hot','hot','http','hot.example.test',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb-hot','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_acl_list_refs)
		VALUES ('R77 策略', 'off', 1, 'stage1', 1, 'deny', ?, '[]')`, entries)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb-hot', ?)`, policyID); err != nil {
		t.Fatalf("bind policy: %v", err)
	}
	return policyID
}

// HP77-1 全量链形状（finishTxApply 拒绝分支）：已提交策略投影在役，策略更新
// 被 CLI 校验拒绝（渲染先于校验完成，投影文件已按未提交内容落盘）——拒绝后
// 投影必须回到已提交内容（旧实现停留未提交内容=必红）。
func TestSecurityPolicySave_cliRejectionRestoresCommittedProjection(t *testing.T) {
	f := newHotPathIPListFixture(t)
	f.router.PUT("/security/policies/:id", f.h.UpdateSecurityPolicy)
	policyID := seedR77InlineACLPolicy(t, `["203.0.113.5"]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := f.projectionContent(policyID)
	if committed != "203.0.113.5/32\n" {
		t.Fatalf("已提交投影基线=%q", committed)
	}

	// CLI 校验桩拒绝一切（渲染已完成——投影已按未提交内容重写）。
	f.h.caddyService.SetCLIValidatorForTest(func([]byte) error {
		return fmt.Errorf("cli: r77 rejected")
	})
	rec := f.putJSON(fmt.Sprintf("/security/policies/%d", policyID),
		map[string]any{"ip_acl_list": `["198.51.100.7"]`})
	if rec.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}

	// Then：投影文件回到已提交内容（HP77-1：DB 回滚但文件=未提交内容即分叉）。
	if got := f.projectionContent(policyID); got != committed {
		t.Fatalf("拒绝后投影文件=%q, want 已提交内容 %q（HP77-1：拒绝路径投影未回滚）", got, committed)
	}
	var acl string
	if err := db.DB.QueryRow(`SELECT ip_acl_list FROM security_policies WHERE id=?`, policyID).Scan(&acl); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if acl != `["203.0.113.5"]` {
		t.Fatalf("拒绝后 ip_acl_list=%q, want 已提交值", acl)
	}
}

// HP77-1 热路径形状 + HP77-5（T1 NeedForce 分支）：名单写经投影热路径重写
// 投影（未提交内容落盘）并物化已提交的新证书 → NeedForce；强制重载被 Caddy
// 拒绝 → tx 回滚 + 磁盘回退到已提交态（投影=已提交名单内容，证书材料=已
// 提交 PEM）。旧实现投影停留未提交内容=必红。
func TestIPListHotPath_needForceRejectedRestoresCommittedState(t *testing.T) {
	f := newHotPathIPListFixture(t)
	certDir := t.TempDir()
	restoreCertDir := services.SetCertDirForTest(certDir)
	t.Cleanup(restoreCertDir)
	certV1, keyV1 := r77TestCertPEM(t, "hot.example.test")
	certV2, keyV2 := r77TestCertPEM(t, "hot.example.test")

	listID, policyID := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_tls=1, tls_source='manual', tls_cert=?, tls_key=? WHERE caddy_id='lb-hot'`,
		certV1, keyV1); err != nil {
		t.Fatalf("seed tls rule: %v", err)
	}
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := f.projectionContent(policyID)

	// 已提交证书续期（v2 落库；磁盘仍 v1——下次渲染经 MaterializeCertPairs
	// 物化 v2 → 快照非空）。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET tls_cert=?, tls_key=? WHERE caddy_id='lb-hot'`, certV2, keyV2); err != nil {
		t.Fatalf("renew cert: %v", err)
	}

	// 强制重载被 Caddy 拒绝。
	f.rejectLoads(1)
	rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]string{"value": "198.51.100.7"})
	if rec.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400（NeedForce 强制被拒=拒绝回滚）", rec.Code, rec.Body.String())
	}

	// HP77-1：投影文件回到已提交内容（refresh 渲染已按未提交条目重写）。
	if got := f.projectionContent(policyID); got != committed {
		t.Fatalf("NeedForce 拒绝后投影文件=%q, want 已提交内容 %q（HP77-1 热路径形状）", got, committed)
	}
	// HP77-5：磁盘证书材料=已提交 PEM（v2 物化内容即已提交态）。
	onDisk, err := os.ReadFile(filepath.Join(certDir, "lb-hot.crt"))
	if err != nil {
		t.Fatalf("读物化证书: %v", err)
	}
	if string(onDisk) != certV2 {
		t.Fatalf("磁盘证书≠已提交 PEM（HP77-5）")
	}
	// DB 回滚（既有语义钉住）。
	var entries string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, listID).Scan(&entries); err != nil {
		t.Fatalf("read list: %v", err)
	}
	if entries != `[{"value":"203.0.113.5","remark":""}]` {
		t.Fatalf("拒绝后名单条目=%q, want 已提交值", entries)
	}
}

// HP77-1 链覆盖钉（发射面变化形态）：allow 模式名单空↔非空=发射面出现 →
// 热路径 Fallback 落回 finishTxApply 全量链 → CLI 拒绝 → 400 + DB 回滚。
// （已提交态不发射该投影——回退后文件停留为未被运行配置引用的惰性孤儿，
// 由 24h GC 回收；内容级回滚断言由上面两条在役投影形状承载。）
func TestIPListWrite_cliRejectionRollsBackListEntries(t *testing.T) {
	f := newHotPathIPListFixture(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
		VALUES ('lb-hot','hot','http','hot.example.test',8080,'weighted_round_robin',1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb-hot','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('R77 名单', '测试', '[]')`)
	if err != nil {
		t.Fatalf("seed list: %v", err)
	}
	listID, _ := res.LastInsertId()
	res, err = db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_acl_list_refs)
		VALUES ('R77 allow 策略', 'off', 1, 'stage1', 1, 'allow', '[]', ?)`, fmt.Sprintf("[%d]", listID))
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb-hot', ?)`, policyID); err != nil {
		t.Fatalf("bind policy: %v", err)
	}
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}

	f.h.caddyService.SetCLIValidatorForTest(func([]byte) error {
		return fmt.Errorf("cli: r77 rejected")
	})
	rec := f.postJSON(fmt.Sprintf("/security/ip-lists/%d/ips", listID), map[string]string{"value": "198.51.100.7"})
	if rec.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var entries string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, listID).Scan(&entries); err != nil {
		t.Fatalf("read list: %v", err)
	}
	if entries != `[]` {
		t.Fatalf("拒绝后名单条目=%q, want 已提交值 []", entries)
	}
}

// HP77-1 链覆盖钉（导入链，ValidateTxRenderViaCLI 快照回退旁）：导入会话
// 的 CLI 校验拒绝 → session.abort 回滚 → 投影回已提交内容（旧实现停留导入
// 内容=必红）。
func TestImportConfigBackup_cliRejectionRestoresCommittedProjection(t *testing.T) {
	f := newHotPathIPListFixture(t)
	// ImportConfigBackup 经 requireMaster——夹具未装配 ClusterService，补同款；
	// 导入核心读 branding 配置（h.cfg.DataDir），补最小 cfg。
	f.h.clusterService = services.NewClusterService(db.DB, "")
	f.h.cfg = &config.Config{DataDir: f.dir}
	f.router.POST("/config/import", f.h.ImportConfigBackup)
	policyID := seedR77InlineACLPolicy(t, `["203.0.113.5"]`)
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := f.projectionContent(policyID)

	f.h.caddyService.SetCLIValidatorForTest(func([]byte) error {
		return fmt.Errorf("cli: r77 rejected")
	})
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":                 {{"caddy_id": "lb-hot", "name": "hot", "protocol": "http", "domain": "hot.example.test", "listen_port": 8080, "enabled": 1}},
		"upstreams":                {{"rule_id": "lb-hot", "host": "127.0.0.1", "port": 9000, "enabled": 1}},
		"security_policies":        {{"id": policyID, "name": "R77 策略", "mode": "off", "enabled": 1, "policy_type": "stage1", "ip_acl_enabled": 1, "ip_acl_mode": "deny", "ip_acl_list": `["198.51.100.7"]`, "ip_acl_list_refs": "[]"}},
		"security_policy_bindings": {{"rule_caddy_id": "lb-hot", "policy_id": policyID}},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	req.Header.Set("Content-Type", "application/json")
	f.router.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatalf("导入应被 CLI 校验拒绝: body=%s", rec.Body.String())
	}
	if got := f.projectionContent(policyID); got != committed {
		t.Fatalf("导入拒绝后投影文件=%q, want 已提交内容 %q（HP77-1 导入链）", got, committed)
	}
}
