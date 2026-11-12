package services

//
// u-* 并集投影稳定命名冲突——预检逐规则渲染（policiesForRule）但
// u-deny/u-trust/u-bl/u-allow/u-allow-exempt/u-trust12 是全局单文件名，
// 异策略集多规则时后渲染覆盖前者=漏拦+误拦。修复方向：scope 编入规则身份
// （ruleCaddyID），GC regex 收新形态。
//
// refreshIPListProjectionsInLock 丢弃证书快照——热路径渲染经
// MaterializeCertPairs 物化了新证书文件（快照非空）而 JSON 字节一致时返回
// 「收敛」，磁盘新证书+Caddy 内存旧证书静默分叉（「物化即有变⇒强制
// 重载」在热路径失守）。修复方向：三态（收敛/需强制/回退），调用方据态走
// 强制重载。
//
// 资格门（ipListsReferencedByEnabledPolicyLabeled）只查
// ip_acl_list_refs/ip_whitelist_refs，不覆盖仅被 trusted_proxy_range_refs
// 或 CRS 排除 scope=ip/list 条目 ListRefs 引用的名单——保守回退口径缺口。
// 本文件 RED 阶段全部使用既有 API（签名不变更即可编译运行），实现后追加
// 新签名钉测。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// testCertPEM 生成自签证书+私钥 PEM（ECDSA P-256，serial 取纳秒保证多次
// 调用内容互异——场景 v1/v2 材料必须字节不同）。
func testCertPEM(t *testing.T, cn string) (string, string) {
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

// 钉测（RED 先行）：两条规则各绑一个异条目 deny ACL 策略，经生产渲染
// 通道逐规则出预检段。修复前两次渲染先后覆写同一个 u-deny.txt——后渲染的
// 并集顶掉前者，先渲染规则的预检算子读到的文件不再是自己的并集（漏拦+误拦）。
// 修复后各规则投影进 u-deny-<ruleCaddyID>.txt，内容各自正确且互不覆盖。
func TestPrecheckProjectionFilesScopedPerRule(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb-scope-a", "scope-a.example.test", 8080)
	seedHTTPRuleForGeneration(t, database, "lb-scope-b", "scope-b.example.test", 8080)
	pidA := mpGenBindPolicy(t, database, "lb-scope-a", "scope-a-deny", mpGenPolicySpec{
		mode: "detection", enabled: true, ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.5"]`,
	})
	pidB := mpGenBindPolicy(t, database, "lb-scope-b", "scope-b-deny", mpGenPolicySpec{
		mode: "detection", enabled: true, ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["198.51.100.9"]`,
	})

	// When：逐规则走与全量渲染同通道的生产渲染（先 A 后 B——B 的渲染在后，
	// 旧实现下 B 的并集会覆盖 u-deny.txt）。
	_, mainA := mpGenRoutes(t, database, mpGenHTTPRule("lb-scope-a", "scope-a.example.test"))
	_, mainB := mpGenRoutes(t, database, mpGenHTTPRule("lb-scope-b", "scope-b.example.test"))
	preA := wafHandlers(t, mainA)[0]["directives"].(string)
	preB := wafHandlers(t, mainB)[0]["directives"].(string)

	// Then：两条规则的 deny 并集投影互不覆盖（按各自渲染产物中的算子路径
	// 读回文件内容）。
	// 逐策略链投影 scope = 策略身份（p<id>-acl），与引擎共用同一文件：
	// 生产粒度=消费粒度，异规则同策略同文件同字节；异策略必不同文件。
	gotA := readRenderedIPList(t, preA, fmt.Sprintf("p%d-acl", pidA))
	gotB := readRenderedIPList(t, preB, fmt.Sprintf("p%d-acl", pidB))
	if !strings.Contains(gotA, "203.0.113.5/32") {
		t.Fatalf("规则 A 的 deny 并集投影被覆盖（缺 203.0.113.5/32）：A 文件=%q B 文件=%q\nA 预检段：\n%s", gotA, gotB, preA)
	}
	if !strings.Contains(gotB, "198.51.100.9/32") {
		t.Fatalf("规则 B 的 deny 并集投影缺自己的条目 198.51.100.9/32：B 文件=%q", gotB)
	}
	if strings.Contains(gotA, "198.51.100.9") || strings.Contains(gotB, "203.0.113.5") {
		t.Fatalf("逐策略 deny 投影串染（B 条目 %q / A 条目 %q）——异策略集规则不得共享投影文件", gotA, gotB)
	}
}

// 钉测（RED 先行）：证书材料变化（等价证书续期已提交：仅 DB 内容变、
// 规则 JSON 形态不变）后发生名单写路径收敛（autoban merge 资格门命中）——
// 热路径渲染会经 MaterializeCertPairs 把新证书物化落盘，JSON 字节一致，
// 旧实现返回「收敛」（零 /load）→ Caddy 内存停留旧证书静默分叉。修复后必须
// 升级为强制重载收敛（回退全量重载回调）。
func TestCertMaterialChangeForcesReloadOnListConverge(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)
	useTemporaryCertDir(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)

	certV1, keyV1 := testCertPEM(t, "scope.example.test")
	certV2, keyV2 := testCertPEM(t, "scope.example.test")
	if certV1 == certV2 {
		t.Fatal("v1/v2 证书材料必须字节不同")
	}

	// installAutobanFixture 会重初始化临时库——必须在全部播种之前（既有
	// autoban 钉测同序）。
	installAutobanFixture(t, "2026-10-15 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "blocked,logged", false)

	// autoban merge 写的是预置名单——资格门查的是预置名单 id 的引用面，
	// 夹具须把预置名单绑进启用策略（seedAutobanListReferencedByPolicy 同源）。
	seedHotPathPolicy(t, presetListID(t))
	seedHTTPRuleForGeneration(t, db.DB, "lb-tls-probe", "tlsprobe.example.test", 8443)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_tls=1, tls_source='manual', tls_cert=?, tls_key=? WHERE caddy_id=?`,
		certV1, keyV1, "lb-tls-probe"); err != nil {
		t.Fatalf("seed tls rule: %v", err)
	}

	// 首轮全量渲染：物化 v1 证书 + 运行配置就位。
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("首次 /load 次数=%d, want 1", got)
	}

	// 证书续期已提交（仅 DB 内容变化，配置 JSON 形态不变）。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET tls_cert=?, tls_key=? WHERE caddy_id=?`,
		certV2, keyV2, "lb-tls-probe"); err != nil {
		t.Fatalf("update cert material: %v", err)
	}

	// 名单写路径收敛（RunAutobanCycle→merge→autobanConvergeLocked→投影热路径），
	// 刷新器注入生产同款 InLock 变体。
	spy := &autobanConvergeSpy{}
	oldRef, oldRel := autobanProjectionRefresher, autobanReloader
	autobanProjectionRefresher = func() (IPListProjectionOutcome, error) { spy.refreshes++; return s.RefreshIPListProjectionsInLock() }
	autobanReloader = func() error { spy.reloads++; return nil }
	t.Cleanup(func() { autobanProjectionRefresher, autobanReloader = oldRef, oldRel })

	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	if len(presetEntries(t)) != 1 || presetEntries(t)[0].Value != "203.0.113.1" {
		t.Fatalf("名单 merge 结果=%+v, want 新封 203.0.113.1", presetEntries(t))
	}
	if spy.refreshes != 1 {
		t.Fatalf("资格门命中必须走投影热路径刷新：refreshes=%d", spy.refreshes)
	}
	// 热路径渲染物化了新证书（快照非空）⇒ 不得宣称收敛，必须强制
	// 重载收敛（回退全量重载回调）。
	if spy.reloads == 0 {
		t.Fatalf("证书材料被热路径渲染物化后仍宣称收敛（零重载）——磁盘新证书与 Caddy 内存旧证书静默分叉：refreshes=%d reloads=%d", spy.refreshes, spy.reloads)
	}
}

// 钉测（RED 先行）其一：仅被 CRS 排除 scope=list 条目 ListRefs 引用的
// 名单，资格门必须判为「被引用」（否则热路径资格误判未引用→回退全量链，
// 保守口径与契约不符）。
func TestRefGateCoversCRSScopedExclusionListRefs(t *testing.T) {
	newClusterTestService(t)
	listID := seedHotPathList(t, `[]`)
	scoped := fmt.Sprintf(`[{"target":"942100","scope":"list","ips":"","listRefs":[%d]}]`, listID)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, crs_excluded_rules) VALUES ('scope-xc', 'blocking', 1, ?)`, scoped); err != nil {
		t.Fatalf("seed scoped exclusion policy: %v", err)
	}
	if !IPListsReferencedByEnabledPolicy([]int{int(listID)}) {
		t.Fatalf("名单 %d 仅被 CRS 作用域排除引用，资格门判为未引用——保守回退口径缺口", listID)
	}
}

// 钉测（RED 先行）其二：仅被 trusted_proxy_range_refs 引用（受信代理
// 已启用）的名单，资格门必须判为「被引用」（tp.txt 投影消费该名单条目）。
func TestRefGateCoversTrustedProxyRangeRefs(t *testing.T) {
	newClusterTestService(t)
	listID := seedHotPathList(t, `[]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_range_refs=? WHERE id=1`,
		"["+strconv.FormatInt(listID, 10)+"]"); err != nil {
		t.Fatalf("seed trusted proxy refs: %v", err)
	}
	if !IPListsReferencedByEnabledPolicy([]int{int(listID)}) {
		t.Fatalf("名单 %d 仅被 trusted_proxy_range_refs 引用，资格门判为未引用——保守回退口径缺口", listID)
	}
}

// 全形状补钉 ----

// 引擎层钉测：id:12 的 u-trust12 投影同样按规则身份隔离——同一策略
// 形态、两条规则身份、两份不同 stage0 保留检测并集，各自投影文件内容正确
// 且互不覆盖（旧全局单文件名下后渲染覆盖前者=信任集串染）。
func TestEngineTrust12ProjectionScopedPerRule(t *testing.T) {
	stubSecurityLibsAvailable(t)
	policy := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}
	dirA := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb-scope-a", []string{"10.0.0.9"}))
	dirB := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb-scope-b", []string{"192.168.1.0/24"}))
	if gotA := readRenderedIPList(t, dirA, "u-trust12"); gotA != "10.0.0.9/32\n" {
		t.Fatalf("规则 A 的 id:12 信任投影=%q, want 仅 10.0.0.9/32\n%s", gotA, dirA)
	}
	if gotB := readRenderedIPList(t, dirB, "u-trust12"); gotB != "192.168.1.0/24\n" {
		t.Fatalf("规则 B 的 id:12 信任投影=%q, want 仅 192.168.1.0/24（不得被 A 串染）\n%s", gotB, dirB)
	}
	if !strings.Contains(dirA, "u-trust12-lb-scope-a.txt") || !strings.Contains(dirB, "u-trust12-lb-scope-b.txt") {
		t.Fatalf("id:12 投影 scope 必须编入规则身份：A=%q B=%q", dirA, dirB)
	}
}

// 畸形形状：空规则身份必须显性报错（fail-loud——静默退回全局名会原样
// 重建覆盖冲突）。
func TestEmptyRuleIdentityFailsLoud(t *testing.T) {
	policy := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}
	if _, err := BuildCorazaDirectives(policy, nil, "", false, 0, ""); err == nil {
		t.Fatal("BuildCorazaDirectives 空 ruleCaddyID 必须报错")
	}
	if _, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{policy}, ""); err == nil {
		t.Fatal("buildIPPrecheckDirectives 空 ruleCaddyID 必须报错")
	}
}

// 直接钉测：证书材料变化 + 名单写（已提交视图）→ RefreshIPListProjections
// 返回 NeedForce；强制重载收敛后名单再写 → 回到 Converged（三态收敛闭环）。
func TestRefreshTriStateCertMaterialization(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)
	useTemporaryCertDir(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)

	certV1, keyV1 := testCertPEM(t, "triprobe.example.test")
	certV2, keyV2 := testCertPEM(t, "triprobe.example.test")
	seedHTTPRuleForGeneration(t, db.DB, "lb-tri-probe", "triprobe.example.test", 8443)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_tls=1, tls_source='manual', tls_cert=?, tls_key=? WHERE caddy_id=?`,
		certV1, keyV1, "lb-tri-probe"); err != nil {
		t.Fatalf("seed tls rule: %v", err)
	}
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	// 基线：名单写（无证书变化）→ Converged（零 /load 契约的回归形状）。
	listID := seedHotPathList(t, `[{"value":"203.0.113.5","remark":""}]`)
	seedHotPathPolicy(t, listID)
	// 名单新增会改变 p<id>-acl.txt 引用面（策略新增=发射面变化）——先全量
	// 应用一次让发射面落定，再改名单内容。
	if err := s.GenerateAndApplyConfigForce(); err != nil {
		t.Fatalf("基线应用: %v", err)
	}
	out, err := s.RefreshIPListProjections()
	if err != nil || out != ProjectionConverged {
		t.Fatalf("无证书变化且发射面不变的刷新应 Converged: out=%v err=%v", out, err)
	}

	// 目标形状：证书续期已提交（仅内容变化）→ 名单内容再变 → NeedForce。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET tls_cert=?, tls_key=? WHERE caddy_id=?`, certV2, keyV2, "lb-tri-probe"); err != nil {
		t.Fatalf("update cert: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`,
		`[{"value":"203.0.113.5","remark":""},{"value":"198.51.100.7","remark":""}]`, listID); err != nil {
		t.Fatalf("update list: %v", err)
	}
	out, err = s.RefreshIPListProjections()
	if err != nil {
		t.Fatalf("刷新: %v", err)
	}
	if out != ProjectionNeedForce {
		t.Fatalf("证书材料被热路径渲染物化必须返回 NeedForce, got %v", out)
	}
	// 强制重载收敛后（磁盘=内存=DB），名单再写回到 Converged（闭环回归形状）。
	if err := s.GenerateAndApplyConfigForce(); err != nil {
		t.Fatalf("强制收敛: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`,
		`[{"value":"203.0.113.5","remark":""},{"value":"198.51.100.8","remark":""}]`, listID); err != nil {
		t.Fatalf("update list 2: %v", err)
	}
	out, err = s.RefreshIPListProjections()
	if err != nil || out != ProjectionConverged {
		t.Fatalf("证书收敛后的名单写应回到 Converged: out=%v err=%v", out, err)
	}
	if n := admin.loadCount(); n != 3 { // 首次+基线强制+NeedForce 后的强制收敛；两次刷新本身零 /load
		t.Fatalf("刷新路径自身不得 /load（强制重载由调用方执行）: /load=%d", n)
	}
}

// 钉测：大名单（内联展开将撞 48KiB 单行护栏）经
// CRS 作用域限定排除引用时——BuildCorazaDirectives 必须成功（旧 @ipMatch
// 内联形态此形状直接渲染失败=整份配置无法保存），排除规则改投影
// @ipListFast（配置行短、名单内容在投影文件里），且渲染产物必须被 coraza
// 引擎接受（ctl:ruleRemoveById + @ipListFast 新形状的引擎级验证）。
func TestScopedExclusionBigListProjectedAndEngineAccepted(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)  // 名单落库需要 DB（loadIPListEntriesVia 经 db.DB 解析）
	scopedExclusionFixture(t) // CRS 规则索引夹具（942 组含 942100）——排除目标须在索引内才发射
	// 6000 条目 ≈ 80KiB 内联行（48KiB 护栏之上充分余量）。
	var b strings.Builder
	b.WriteString("[")
	for i := range 6000 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"value":"10.%d.%d.%d","remark":""}`, i/65536%256, i/256%256, i%256)
	}
	b.WriteString("]")
	listID := seedHotPathList(t, b.String())
	policy := &models.SecurityPolicy{
		AnomalyThreshold: 5,
		Mode:             "blocking",
		CRSExcludedRules: json.RawMessage(fmt.Sprintf(`[{"target":"942100","scope":"list","ips":"203.0.113.5","listRefs":[%d]}]`, listID)),
	}
	directives, err := BuildCorazaDirectives(policy, db.DB, "", false, 0, "lb-big-probe")
	if err != nil {
		t.Fatalf("大名单作用域排除必须经投影渲染成功（不得触 48KiB 护栏）: %v", err)
	}
	if !strings.Contains(directives, "@ipListFast ") || !strings.Contains(directives, "-crsxc-") {
		t.Fatalf("排除匹配集必须投影 crsxc 哈希命名文件（@ipListFast）:\n%s", directives)
	}
	if !strings.Contains(directives, "ctl:ruleRemoveById=942100") {
		t.Fatalf("作用域排除 ctl 规则缺失:\n%s", directives)
	}
	for _, line := range strings.Split(directives, "\n") {
		if len(line) > 48*1024 {
			t.Fatalf("渲染产物存在超 48KiB 单行（%d 字节）", len(line))
		}
	}
	// 投影文件内容=ips ∪ 名单条目（聚合后——6000 条连续 10.x 聚合为大网段）。
	proj := readRenderedIPList(t, directives, "-crsxc-")
	if !strings.Contains(proj, "203.0.113.5/32") || !strings.Contains(proj, "10.0.0.0/20") {
		t.Fatalf("投影文件须含 ips 与聚合后的名单条目: %q…", proj[:min(200, len(proj))])
	}
	// ctl:ruleRemoveById + @ipListFast 新形状必须被 coraza 编译接受。
	compileForEngineGate(t, directives)
}

// 回归形状：scope=all 条目的 ListRefs 不构成投影引用面（发射侧不消费
// ——emitScopedCRSExclusions 仅收 scope=ip/list），资格门不得误判。
func TestRefGateIgnoresScopeAllListRefs(t *testing.T) {
	newClusterTestService(t)
	listID := seedHotPathList(t, `[]`)
	scoped := fmt.Sprintf(`[{"target":"942100","scope":"all","ips":"","listRefs":[%d]}]`, listID)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, crs_excluded_rules) VALUES ('scope-all', 'blocking', 1, ?)`, scoped); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if IPListsReferencedByEnabledPolicy([]int{int(listID)}) {
		t.Fatalf("scope=all 条目的 ListRefs 不参与发射，名单 %d 不应判为被引用", listID)
	}
}

// 回归形状：受信代理未启用时 trusted_proxy_range_refs 不构成引用面
// （渲染侧 trustedProxyServerFields 按未启用返回，tp.txt 不消费名单）。
func TestRefGateIgnoresDisabledTrustedProxyRefs(t *testing.T) {
	newClusterTestService(t)
	listID := seedHotPathList(t, `[]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=0, trusted_proxy_range_refs=? WHERE id=1`,
		"["+strconv.FormatInt(listID, 10)+"]"); err != nil {
		t.Fatalf("seed trusted proxy refs: %v", err)
	}
	if IPListsReferencedByEnabledPolicy([]int{int(listID)}) {
		t.Fatalf("受信代理未启用时名单 %d 不应判为被引用", listID)
	}
}
