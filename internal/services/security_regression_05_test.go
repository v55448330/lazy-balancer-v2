package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
	"lazy-balancer-v2/wafiplist"
)

// ---- 爬虫名单词法边界与格式校验 ----

func TestParseCrawlerCIDRs_strictTokenBoundaries(t *testing.T) {
	body := "not.an.ip.version.1.2.3.4.5\n" +
		"2026.10.18 release 9.9.9.9.1\n" +
		"host 42.236.12.130\n" +
		"other-valid 142.236.12.130 trailing-digit 42.236.12.1307 trailing-octet 42.236.12.130.999 invalid-octet 999.42.236.12.130\n"
	got, err := parseCrawlerCIDRsForFormat(body, "")
	if err != nil {
		t.Fatalf("parse crawler CIDRs: %v", err)
	}
	// 精确集合同时排除多八位组两侧拼出的合法 IP 片段；只检查三个
	// 样本是否包含/不包含会让额外误收静默通过。
	if joined := strings.Join(got, ","); joined != "42.236.12.130/32,142.236.12.130/32" {
		t.Fatalf("爬虫网段集合=%q, want 两个合法裸 IP，版本号/相邻多八位组片段不得进入", joined)
	}
}

func TestParseCrawlerCIDRsForFormat_rejectsErrorPage(t *testing.T) {
	// json 源返回错误页（HTML）：解析失败必须报错（调用方保留上次快照）。
	if _, err := parseCrawlerCIDRsForFormat("<html>rate limited</html>", "json"); err == nil {
		t.Fatal("json 源返回非 JSON 错误页应报错，不得静默产空/误收")
	}
	// 合法 JSON：结构化字段命中。
	got, err := parseCrawlerCIDRsForFormat(`{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`, "json")
	if err != nil || !containsString(got, "203.0.113.0/24") {
		t.Fatalf("json 结构化提取失败: got=%v err=%v", got, err)
	}
	// html 源：词法提取照常。
	got, err = parseCrawlerCIDRsForFormat("<table><td>198.51.100.7</td></table>", "html")
	if err != nil || !containsString(got, "198.51.100.7/32") {
		t.Fatalf("html 词法提取失败: got=%v err=%v", got, err)
	}
}

// ---- 陈旧 .iplist 文本不得遮蔽集群刚同步的 .fast ----

func TestReadThreatIplistEntries_newerFastWinsOverStaleText(t *testing.T) {
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()
	path := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := os.WriteFile(path, []byte("198.51.100.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 文本是旧代（主节点时期），fast 是集群后同步的新代。
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := wafiplist.WriteFastFile(wafiplist.FastPath(path), []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, nil); err != nil {
		t.Fatal(err)
	}

	vals, err := readThreatIplistEntries("中科大恶意 IP 名单（USTC）")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if containsString(vals, "198.51.100.1") {
		t.Fatalf("陈旧文本条目仍生效: %v", vals)
	}
	if !containsString(vals, "203.0.113.0/24") {
		t.Fatalf("新同步的 .fast 未生效: %v", vals)
	}
}

// ---- 主端 fast 扫描须复用威胁源白名单（与从端写侧对称） ----

func TestScanThreatFastFiles_ignoresUnknownSources(t *testing.T) {
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()
	prefixes := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if err := wafiplist.WriteFastFile(filepath.Join(wafDir, "threat-ustc.iplist.fast"), prefixes, nil); err != nil {
		t.Fatal(err)
	}
	if err := wafiplist.WriteFastFile(filepath.Join(wafDir, "threat-stray.iplist.fast"), prefixes, nil); err != nil {
		t.Fatal(err)
	}
	got := scanThreatFastFiles()
	if _, ok := got["ustc"]; !ok {
		t.Fatalf("合法源未被扫描: %v", got)
	}
	if _, ok := got["stray"]; ok {
		t.Fatalf("未知源名进入 bundle 引用（从端会拒绝整包）: %v", got)
	}
}

// ---- 同名 system=0 名单不得抑制内置 system=1 行 ----

func TestWriteThreatSystemList_seedsSystemRowDespiteUserNameCollision(t *testing.T) {
	_, database := newClusterTestService(t)
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()
	name := db.ThreatListNameBySource("ustc")
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
		VALUES (?, '用户自建同名', '自定义', '[]', 0, datetime('now'), datetime('now'))`, name); err != nil {
		t.Fatal(err)
	}

	changed, err := writeThreatSystemList("ustc", []string{"203.0.113.0/24"})
	if err != nil {
		t.Fatalf("writeThreatSystemList: %v", err)
	}
	if !changed {
		t.Fatal("首次写入应报告内容变化")
	}
	var sysRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND system=1`, name).Scan(&sysRows); err != nil {
		t.Fatal(err)
	}
	if sysRows != 1 {
		t.Fatalf("system=1 行数=%d, want 1（存在性判定须按 system 限定）", sysRows)
	}
}

// ---- 渲染被跳过的策略不得抢走事件归因 ----

func TestSecurityEventsAttributePolicy_skipsRenderSkippedPolicy(t *testing.T) {
	missing := &models.SecurityPolicy{
		ID: 1, Name: "缺失引用", IPRefMissing: true,
		IPBlacklist: json.RawMessage(`["203.0.113.7"]`),
	}
	ok := &models.SecurityPolicy{
		ID: 2, Name: "正常策略",
		IPBlacklist: json.RawMessage(`["203.0.113.7"]`),
	}
	policyByID := map[int]*models.SecurityPolicy{1: missing, 2: ok}
	bindings := map[string][]int{"lb_x": {1, 2}}

	pid, name := securityEventsAttributePolicy("lb_x", "4", "blocked", "203.0.113.7", policyByID, bindings)
	if pid != 2 || name != "正常策略" {
		t.Fatalf("attribution=(%d,%q), want (2,正常策略)（IPRefMissing 策略物理未渲染）", pid, name)
	}
	// 回归形状：唯一候选为缺失策略时仍须归属（不得归零——发射后漂移语义）。
	delete(policyByID, 2)
	pid, name = securityEventsAttributePolicy("lb_x", "4", "blocked", "203.0.113.7", policyByID, map[string][]int{"lb_x": {1}})
	if pid != 1 || name != "缺失引用" {
		t.Fatalf("attribution=(%d,%q), want 兜底归属缺失策略", pid, name)
	}
}

func TestSecurityEventsAttributePolicy_fallbackPrefersRenderedBeforeMissing(t *testing.T) {
	missing := &models.SecurityPolicy{ID: 1, Name: "缺失候选", Mode: "blocking", IPRefMissing: true}
	rendered := &models.SecurityPolicy{ID: 2, Name: "已渲染候选", Mode: "blocking"}
	policyByID := map[int]*models.SecurityPolicy{1: missing, 2: rendered}
	bindings := map[string][]int{"lb_x": {1, 2}}

	// id:11 非 IP/自定义族，两个候选都只能走兜底归因；已渲染者必须优先。
	pid, name := securityEventsAttributePolicy("lb_x", "11", "blocked", "203.0.113.7", policyByID, bindings)
	if pid != 2 || name != "已渲染候选" {
		t.Fatalf("attribution=(%d,%q), want rendered fallback (2,已渲染候选)", pid, name)
	}
}

// ---- 缺失引用错误审计须限流 ----

func TestResolvePolicyIPListRefs_missingRefAuditThrottled(t *testing.T) {
	_, database := newClusterTestService(t)
	if db.AuditDB == nil {
		t.Skip("audit db unavailable")
	}
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()
	name := db.ThreatListNameBySource("ustc")
	// system=1 名单名唯一，威胁库行由 DB 初始化播种；直接复用其 id
	// （空 entries + 缺失 .iplist = 装载失败形态）。
	var listID int64
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1`, name).Scan(&listID); err != nil {
		t.Fatal(err)
	}

	policy := func() []*models.SecurityPolicy {
		return []*models.SecurityPolicy{{
			ID: 1, Name: "限流测试策略", IPACLListRefs: "[" + strconv.FormatInt(listID, 10) + "]",
		}}
	}
	resolvePolicyIPListRefs(policy(), nil)
	resolvePolicyIPListRefs(policy(), nil)

	var audits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='安全策略' AND action='渲染跳过'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("渲染跳过审计行=%d, want 1（同一缺失引用在限流窗口内仅留痕一次）", audits)
	}
}

// ---- 爬虫名单更新后的投影收敛（复用威胁库单源热路径） ----

func TestCrawlerRunUpdate_convergesProjectionWhenContentChanged(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	defer func() { threatProjectionRefresher, threatReloader = oldRefresher, oldReloader }()
	refreshCalls, reloadCalls := 0, 0
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) {
		refreshCalls++
		return ProjectionConverged, nil
	}
	threatReloader = func() error { reloadCalls++; return nil }

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`))
	}))
	defer ts.Close()
	// 先播种内置源（fresh DB 无行时 UPDATE 会影响 0 行，RunUpdate 再补种真实 URL）。
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET url=?, update_enabled=1 WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	// 收缩门以当前快照为基线；预置 1 条旧值，让本轮 1 条新值属于「内容变化」而非塌缩。
	if err := upsertCrawlerIPList("googlebot", []string{"198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	// manual 触发会跑全部启用源；其余内置源是真实外网 URL，必须禁用，
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0 WHERE name<>'googlebot'`); err != nil {
		t.Fatal(err)
	}

	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Trigger: "manual"}); err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if refreshCalls != 1 || reloadCalls != 0 {
		t.Fatalf("refresh=%d reload=%d, want 1/0（内容变化经投影热路径收敛）", refreshCalls, reloadCalls)
	}
}

func TestConvergeIPListProjection_fallsBackToReload(t *testing.T) {
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	defer func() { threatProjectionRefresher, threatReloader = oldRefresher, oldReloader }()
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) { return ProjectionNeedForce, nil }
	reloads := 0
	threatReloader = func() error { reloads++; return nil }
	convergeIPListProjectionAfterMutation("test")
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1（未证实收敛须回退全量重载）", reloads)
	}
}

// ---- 集群 apply 后重建爬虫运行快照 ----

func TestApplySnapshot_rebuildsCrawlerRuntimeSnapshot(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	old := rebuildCrawlerSnapshotForSync
	calls := 0
	rebuildCrawlerSnapshotForSync = func() error { calls++; return nil }
	defer func() { rebuildCrawlerSnapshotForSync = old }()

	base, err := service.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	base.Version = 2
	if err := syncService.applySnapshot(context.Background(), base); err != nil {
		t.Fatalf("applySnapshot: %v", err)
	}
	if calls != 1 {
		t.Fatalf("爬虫快照重建调用=%d, want 1（安全节应用后必须从 DB 重建运行快照）", calls)
	}
}

// ---- helpers ----

// 此前 {"error":"rate limited from 1.2.3.4"} 会把 1.2.3.4 当官方网段写进
// 爬虫豁免名单（真实爬虫失去豁免、被列 IP 反而获得豁免面）。
func TestParseCrawlerCIDRs_jsonRequiresStructuredFields(t *testing.T) {
	// Given 合法 JSON 的错误页（无 ipv4Prefix/ipv6Prefix 字段）
	body := `{"error":"rate limited from 1.2.3.4","retry_after":60}`
	// When parse as json
	got, err := parseCrawlerCIDRsForFormat(body, "json")
	// Then 显式失败（调用方保留上次快照），绝不返回词法命中的 1.2.3.4
	if err == nil {
		t.Fatalf("结构化字段缺失的 JSON 应报错，got=%v", got)
	}

	// Given 结构化字段与错误文本、相邻多八位组混杂
	body = `{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}],"note":"blocked 198.51.100.7 1198.51.100.7 198.51.100.70"}`
	// When
	got, err = parseCrawlerCIDRsForFormat(body, "json")
	// Then 精确集合只含结构化网段，错误页/note 中的 IP 及其片段均不得进入
	if err != nil {
		t.Fatalf("结构化 JSON 解析失败: %v", err)
	}
	if joined := strings.Join(got, ","); joined != "203.0.113.0/24" {
		t.Fatalf("JSON 源网段集合=%q, want 仅结构化字段", joined)
	}

	// 对照：非 json 格式（html/空）仍按词法提取（源站形态未变）。
	got, err = parseCrawlerCIDRsForFormat(`{"error":"from 1.2.3.4"}`, "")
	if err != nil || !containsString(got, "1.2.3.4/32") {
		t.Fatalf("非 JSON 格式词法提取回归: got=%v err=%v", got, err)
	}
}

// 摘要/列表的存在性判定只取 .fast 头部规模（不展开 []string），且必须与
// 渲染同源：新 .fast 生效、空 .fast 为假、陈旧文本不得遮蔽新 fast。
func TestThreatIplistHasEntries_fastFirstWithoutExpansion(t *testing.T) {
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()
	path := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := os.WriteFile(path, []byte("198.51.100.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	// 空 .fast（新代、零条目）+ 旧文本有 1 条：按 .fast 代际 → 无生效条目。
	if err := wafiplist.WriteFastFile(wafiplist.FastPath(path), nil, nil); err != nil {
		t.Fatal(err)
	}
	has, err := threatIplistHasEntries(path)
	if err != nil {
		t.Fatalf("empty fast: %v", err)
	}
	if has {
		t.Fatal("空 .fast 代际必须判无生效条目（不得回落到陈旧文本）")
	}

	// 写入新 fast 条目 → 有生效条目。
	if err := wafiplist.WriteFastFile(wafiplist.FastPath(path), []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, nil); err != nil {
		t.Fatal(err)
	}
	has, err = threatIplistHasEntries(path)
	if err != nil || !has {
		t.Fatalf("has=%v err=%v, want true", has, err)
	}

	// 两代际均不可用 → 错误上抛（严格模式由调用方跳过策略），不得静默 false。
	if err := os.Remove(wafiplist.FastPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := threatIplistHasEntries(path); err == nil {
		t.Fatal("两个代际都不可用必须报错（fail-visible，不得按空集处理）")
	}
}
