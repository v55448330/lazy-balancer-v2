package services

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
)

func TestTrustedProxyPrefixTooWide_acceptsOfficialCDNv6Ranges(t *testing.T) {
	// Cloudflare 官方列表含 2a06:98c0::/29；/96 会拒绝全部真实 CDN 回源段。
	for _, tc := range []struct {
		cidr string
		want bool
	}{
		{cidr: "2a06:98c0::/29", want: false},
		{cidr: "2400:cb00::/32", want: false},
		{cidr: "2001:db8::/28", want: true},
		{cidr: "::/0", want: true},
		{cidr: "104.16.0.0/13", want: false},
		{cidr: "0.0.0.0/8", want: true},
		// IPv4 最小前缀长度的边界对：`0.0.0.0/8` 同时命中 AllSpace 名单（|| 短路），
		// 故它无法证伪 `Bits() < 8` 判据。以下两条避开 AllSpace：/8 恰好合法、
		// /7 过宽——把 v4 下限改成 12/13 任一时 `1.0.0.0/8` 立刻变红。
		{cidr: "1.0.0.0/8", want: false},
		{cidr: "1.0.0.0/7", want: true},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tc.cidr)
			if got := TrustedProxyPrefixTooWide(prefix); got != tc.want {
				t.Fatalf("TrustedProxyPrefixTooWide(%s)=%v, want %v", tc.cidr, got, tc.want)
			}
		})
	}
}

// 规范形态单源：Masked 剥主机位、4in6 映射折成等价 v4 再判宽——映射写法的
// 位数（/96 ≥ IPv6 下限 /29）与实际生效的 v4 覆盖范围必须同口径，否则
// mapped 主机位变体绕过全空间门后又被投影装载折叠成 0.0.0.0/0。
func TestTrustedProxyPrefixCanonical_mappedVariants(t *testing.T) {
	for _, tc := range []struct {
		value    string
		want     string
		wantWide bool
	}{
		{"::ffff:0.0.0.1/96", "0.0.0.0/0", true}, // 主机位变体 = canonical 全空间
		{"::ffff:0:0/96", "0.0.0.0/0", true},
		{"::ffff:0.0.0.0/104", "0.0.0.0/8", true}, // 等价 v4 /8（既有全空间组）
		{"::ffff:0.0.0.0/97", "0.0.0.0/1", true},  // 等价 v4 /1 低于 /8 下限
		{"::ffff:0.0.0.1/95", "0.0.0.0/0", true},  // 位数 <96：覆盖整个 v4-mapped 空间
		{"::ffff:203.0.113.7/120", "203.0.113.0/24", false},
		{"::ffff:203.0.113.7/128", "203.0.113.7/32", false},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8", false},
		{"192.0.2.129/24", "192.0.2.0/24", false},
		{"2a06:98c0::1/29", "2a06:98c0::/29", false},
		{"::/0", "::/0", true},
		{"0.0.0.0/8", "0.0.0.0/8", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tc.value)
			canonical := TrustedProxyPrefixCanonical(prefix)
			if canonical.String() != tc.want {
				t.Fatalf("TrustedProxyPrefixCanonical(%s)=%s, want %s", tc.value, canonical, tc.want)
			}
			if got := TrustedProxyPrefixTooWide(prefix); got != tc.wantWide {
				t.Fatalf("TrustedProxyPrefixTooWide(%s)=%v, want %v", tc.value, got, tc.wantWide)
			}
			// 归一幂等：写侧/渲染侧可重复应用（渲染对已归一的值再判一次）
			if again := TrustedProxyPrefixCanonical(canonical); again != canonical {
				t.Fatalf("TrustedProxyPrefixCanonical 不幂等：%s → %s", canonical, again)
			}
		})
	}
}

// 受信代理网段引用 IP 地址列表（trusted_proxy_range_refs，2026-10-12）：
// 内联 CIDR ∪ 引用名单条目合并投影（2026-10-15 热路径化，tp.txt/lb_file）。
func TestTrustedProxyRender_expandsReferencedLists(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tpr", "tpr.example.test", 8080)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('CDN 回源', 'CDN 节点', '[{"value":"198.51.100.0/24","remark":""},{"value":"192.0.2.7","remark":"与内联重复"},{"value":"203.0.113.99","remark":""}]')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24","192.0.2.7"]', trusted_proxy_range_refs=? WHERE id=1`,
		"["+jsonInt(listID)+"]"); err != nil {
		t.Fatal(err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}

	// Then
	apps := generated["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	if len(servers) == 0 {
		t.Fatal("no servers rendered")
	}
	// Then：发射 lb_file 源，合并网段（内联 ∪ 引用名单）投影进稳定路径文件
	// （tp.txt）。内容口径=投影聚合（排序+去重+包含归并）后的并集——被内联
	// /24 包含的 203.0.113.99/32 归并入 203.0.113.0/24（匹配语义逐 IP 等
	// 价），裸 IP 补 /32、跨来源去重不变。
	want := []string{"192.0.2.7/32", "198.51.100.0/24", "203.0.113.0/24"}
	tpPath := filepath.Join(IPListDataDir, "tp.txt")
	raw, err := os.ReadFile(tpPath)
	if err != nil {
		t.Fatalf("读受信代理投影 %s: %v", tpPath, err)
	}
	content := string(raw)
	for _, entry := range want {
		if !strings.Contains(content, entry) {
			t.Fatalf("投影内容=%q, want 含 %s", content, entry)
		}
	}
	for name, serverVal := range servers {
		srv, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}
		tp, ok := srv["trusted_proxies"].(map[string]interface{})
		if !ok {
			t.Fatalf("server %s missing trusted_proxies", name)
		}
		if tp["source"] != "lb_file" {
			t.Fatalf("server %s trusted_proxies.source=%v, want lb_file", name, tp["source"])
		}
		if path, _ := tp["path"].(string); path != tpPath {
			t.Fatalf("server %s trusted_proxies.path=%v, want %s", name, tp["path"], tpPath)
		}
		if _, has := tp["ranges"]; has {
			t.Fatalf("server %s trusted_proxies 不得再内联 ranges（lb_file 源）", name)
		}
	}
}

// 名单不存在（悬空引用，仅见于带外改库/导入）→ 该名单贡献零条目，渲染
// 照常成功（保存侧校验与删除守卫保证常规路径不产生悬空引用）。
func TestTrustedProxyRender_missingRefListContributesZero(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tpm", "tpm.example.test", 8080)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24"]', trusted_proxy_range_refs='[424242]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}

	// Then：投影文件仅内联（悬空引用贡献零条目），发射 lb_file 源
	tpPath := filepath.Join(IPListDataDir, "tp.txt")
	raw, err := os.ReadFile(tpPath)
	if err != nil {
		t.Fatalf("读受信代理投影 %s: %v", tpPath, err)
	}
	if content := string(raw); strings.TrimSpace(content) != "203.0.113.0/24" {
		t.Fatalf("投影内容=%q, want 仅内联 203.0.113.0/24（悬空引用贡献零条目）", content)
	}
	apps := generated["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	checkedServers := 0
	for name, serverVal := range servers {
		srv, ok := serverVal.(map[string]interface{})
		if !ok {
			continue
		}
		tp, ok := srv["trusted_proxies"].(map[string]interface{})
		if !ok {
			t.Fatalf("server %s missing trusted_proxies", name)
		}
		if tp["source"] != "lb_file" {
			t.Fatalf("server %s trusted_proxies.source=%v, want lb_file", name, tp["source"])
		}
		if path, _ := tp["path"].(string); path != tpPath {
			t.Fatalf("server %s trusted_proxies.path=%v, want %s", name, tp["path"], tpPath)
		}
		checkedServers++
	}
	// 正向控制：渲染结果里必须有可检 server，集合为空时循环断言空转。
	if checkedServers == 0 {
		t.Fatalf("no servers rendered: servers=%v", servers)
	}
}

// 旧库/带外残留的 mapped 主机位变体在渲染侧必须跳过——投影装载
// （wafiplist.ParseIPEntry）会把 mapped /96 Unmap + bits-96 折叠成
// 0.0.0.0/0，等于信任任意 IPv4 来源的伪造头。写侧已 400，此处覆盖升级前
// 已落库的形态与带外改库。
func TestTrustedProxyRender_skipsMappedAllSpaceVariants(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tp_mapped", "tp-mapped.example.test", 8080)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges=? WHERE id=1`,
		`["::ffff:0.0.0.1/96","::ffff:0.0.0.1/95","::ffff:203.0.113.9/96","::ffff:0.0.0.0/104","203.0.113.0/24"]`); err != nil {
		t.Fatal(err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}

	tpPath := filepath.Join(IPListDataDir, "tp.txt")
	raw, err := os.ReadFile(tpPath)
	if err != nil {
		t.Fatalf("读受信代理投影 %s: %v", tpPath, err)
	}
	content := string(raw)
	if strings.Contains(content, "::ffff:") || strings.Contains(content, "0.0.0.0/") {
		t.Fatalf("投影不得含 mapped 全空间变体或 v4 全空间形态:\n%s", content)
	}
	if !strings.Contains(content, "203.0.113.0/24") {
		t.Fatalf("合法网段必须保留:\n%s", content)
	}

	// 消费侧同一结论：装载出的前缀集不得含全空间段（信任任意来源）。
	wafiplist.EvictIPListCache(tpPath)
	prefixes, err := wafiplist.LoadPrefixesFresh(tpPath)
	if err != nil {
		t.Fatalf("装载受信代理投影: %v", err)
	}
	for _, prefix := range prefixes {
		if prefix.Bits() == 0 {
			t.Fatalf("投影装载出全空间前缀 %s（信任任意来源）", prefix)
		}
	}
}

// 唯一网段被跳过（mapped 全空间变体）时必须落零网段降级说明——面板
// 「已启用」与实际零信任不可区分。
func TestTrustedProxyRender_mappedAllSpaceOnlyCarriesDegradation(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tp_mapped_only", "tp-mapped-only.example.test", 8080)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["::ffff:0.0.0.1/96"]', trusted_proxy_range_refs='[]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	degraded, _ := generated[caddyConfigDegradationKey].(string)
	if !strings.Contains(degraded, "没有任何有效网段") {
		t.Fatalf("唯一网段被跳过时必须携带零网段降级说明, got %q", degraded)
	}
}

// 引用名单通道同口径：名单条目为 mapped 主机位变体（升级前存量）时投影
// 不得携带，名单内合法条目照常保留。
func TestTrustedProxyRender_skipsMappedAllSpaceRefEntries(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tp_mapped_ref", "tp-mapped-ref.example.test", 8080)
	res, err := database.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('mapped-ref', 'CDN 节点', '[{"value":"::ffff:0.0.0.1/96","remark":""},{"value":"198.51.100.0/24","remark":""}]')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='[]', trusted_proxy_range_refs=? WHERE id=1`,
		"["+jsonInt(listID)+"]"); err != nil {
		t.Fatal(err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	raw, err := os.ReadFile(filepath.Join(IPListDataDir, "tp.txt"))
	if err != nil {
		t.Fatalf("读受信代理投影: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, "::ffff:") || strings.Contains(content, "0.0.0.0/") {
		t.Fatalf("引用名单的 mapped 全空间变体不得进入投影:\n%s", content)
	}
	if !strings.Contains(content, "198.51.100.0/24") {
		t.Fatalf("名单内合法条目必须保留:\n%s", content)
	}
}

// 合法 mapped 精确段不得回退：投影装载后是等价 v4 前缀（匹配语义逐 IP 等价）。
func TestTrustedProxyRender_keepsPreciseMappedRanges(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tp_mapped_ok", "tp-mapped-ok.example.test", 8080)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges=? WHERE id=1`,
		`["::ffff:198.51.100.7/128","::ffff:203.0.113.0/120"]`); err != nil {
		t.Fatal(err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	tpPath := filepath.Join(IPListDataDir, "tp.txt")
	raw, err := os.ReadFile(tpPath)
	if err != nil {
		t.Fatalf("读受信代理投影 %s: %v", tpPath, err)
	}
	content := string(raw)
	for _, want := range []string{"198.51.100.7/32", "203.0.113.0/24"} {
		if !strings.Contains(content, want) {
			t.Fatalf("投影缺失 %s（mapped 精确段不得回退）:\n%s", want, content)
		}
	}

	wafiplist.EvictIPListCache(tpPath)
	prefixes, err := wafiplist.LoadPrefixesFresh(tpPath)
	if err != nil {
		t.Fatalf("装载受信代理投影: %v", err)
	}
	got := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		got[prefix] = struct{}{}
	}
	for _, want := range []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("203.0.113.0/24")} {
		if _, ok := got[want]; !ok {
			t.Fatalf("装载结果缺 %s（精确匹配语义丢失）: %v", want, prefixes)
		}
	}
}

// 集群快照携带 refs（主端装载恒携带）+ 从端 apply 落库。
func TestLoadSnapshotGlobalSettings_carriesTrustedProxyRangeRefs(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_range_refs='[7,9]' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	var snapshot models.ClusterSnapshot
	if err := service.loadSnapshotGlobalSettings(context.Background(), database, &snapshot); err != nil {
		t.Fatalf("load snapshot settings: %v", err)
	}
	if snapshot.BasicSettings.TrustedProxyRangeRefs == nil || *snapshot.BasicSettings.TrustedProxyRangeRefs != "[7,9]" {
		t.Fatalf("trusted_proxy_range_refs=%v, want [7,9]", snapshot.BasicSettings.TrustedProxyRangeRefs)
	}
	wire, err := json.Marshal(snapshot.BasicSettings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"trusted_proxy_range_refs":"[7,9]"`) {
		t.Fatalf("wire basic_settings=%s, must carry trusted_proxy_range_refs", wire)
	}
}

func TestUpdateSnapshotSettings_trustedProxyRangeRefsApplied(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	caddyConfig := "{}"

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{
		CaddyConfig: &caddyConfig,
		BasicSettings: models.ClusterBasicSettings{
			JWTExpireMinutes:      new(20),
			TrustedProxyRangeRefs: new("[11]"),
		},
	}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := database.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "[11]" {
		t.Fatalf("applied trusted_proxy_range_refs=%q, want [11]", got)
	}
}
