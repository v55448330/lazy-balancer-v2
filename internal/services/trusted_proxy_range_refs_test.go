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
