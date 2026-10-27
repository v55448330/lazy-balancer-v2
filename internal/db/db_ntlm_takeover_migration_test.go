package db

// NTLM 接管一致性 存量归一钉测：启动迁移把「ntlm_compatible=1 但接管四列
// 不齐」的行归一 ntlm_compatible=0——该列渲染零消费（纯展示修正，使面板显示
// 与运行行为一致），四列运行值原样保留；四列全齐的合法接管行与 ntlm=0 行
// 零触碰；迁移幂等（二次启动零漂移）。

import (
	"testing"
)

func TestInitialize_normalizesInconsistentNtlmTakeoverRows(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	// Given：三种形态各一条——不一致（ntlm=1 四列不齐）/一致（UI 联动形态）/ntlm=0
	if _, err := DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,
		ntlm_compatible,tcp_try_duration,upstream_force_http1,proxy_flush_interval,upstream_keepalive_timeout) VALUES
		('lb_ntlmhalf','half','http','half.example.test',18630,'cookie',1, 1,0,0,0,0),
		('lb_ntlmfull','full','http','full.example.test',18631,'cookie',1, 1,-1,1,-1,300),
		('lb_ntlmoff','off','http','off.example.test',18632,'weighted_round_robin',1, 0,5000,0,100,60)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	readRow := func(caddyID string) (ntlm, td, forceHTTP1, flush, keepalive int) {
		t.Helper()
		if err := DB.QueryRow(`SELECT COALESCE(ntlm_compatible,0), COALESCE(tcp_try_duration,0),
			COALESCE(upstream_force_http1,0), COALESCE(proxy_flush_interval,0), COALESCE(upstream_keepalive_timeout,0)
			FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&ntlm, &td, &forceHTTP1, &flush, &keepalive); err != nil {
			t.Fatalf("read %s: %v", caddyID, err)
		}
		return
	}
	restart := func() {
		t.Helper()
		if err := Close(); err != nil {
			t.Fatalf("close before restart: %v", err)
		}
		if err := Initialize(dir); err != nil {
			t.Fatalf("reinitialize: %v", err)
		}
	}

	// When：服务重启（启动迁移执行）
	restart()

	// Then：不一致行归一 ntlm=0，四列运行值原样保留（纯展示修正）
	if ntlm, td, forceHTTP1, flush, keepalive := readRow("lb_ntlmhalf"); ntlm != 0 || td != 0 || forceHTTP1 != 0 || flush != 0 || keepalive != 0 {
		t.Fatalf("inconsistent row=(%d,%d,%d,%d,%d), want ntlm=0 且四列原样 (0,0,0,0)", ntlm, td, forceHTTP1, flush, keepalive)
	}
	// 一致行（UI 联动形态）零触碰
	if ntlm, td, forceHTTP1, flush, keepalive := readRow("lb_ntlmfull"); ntlm != 1 || td != -1 || forceHTTP1 != 1 || flush != -1 || keepalive != 300 {
		t.Fatalf("consistent row=(%d,%d,%d,%d,%d), want untouched (1,-1,1,-1,300)", ntlm, td, forceHTTP1, flush, keepalive)
	}
	// ntlm=0 行零触碰
	if ntlm, td, _, _, _ := readRow("lb_ntlmoff"); ntlm != 0 || td != 5000 {
		t.Fatalf("ntlm=0 row changed: ntlm=%d td=%d, want 0/5000", ntlm, td)
	}

	// 幂等：二次重启零漂移
	restart()
	if ntlm, td, forceHTTP1, flush, keepalive := readRow("lb_ntlmfull"); ntlm != 1 || td != -1 || forceHTTP1 != 1 || flush != -1 || keepalive != 300 {
		t.Fatalf("second restart drifted consistent row=(%d,%d,%d,%d,%d)", ntlm, td, forceHTTP1, flush, keepalive)
	}
	if ntlm, _, _, _, _ := readRow("lb_ntlmhalf"); ntlm != 0 {
		t.Fatalf("second restart flipped normalized row back: ntlm=%d", ntlm)
	}
}
