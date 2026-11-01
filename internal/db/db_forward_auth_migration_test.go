package db

// 认证网关（forward_auth）存量归一钉测：启动迁移把「enabled=1 但 upstream
// 缺失（无法构造网关子请求，渲染必败）」与「TCP 行残留 enabled=1（HTTP 专属
// 特性）」的带外行归一 enabled=0；uri/copy_headers 空值回填确定默认（渲染
// 四件套齐备，canonical 稳定）；upstream 齐备的合法行与 enabled=0 行零触碰；
// 迁移幂等（二次启动零漂移）。

import (
	"testing"
)

func TestInitialize_normalizesForwardAuthRows(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	// Given：四种形态各一条——enabled=1 无 upstream（归零对象）/enabled=1
	// upstream 齐备（零触碰）/TCP 行 enabled=1（归零对象）/enabled=0 空 uri
	// （仅回填默认，开关不动）。
	if _, err := DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,
		forward_auth_enabled,forward_auth_upstream,forward_auth_uri,forward_auth_copy_headers) VALUES
		('lb_faghost','ghost','http','ghost.example.test',18640,'weighted_round_robin',1, 1,'','',''),
		('lb_faok','ok','http','ok.example.test',18641,'weighted_round_robin',1, 1,'http://gw.internal:7000','/api/verify','Remote-User'),
		('lb_fatcp','tcprow','tcp','',18700,'weighted_round_robin',1, 1,'http://gw.internal:7000','',''),
		('lb_faoff','off','http','off.example.test',18642,'weighted_round_robin',1, 0,'','','')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	readRow := func(caddyID string) (enabled int, upstream, uri, headers string) {
		t.Helper()
		if err := DB.QueryRow(`SELECT COALESCE(forward_auth_enabled,0), COALESCE(forward_auth_upstream,''),
			COALESCE(forward_auth_uri,''), COALESCE(forward_auth_copy_headers,'')
			FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&enabled, &upstream, &uri, &headers); err != nil {
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

	// Then：enabled=1 无 upstream → 归零；uri/copy_headers 已随全表回填获得
	// 确定默认（canonical 稳定：全部行四件套形态一致）
	if enabled, upstream, uri, headers := readRow("lb_faghost"); enabled != 0 || upstream != "" ||
		uri != DefaultForwardAuthURI || headers != DefaultForwardAuthCopyHeaders {
		t.Fatalf("ghost row=(%d,%q,%q,%q), want (0,'',%q,%q)", enabled, upstream, uri, headers, DefaultForwardAuthURI, DefaultForwardAuthCopyHeaders)
	}
	// upstream 齐备的合法行零触碰（含自定义 uri/headers）
	if enabled, upstream, uri, headers := readRow("lb_faok"); enabled != 1 || upstream != "http://gw.internal:7000" || uri != "/api/verify" || headers != "Remote-User" {
		t.Fatalf("ok row=(%d,%q,%q,%q), want untouched", enabled, upstream, uri, headers)
	}
	// TCP 行 enabled=1 → 归零（HTTP 专属特性）
	if enabled, _, _, _ := readRow("lb_fatcp"); enabled != 0 {
		t.Fatalf("tcp row forward_auth_enabled=%d, want 0", enabled)
	}
	// enabled=0 行开关不动，空 uri/copy_headers 回填确定默认（canonical 稳定）
	if enabled, upstream, uri, headers := readRow("lb_faoff"); enabled != 0 || upstream != "" ||
		uri != DefaultForwardAuthURI || headers != DefaultForwardAuthCopyHeaders {
		t.Fatalf("off row=(%d,%q,%q,%q), want (0,'',%q,%q)", enabled, upstream, uri, headers, DefaultForwardAuthURI, DefaultForwardAuthCopyHeaders)
	}

	// 幂等：二次重启零漂移
	restart()
	if enabled, _, uri, headers := readRow("lb_faghost"); enabled != 0 || uri != DefaultForwardAuthURI || headers != DefaultForwardAuthCopyHeaders {
		t.Fatalf("second restart drifted ghost row=(%d,%q,%q)", enabled, uri, headers)
	}
	if enabled, _, uri, headers := readRow("lb_faoff"); enabled != 0 || uri != DefaultForwardAuthURI || headers != DefaultForwardAuthCopyHeaders {
		t.Fatalf("second restart drifted off row=(%d,%q,%q)", enabled, uri, headers)
	}
	if enabled, _, _, _ := readRow("lb_faok"); enabled != 1 {
		t.Fatalf("second restart flipped ok row: enabled=%d", enabled)
	}
}
