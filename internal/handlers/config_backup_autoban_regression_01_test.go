package handlers

//   自动封禁六列：布尔两键入 validateV2BackupBooleanTypes 枚举（非布尔
//   形态整包 400 点名键）；threshold/window 数值钳制（写侧同边界 [1,10000]/
//   [1,60]，非整数形态归一缺省）；duration/scope 枚举校验（空串/null 归一
//   缺省、非空非法拒绝——镜像 security_policies mode 族口径），导入/预览双路径同序。
//   受信代理三 TEXT 列：复用保存侧 validateTrustedProxyFields 同一口径
//   （形态门+归一+引用存在性+总量上限），畸形值不得落库致渲染 fail-closed
//   而面板宣称已启用。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestImportConfigBackup_booleanTypeGate_autobanKeys(t *testing.T) {
	tests := []struct {
		name string
		cfg  map[string]any
		want string
	}{
		{"字符串形态 enabled 400 点名", map[string]any{"autoban_enabled": "1"}, "autoban_enabled 需为布尔值"},
		{"越界数值形态 dry_run 400 点名", map[string]any{"autoban_dry_run": 2}, "autoban_dry_run 需为布尔值"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, tt.cfg)
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("import status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tt.want) {
				t.Fatalf("body=%s, want contain %q", response.Body.String(), tt.want)
			}
		})
	}
}

func TestImportConfigBackup_clamps_autoban_threshold(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int
	}{
		{"0 钳位到 1（写侧下限）", 0, 1},
		{"负值钳位到 1", -50, 1},
		{"10001 钳位到 10000（写侧上限）", 10001, 10000},
		{"天文值钳位到 10000", 99999999, 10000},
		{"合法值保持不变", 42, 42},
		{"边界 1 保持不变", 1, 1},
		{"边界 10000 保持不变", 10000, 10000},
		{"非整数形态回退缺省 100", "garbage", 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"autoban_threshold": tt.value})
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow("SELECT COALESCE(autoban_threshold,0) FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatalf("read autoban_threshold: %v", err)
			}
			if stored != tt.want {
				t.Fatalf("autoban_threshold=%d, want %d", stored, tt.want)
			}
		})
	}
}

func TestImportConfigBackup_clamps_autoban_window_minutes(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int
	}{
		{"0 钳位到 1（写侧下限）", 0, 1},
		{"61 钳位到 60（写侧上限）", 61, 60},
		{"合法值保持不变", 13, 13},
		{"非整数形态回退缺省 5", "garbage", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"autoban_window_minutes": tt.value})
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow("SELECT COALESCE(autoban_window_minutes,0) FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatalf("read autoban_window_minutes: %v", err)
			}
			if stored != tt.want {
				t.Fatalf("autoban_window_minutes=%d, want %d", stored, tt.want)
			}
		})
	}
}

// duration/scope 枚举门：空串/null 归一缺省（'1h'/'all'，镜像 mode 族「无值
// 归一」）；非空非法与非字符串形态拒绝（导入不宽于保存侧）。
func TestImportConfigBackup_autobanEnumGate(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   any
		wantErr string
	}{
		{"duration 非法枚举拒绝", "autoban_duration", "bogus", "autoban_duration"},
		{"duration 非字符串拒绝", "autoban_duration", 123, "autoban_duration"},
		{"scope 非法枚举拒绝", "autoban_scope", "bogus", "autoban_scope"},
		{"scope 非字符串拒绝", "autoban_scope", true, "autoban_scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{tt.key: tt.value})
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("import status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tt.wantErr) {
				t.Fatalf("body=%s, want contain %q", response.Body.String(), tt.wantErr)
			}
		})
	}

	// 归一形状：空串/null 归一缺省，合法值保持
	for _, tt := range []struct {
		name  string
		cfg   map[string]any
		check func(t *testing.T)
	}{
		{"duration 空串归一 1h", map[string]any{"autoban_duration": ""}, func(t *testing.T) {
			assertImportedAutobanText(t, "autoban_duration", "1h")
		}},
		{"duration 合法保持 24h", map[string]any{"autoban_duration": "24h"}, func(t *testing.T) {
			assertImportedAutobanText(t, "autoban_duration", "24h")
		}},
		{"scope 空串归一默认全选", map[string]any{"autoban_scope": ""}, func(t *testing.T) {
			assertImportedAutobanText(t, "autoban_scope", "blocked,logged,challenge_issued,challenge_failed")
		}},
		{"scope 合法保持 logged", map[string]any{"autoban_scope": "logged"}, func(t *testing.T) {
			assertImportedAutobanText(t, "autoban_scope", "logged")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, tt.cfg)
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			tt.check(t)
		})
	}
}

func assertImportedAutobanText(t *testing.T, column, want string) {
	t.Helper()
	var got string
	if err := db.DB.QueryRow("SELECT COALESCE(" + column + ",'') FROM global_config WHERE id=1").Scan(&got); err != nil {
		t.Fatalf("read %s: %v", column, err)
	}
	if got != want {
		t.Fatalf("%s=%q, want %q", column, got, want)
	}
}

// 受信代理三 TEXT 列导入门——畸形形态/畸形 JSON/悬空引用/非法条目/总量
// 超限整包 400；合法载荷按保存侧同口径归一落库。
func TestImportConfigBackup_trustedProxyTextColumnsGate(t *testing.T) {
	t.Run("ranges 非字符串类型拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"trusted_proxy_ranges": 123})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "trusted_proxy_ranges") {
			t.Fatalf("status=%d body=%s, want 400 naming trusted_proxy_ranges", response.Code, response.Body.String())
		}
	})
	t.Run("ranges 畸形 JSON 拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"trusted_proxy_ranges": "not-json"})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "JSON 数组") {
			t.Fatalf("status=%d body=%s, want 400 JSON 数组", response.Code, response.Body.String())
		}
	})
	t.Run("headers 非法字符拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"trusted_proxy_headers": `["bad header!"]`})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
		}
	})
	t.Run("refs 悬空引用拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"trusted_proxy_range_refs": "[424242]"})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不存在") {
			t.Fatalf("status=%d body=%s, want 400 不存在", response.Code, response.Body.String())
		}
	})
	t.Run("内联+引用展开超总量拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		entries := make([]string, 0, 2000)
		for i := range 2000 {
			entries = append(entries, fmt.Sprintf(`{"value":"198.51.%d.%d"}`, i/254, i%254+1))
		}
		// 名单表随备份全量替换，refs 存在性仅按备份行解析——被引用的 2000 条
		// 名单须随备份行到场（自洽备份），总量门判定面=备份行展开。
		backup := configBackupJSON(t, map[string][]map[string]any{
			"security_ip_lists": {{"id": 5, "name": "huge-list", "entries": "[" + strings.Join(entries, ",") + "]"}},
		}, map[string]any{
			"trusted_proxy_ranges":     `["203.0.113.0/24"]`,
			"trusted_proxy_range_refs": "[5]",
		})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "2000") {
			t.Fatalf("status=%d body=%s, want 400 with 2000 上限", response.Code, response.Body.String())
		}
	})
	t.Run("refs 引用仅存在于备份内的名单（跨节点还原形态）导入成功", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		// live 库无名单 99——名单随备份 security_ip_lists 表到达（「备份内优先」
		// 解析；此前若只查库会把合法跨节点还原误拒为「不存在」）
		backup := configBackupJSON(t, map[string][]map[string]any{
			"security_ip_lists": {{"id": 99, "name": "cross-node-cdn", "entries": `[{"value":"203.0.113.0/24","remark":""}]`}},
		}, map[string]any{"trusted_proxy_range_refs": "[99]"})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s, want 200（备份内名单须可解析）", response.Code, response.Body.String())
		}
		var refs string
		if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&refs); err != nil {
			t.Fatal(err)
		}
		if refs != "[99]" {
			t.Fatalf("refs=%s, want [99]", refs)
		}
	})
	t.Run("合法载荷归一落库", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedCurrentAdminShared(t)
		backup := configBackupJSON(t, map[string][]map[string]any{
			"security_ip_lists": {{"id": 5, "name": "ref-list", "entries": `[{"value":"198.51.100.0/24","remark":""}]`}},
		}, map[string]any{
			"trusted_proxy_enabled":    true,
			"trusted_proxy_ranges":     `["198.51.100.7"]`,
			"trusted_proxy_range_refs": "[5]",
			"trusted_proxy_headers":    `["CF-Connecting-IP","X-Forwarded-For","CF-Connecting-IP"]`,
		})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		var ranges, refs, headers string
		if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_ranges,''), COALESCE(trusted_proxy_range_refs,''), COALESCE(trusted_proxy_headers,'')
			FROM global_config WHERE id=1`).Scan(&ranges, &refs, &headers); err != nil {
			t.Fatal(err)
		}
		if ranges != `["198.51.100.7/32"]` {
			t.Fatalf("ranges=%s, want bare IP normalized to /32", ranges)
		}
		if refs != "[5]" {
			t.Fatalf("refs=%s, want [5]", refs)
		}
		if headers != `["CF-Connecting-IP","X-Forwarded-For"]` {
			t.Fatalf("headers=%s, want dedup preserve order", headers)
		}
	})
}

// 预览同序：畸形 autoban/受信代理载荷在预览端点同样报不可导入（不得预览
// 通过、导入才 400）。
func TestValidateConfigImport_autobanAndTrustedProxyGatesPreview(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  map[string]any
		want string
	}{
		{"duration 非法枚举", map[string]any{"autoban_duration": "bogus"}, "autoban_duration"},
		{"duration 非字符串形态", map[string]any{"autoban_duration": 123}, "autoban_duration"},
		{"scope 非法枚举", map[string]any{"autoban_scope": "bogus"}, "autoban_scope"},
		{"受信代理悬空引用", map[string]any{"trusted_proxy_range_refs": "[424242]"}, "不存在"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, tt.cfg)
			response := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", backup)
			if response.Code != http.StatusOK {
				t.Fatalf("validate status=%d body=%s, want 200 envelope", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"valid":false`) {
				t.Fatalf("body=%s, want valid=false", response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tt.want) {
				t.Fatalf("body=%s, want contain %q", response.Body.String(), tt.want)
			}
		})
	}
}

// 预览必须呈现链内自动封禁钳制事实：预览显示 valid 且无提示、导入后实际
// 生效值已被归一，是「预览与提交不同源」的可解释性缺口。
func TestValidateConfigImport_previewSurfacesAutobanClampNotes(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedCurrentAdminShared(t)
	backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{
		"autoban_threshold":      999999,
		"autoban_window_minutes": 0,
	})
	response := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", backup)
	if response.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"valid":true`) {
		t.Fatalf("钳制不阻断导入: body=%s", body)
	}
	if !strings.Contains(body, "autoban_threshold 越界") || !strings.Contains(body, "autoban_window_minutes 越界") {
		t.Fatalf("预览 warnings 缺少钳制事实: body=%s", body)
	}
}
