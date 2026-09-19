package handlers

// SYS37-2(第 37 轮审计,P3):v2 备份导入钳制缺口——caddy_log_size_mb
// (写侧 ≥100,caddy.go:305-308)与 audit_log_size_mb(写侧 ≤512,:380-387)
// 无导入侧钳制(R56#3/R57 C-2/R58 C-N2 同族漏网):越界值原样落库后,
// 基础设置保存被写侧校验锁死(400),直至人工修库或重启钳位(若有)。

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestImportConfigBackup_clamps_caddy_log_size_mb(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int
	}{
		{"10 钳位到 100(写侧下限)", 10, 100},
		{"0 钳位到 100", 0, 100},
		{"负值钳位到 100", -50, 100},
		{"合法值保持不变", 200, 200},
		{"边界 100 保持不变", 100, 100},
		{"边界 10240 保持不变", 10240, 10240},
		{"10241 钳位到 10240（SYS41-7 上限）", 10241, 10240},
		{"天文值钳位到 10240", 99999999, 10240},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			r55SeedCurrentAdmin(t)
			backup := r55BackupJSONWithConfig(t, map[string][]map[string]any{}, map[string]any{"caddy_log_size_mb": tt.value})
			response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow("SELECT COALESCE(caddy_log_size_mb,100) FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatalf("read caddy_log_size_mb: %v", err)
			}
			if stored != tt.want {
				t.Fatalf("caddy_log_size_mb=%d, want %d", stored, tt.want)
			}
		})
	}
}

func TestImportConfigBackup_clamps_audit_log_size_mb(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int
	}{
		{"9999 钳位到 512(写侧上限)", 9999, 512},
		{"513 钳位到 512", 513, 512},
		{"0 钳位到 1", 0, 1},
		{"负值钳位到 1", -5, 1},
		{"合法值保持不变", 256, 256},
		{"边界 512 保持不变", 512, 512},
		{"边界 1 保持不变", 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			r55SeedCurrentAdmin(t)
			backup := r55BackupJSONWithConfig(t, map[string][]map[string]any{}, map[string]any{"audit_log_size_mb": tt.value})
			response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow("SELECT COALESCE(audit_log_size_mb,10) FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatalf("read audit_log_size_mb: %v", err)
			}
			if stored != tt.want {
				t.Fatalf("audit_log_size_mb=%d, want %d", stored, tt.want)
			}
		})
	}
}
