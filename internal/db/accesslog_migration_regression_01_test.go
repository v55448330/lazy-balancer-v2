package db

import (
	"strings"
	"testing"
)

// 既有的 rename 行同样被移除（渲染层虽强制 delete 覆盖，落库值仍应与所见一致）；
// 空格式保持为空（默认「不裁剪原生字段」形态，渲染层恒注入脱敏行）。
func TestRunMigrationsNormalizesAPIKeyAccessLogRedaction(t *testing.T) {
	cases := []struct {
		name    string
		stored  string
		want    string
		wantRaw bool
	}{
		{name: "empty stays empty", stored: "", want: "", wantRaw: true},
		{
			name:   "appends canonical line",
			stored: "request>remote_ip -> src",
			want:   "request>remote_ip -> src\nrequest>headers>X-Api-Key -> delete",
		},
		{
			name:   "replaces rename line",
			stored: "request>remote_ip -> src\nrequest>headers>X-API-Key -> apikey",
			want:   "request>remote_ip -> src\nrequest>headers>X-Api-Key -> delete",
		},
		{
			name:   "converges legacy literal spelling to canonical",
			stored: "request>remote_ip -> src\nrequest>headers>X-API-Key -> delete",
			want:   "request>remote_ip -> src\nrequest>headers>X-Api-Key -> delete",
		},
		{
			name:   "idempotent on canonical line",
			stored: "request>remote_ip -> src\nrequest>headers>X-Api-Key -> delete",
			want:   "request>remote_ip -> src\nrequest>headers>X-Api-Key -> delete",
		},
		{
			name:   "collapses mixed spellings to one line",
			stored: "request>headers>X-API-Key -> delete\nrequest>headers>X-Api-Key -> apikey",
			want:   "request>headers>X-Api-Key -> delete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := openMigrationTestDB(t)
			if err := createTables(); err != nil {
				t.Fatalf("create tables: %v", err)
			}
			if _, err := database.Exec("INSERT INTO global_config (id,caddy_config,access_log_format) VALUES (1,'{}',?)", tc.stored); err != nil {
				t.Fatalf("seed global config: %v", err)
			}
			if err := runMigrations(); err != nil {
				t.Fatalf("run migrations: %v", err)
			}
			var got string
			if err := database.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&got); err != nil {
				t.Fatalf("read format: %v", err)
			}
			if got != tc.want {
				t.Fatalf("format=%q, want %q", got, tc.want)
			}
			if tc.wantRaw {
				return
			}
			if strings.Count(got, "request>headers>") != 1 {
				t.Fatalf("脱敏行不唯一: %q", got)
			}
		})
	}
}
