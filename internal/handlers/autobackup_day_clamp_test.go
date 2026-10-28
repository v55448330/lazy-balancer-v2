package handlers

// AutoBackupSettings 读侧钳制不对称——keep 有越界回退
// （1-30 外回退 7），day 却原样返回。越界存量 day（如 weekly=15 / monthly=40）
// 会直接渲染到 UI 的日期下拉，展示层与调度消费端（weekly 1-7、monthly 1-28、
// daily 忽略）判据分叉。修复=读侧按 frequency 钳制，越界回退 1（DB 默认），
// 与 keep 回退同格；合法值原样返回（回归形状）。

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestAutoBackupSettings_clampsDayByFrequency(t *testing.T) {
	cases := []struct {
		name string
		freq string
		day  int
		want int
	}{
		{"weekly above max falls back", "weekly", 15, 1},
		{"weekly below min falls back", "weekly", 0, 1},
		{"weekly in range kept", "weekly", 6, 6},
		{"weekly at max kept", "weekly", 7, 7},
		{"monthly above max falls back", "monthly", 40, 1},
		{"monthly at max kept", "monthly", 28, 28},
		{"daily above max falls back", "daily", 90, 1},
		{"daily in range kept", "daily", 3, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAutoBackupTestHandlers(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency=?, auto_backup_time='03:00', auto_backup_day=?, auto_backup_keep=7 WHERE id=1`, tc.freq, tc.day); err != nil {
				t.Fatalf("seed settings: %v", err)
			}
			response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var payload struct {
				Data struct {
					Day int `json:"day"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.Data.Day != tc.want {
				t.Fatalf("freq=%s day=%d → 返回 day=%d, want %d", tc.freq, tc.day, payload.Data.Day, tc.want)
			}
		})
	}
}

func TestAutoBackupSettings_clampsKeepOnRead(t *testing.T) {
	for _, tc := range []struct{ stored, want int }{{0, 7}, {31, 7}, {1, 1}, {30, 30}, {12, 12}} {
		h := newAutoBackupTestHandlers(t)
		if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_keep=? WHERE id=1`, tc.stored); err != nil {
			t.Fatal(err)
		}
		response := serveAutoBackupJSON(t, h, http.MethodGet, "/settings/auto-backup", "/settings/auto-backup", "", h.AutoBackupSettings)
		if response.Code != http.StatusOK {
			t.Fatalf("stored=%d status=%d body=%s", tc.stored, response.Code, response.Body.String())
		}
		var payload struct {
			Data struct {
				Keep int `json:"keep"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Data.Keep != tc.want {
			t.Fatalf("stored keep=%d → response=%d, want %d", tc.stored, payload.Data.Keep, tc.want)
		}
	}
}
