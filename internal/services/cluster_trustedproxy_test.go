package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 受信代理四设置（v2.3.x CDN 真实 IP）随集群快照同步：主端装载恒携带、
// 从端 apply 落库（与 Caddy 全局轴同批——仅在快照携带 caddy_config 时写入）。
func TestLoadSnapshotGlobalSettings_carriesTrustedProxySettings(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24"]', trusted_proxy_headers='["CF-Connecting-IP","X-Forwarded-For"]', trusted_proxy_strict=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	var snapshot models.ClusterSnapshot
	if err := service.loadSnapshotGlobalSettings(context.Background(), database, &snapshot); err != nil {
		t.Fatalf("load snapshot settings: %v", err)
	}
	s := snapshot.BasicSettings
	if !s.TrustedProxyEnabled || s.TrustedProxyRanges != `["203.0.113.0/24"]` ||
		s.TrustedProxyHeaders != `["CF-Connecting-IP","X-Forwarded-For"]` || s.TrustedProxyStrict {
		t.Fatalf("trusted proxy settings=%+v, want DB values", s)
	}
	wire, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"trusted_proxy_enabled":true`, `"trusted_proxy_ranges":"[\"203.0.113.0/24\"]"`, `"trusted_proxy_headers"`, `"trusted_proxy_strict"`} {
		if want == `"trusted_proxy_strict"` {
			// strict=false 时 omitempty 省略键——只验证 true 形态携带。
			continue
		}
		if !strings.Contains(string(wire), want) {
			t.Fatalf("wire basic_settings=%s, must contain %s", wire, want)
		}
	}
}

func TestUpdateSnapshotSettings_trustedProxySettingsApplied(t *testing.T) {
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
			JWTExpireMinutes:    20,
			TrustedProxyEnabled: true,
			TrustedProxyRanges:  `["198.51.100.0/24"]`,
			TrustedProxyHeaders: `["X-Forwarded-For"]`,
			TrustedProxyStrict:  true,
		},
	}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var gotEnabled, gotStrict bool
	var gotRanges, gotHeaders string
	if err := database.QueryRow(`SELECT COALESCE(trusted_proxy_enabled,0), COALESCE(trusted_proxy_ranges,'[]'), COALESCE(trusted_proxy_headers,'[]'), COALESCE(trusted_proxy_strict,1) FROM global_config WHERE id=1`).
		Scan(&gotEnabled, &gotRanges, &gotHeaders, &gotStrict); err != nil {
		t.Fatal(err)
	}
	if !gotEnabled || !gotStrict || gotRanges != `["198.51.100.0/24"]` || gotHeaders != `["X-Forwarded-For"]` {
		t.Fatalf("applied trusted proxy enabled=%v strict=%v ranges=%q headers=%q, want snapshot values",
			gotEnabled, gotStrict, gotRanges, gotHeaders)
	}
}
