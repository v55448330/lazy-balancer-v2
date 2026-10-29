package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

type securityBindingSyncShape struct {
	ruleCaddyID string
	policyID    int
}

func TestSyncService_SecuritySectionConvergesAcrossBindingShapes(t *testing.T) {
	localBinding := securityBindingSyncShape{ruleCaddyID: "lb_local_waf", policyID: 5}
	masterOnlyBinding := securityBindingSyncShape{ruleCaddyID: "lb_master_only", policyID: 5}
	cases := []struct {
		name           string
		rulesSync      bool
		localBindings  []securityBindingSyncShape
		masterBindings []securityBindingSyncShape
	}{
		{name: "rules_enabled_master_set", rulesSync: true, localBindings: []securityBindingSyncShape{localBinding}, masterBindings: []securityBindingSyncShape{localBinding, masterOnlyBinding}},
		{name: "rules_disabled_empty_bindings", rulesSync: false},
		{name: "rules_disabled_local_only_binding", rulesSync: false, localBindings: []securityBindingSyncShape{localBinding}},
		{name: "rules_disabled_master_set", rulesSync: false, localBindings: []securityBindingSyncShape{localBinding}, masterBindings: []securityBindingSyncShape{localBinding, masterOnlyBinding}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given a slave with its own rule and policy, plus the case's local bindings.
			ctx := context.Background()
			service, database := newClusterTestService(t)
			rulesSync := 0
			if tc.rulesSync {
				rulesSync = 1
			}
			if _, err := database.Exec(`UPDATE global_config SET is_master=0, sync_rules=?, sync_security=1 WHERE id=1`, rulesSync); err != nil {
				t.Fatalf("set slave switches: %v", err)
			}
			if _, err := database.Exec(`
				INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
					VALUES ('lb_local_waf','local','http','local.test',18081,1,0,'none');
				INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
					VALUES ('lb_local_waf','127.0.0.1',18082,1,1,'http');
				INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'shared','blocking',1);
			`); err != nil {
				t.Fatalf("seed local rule and policy: %v", err)
			}
			for _, binding := range tc.localBindings {
				if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, binding.ruleCaddyID, binding.policyID); err != nil {
					t.Fatalf("seed local binding: %v", err)
				}
			}

			master, err := service.clusterSnapshotBypassingCache(ctx)
			if err != nil {
				t.Fatalf("build master snapshot: %v", err)
			}
			master.Version++
			master.MasterSyncSwitches = &models.ClusterSyncSwitchesPayload{Users: true, Rules: tc.rulesSync, Security: true}
			bindings := make([]map[string]interface{}, 0, len(tc.masterBindings))
			for _, binding := range tc.masterBindings {
				bindings = append(bindings, map[string]interface{}{"rule_caddy_id": binding.ruleCaddyID, "policy_id": binding.policyID})
			}
			master.SecurityBindings, err = json.Marshal(bindings)
			if err != nil {
				t.Fatalf("encode master bindings: %v", err)
			}
			master.SectionHashes = ComputeSnapshotSectionHashes(&master)

			var loads int32
			caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/load" {
					atomic.AddInt32(&loads, 1)
				}
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(caddyServer.Close)
			syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
			t.Cleanup(func() { unregisterSyncDrainer(syncService) })

			// When the snapshot is applied, then seen again in steady state and after an unrelated version bump.
			if err := syncService.applySnapshot(ctx, master); err != nil {
				t.Fatalf("apply initial snapshot: %v", err)
			}
			initialLoads := atomic.LoadInt32(&loads)
			var bindingCount int
			if err := database.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings`).Scan(&bindingCount); err != nil {
				t.Fatalf("count applied bindings: %v", err)
			}
			wantBindings := len(tc.localBindings)
			if tc.rulesSync {
				wantBindings = len(tc.masterBindings)
			}
			if bindingCount != wantBindings {
				t.Fatalf("applied binding count=%d, want %d", bindingCount, wantBindings)
			}

			if drifted := syncService.driftedSections(ctx); drifted != "" {
				t.Errorf("steady-state drifted sections=%q, want none", drifted)
			}
			if err := syncService.applySnapshot(ctx, master); err != nil {
				t.Fatalf("apply repeated snapshot: %v", err)
			}
			if got := atomic.LoadInt32(&loads); got != initialLoads {
				t.Errorf("repeated snapshot caddy /load count=%d, want %d", got, initialLoads)
			}
			localHashes, err := service.driftGuardSectionHashes(ctx)
			if err != nil {
				t.Fatalf("rebuild local hashes: %v", err)
			}
			switches, err := readSyncSwitches(ctx, database)
			if err != nil {
				t.Fatalf("read sync switches: %v", err)
			}
			if skips := computeSectionSkips(ctx, database, master, switches, localHashes); !skips.skip("security") {
				t.Error("unchanged security section must be skipped after convergence")
			}

			laterBump := master
			laterBump.Version++
			if err := syncService.applySnapshot(ctx, laterBump); err != nil {
				t.Fatalf("apply unrelated version bump: %v", err)
			}
			// Then binding differences outside the applied data must not cause another replay or reload.
			if got := atomic.LoadInt32(&loads); got != initialLoads {
				t.Errorf("unrelated version bump caddy /load count=%d, want %d", got, initialLoads)
			}
			if drifted := syncService.driftedSections(ctx); drifted != "" {
				t.Errorf("post-bump drifted sections=%q, want none", drifted)
			}
		})
	}
}
