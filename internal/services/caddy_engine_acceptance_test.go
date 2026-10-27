package services

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func caddyBinaryForAcceptance(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Skipf("真实 Caddy 引擎不可用：PATH 中未找到 caddy（需要项目定制二进制的 layer4/map 等模块）: %v", err)
	}
	output, err := exec.CommandContext(t.Context(), binary, "version").CombinedOutput()
	if err != nil {
		t.Skipf("真实 Caddy 引擎不可用：caddy version 执行失败: %v\n%s", err, output)
	}
	t.Logf("Caddy engine: %s (%s)", strings.TrimSpace(string(output)), binary)
	return binary
}

func generatedCaddyJSONForAcceptance(t *testing.T) []byte {
	t.Helper()
	generated := GenerateCaddyConfig()
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("GenerateCaddyConfig failed: %s", message)
	}
	rendered, err := json.Marshal(caddyPayload(generated))
	if err != nil {
		t.Fatalf("marshal complete Caddy JSON: %v", err)
	}
	return rendered
}

func validateCaddyJSONForAcceptance(t *testing.T, binary string, rendered []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "generated.json")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatalf("write generated Caddy JSON: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), binary, "validate", "--adapter", "json", "--config", path)
	output, err := cmd.CombinedOutput()
	t.Logf("caddy validate --adapter json --config %s\n%s", path, strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatalf("real Caddy engine rejected generated JSON: %v", err)
	}
}

func TestGenerateCaddyConfig_realEngineAcceptance(t *testing.T) {
	binary := caddyBinaryForAcceptance(t)
	strategies := []string{"weighted_round_robin", "least_conn", "ip_hash", "random", "first", "cookie"}
	for _, strategy := range strategies {
		t.Run("strategy/"+strategy, func(t *testing.T) {
			_, database := newClusterTestService(t)
			if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,health_check_interval,enabled)
				VALUES ('lb_engine_strategy','engine strategy','http','strategy.example.test',18080,?,'',10,1)`, strategy); err != nil {
				t.Fatalf("seed HTTP rule: %v", err)
			}
			if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol,weight) VALUES
				('lb_engine_strategy','127.0.0.1',19000,1,'http',3),
				('lb_engine_strategy','127.0.0.1',19001,1,'http',1)`); err != nil {
				t.Fatalf("seed HTTP upstreams: %v", err)
			}

			rendered := generatedCaddyJSONForAcceptance(t)
			if marker := []byte(`"policy":"` + strategy + `"`); !bytes.Contains(rendered, marker) {
				t.Fatalf("generated JSON lacks strategy marker %s", marker)
			}
			validateCaddyJSONForAcceptance(t, binary, rendered)
		})
	}

	t.Run("handlers_and_tcp", func(t *testing.T) {
		_, database := newClusterTestService(t)
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,custom_routes_enabled)
			VALUES ('lb_engine_http','engine HTTP','http','features.example.test',18081,'weighted_round_robin',1,1)`); err != nil {
			t.Fatalf("seed feature HTTP rule: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol,origin_domain) VALUES
			('lb_engine_http','127.0.0.1',19443,1,'https','origin-a.example.test'),
			('lb_engine_http','127.0.0.2',19443,1,'https','')`); err != nil {
			t.Fatalf("seed origin upstreams: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,response_mode,response_status,response_body,response_content_type,redirect_to) VALUES
			('lb_engine_http',10,'prefix','/api','/v1','',0,'','',''),
			('lb_engine_http',20,'exact','/old','/new','',0,'','',''),
			('lb_engine_http',30,'prefix','/health','','static',201,'pong','text/plain',''),
			('lb_engine_http',40,'exact','/legacy','','redirect',0,'','','https://example.test/landing')`); err != nil {
			t.Fatalf("seed response and rewrite paths: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,strategy,enabled)
			VALUES ('lb_engine_tcp','engine TCP','tcp',19090,'weighted_round_robin',1)`); err != nil {
			t.Fatalf("seed TCP rule: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES
			('lb_engine_tcp','127.0.0.1',19091,1,'tcp')`); err != nil {
			t.Fatalf("seed TCP upstream: %v", err)
		}

		rendered := generatedCaddyJSONForAcceptance(t)
		markers := [][]byte{
			[]byte(`"handler":"map"`),
			[]byte(`"origin-a.example.test"`),
			[]byte(`"strip_path_prefix":"/api"`),
			[]byte(`"uri":"/v1{http.request.uri}"`),
			[]byte(`"uri":"/new"`),
			[]byte(`"body":"pong"`),
			[]byte(`"status_code":301`),
			[]byte(`"Location":["https://example.test/landing"]`),
			[]byte(`"layer4"`),
		}
		for _, marker := range markers {
			if !bytes.Contains(rendered, marker) {
				t.Errorf("generated JSON lacks feature marker %s", marker)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
		validateCaddyJSONForAcceptance(t, binary, rendered)
	})
}
