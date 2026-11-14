package services

// path_rules 渲染读投影单源钉：渲染 SELECT 经 db.PathRuleSelectColumns 派生
// （12 列含 id/rule_id），全列往返渲染不丢值——手写列清单分叉（缺列/错序）
// 会在此当场失败。

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateCaddyConfig_pathRuleColumnsRoundTrip(t *testing.T) {
	// Given：启用自定义路由的规则 + 一条全列非零的路径规则（redirect 形态：
	// redirect_to/status 入载荷；上游 JSON 非 NULL 走解码分支）。
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,custom_routes_enabled)
		VALUES ('lb_prcols','prcols','http','prcols.example.test',18091,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_prcols','10.7.7.7',18091,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules
		(rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to)
		VALUES ('lb_prcols',7,'exact','/maint','/v2','[{"address":"10.8.8.8","port":9090,"weight":2,"enabled":true}]','redirect',301,'维护中','text/plain; charset=utf-8','https://elsewhere.example.test/')`); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then：渲染成功且路径规则列值进入载荷。
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("path rule render failed: %s", message)
	}
	data, err := json.Marshal(caddyPayload(generated))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload := string(data)
	for _, want := range []string{"/maint", "https://elsewhere.example.test/", "301"} {
		if !strings.Contains(payload, want) {
			t.Fatalf("渲染载荷缺少路径规则列值 %q（列清单分叉/错序）", want)
		}
	}
}
