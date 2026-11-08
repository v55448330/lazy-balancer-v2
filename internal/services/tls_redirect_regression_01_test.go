package services

// （旧代码只对 acme_dns 判证书就绪）——域名被 301 到无服务的 TLS 端口。
// 修复：跳转与 server 同判据（availableCerts 命中才发射），不分 tls_source。
// 可达性：保存/启用/导入侧均已拦截空证书（直改 DB/残留脏行才可达），下限。

import (
	"testing"
)

func Test_manualTLSRedirectRequiresReadyCert(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)

	// 目标形状：manual + tls_http_redirect + 空证书（脏行形态）。
	seedGenerationRule(t, database, "lb_mredir", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='mredir.example.test', enable_tls=1, tls_source='manual', tls_cert='', tls_key='', tls_http_redirect=1, listen_port=18445 WHERE caddy_id='lb_mredir'`); err != nil {
		t.Fatalf("seed manual TLS rule without cert: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	servers := l7HTTPServers(t, generated)

	if _, ok := servers["http_18445"]; ok {
		t.Fatalf("unready manual TLS rule must not publish a server: %#v", servers["http_18445"])
	}
	// 80 端口 301 跳转也不得发射（本修复点）。默认站恒渲染——缺失即形态
	// 异常，负断言不得被存在性检查静默跳过。
	if _, ok := servers["http_80"].(map[string]interface{}); !ok {
		t.Fatalf("默认站 http_80 必须存在（301 负断言前置）: %#v", servers)
	}
	if redirect := findRouteByID(t, httpRoutesFromServer(t, generated, "http_80"), "lb_mredir_redirect"); redirect != nil {
		t.Fatalf("证书未就绪的 manual TLS 规则不得发射 301 跳转: %#v", redirect)
	}

	// 回归形状：证书物化后 server 与跳转同时出现（同判据的另一面）。
	certPEM, keyPEM := matchingCertificatePair(t, "mredir.example.test")
	if _, err := database.Exec(`UPDATE lb_rules SET tls_cert=?, tls_key=? WHERE caddy_id='lb_mredir'`, certPEM, keyPEM); err != nil {
		t.Fatalf("materialize cert: %v", err)
	}
	generated = generateCaddyConfigFromStore(database)
	servers = l7HTTPServers(t, generated)
	if _, ok := servers["http_18445"]; !ok {
		t.Fatal("证书就绪后 server 必须发布")
	}
	if redirect := findRouteByID(t, httpRoutesFromServer(t, generated, "http_80"), "lb_mredir_redirect"); redirect == nil {
		t.Fatal("证书就绪后 301 跳转必须发射")
	}
}

// 同端口明文跳转（TLS 端口上 http→https）：规则监听什么端口，就在该端口
// 完成跳转——TLS server 挂 lb_https_redirect 监听包装器（首字节嗅探：明文
// 连接由包装器以 301 应答，TLS 连接透传），不再要求用户为同域名补 80 端口
// 规则。安全约束钉住：包装器配置必须携带该端口全部跳转域名集（Host 限定，
// 防反射开放重定向）；明文请求永不进入代理路由（包装器 terminal 应答，
// fail-closed 保持）。
func TestGenerateCaddyConfig_samePortTLSRedirectListenerWrapper(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "shop.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect,enabled) VALUES ('lb-sameredirect','sameport','http','shop.example.test',666,'weighted_round_robin',1,'manual',?,?,1,1)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb-sameredirect','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	config := GenerateCaddyConfig()
	if message, failed := config[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate: %s", message)
	}
	servers := config["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	sv, exists := servers["http_666"]
	if !exists {
		t.Fatalf("server http_666 missing（证书已就绪的 TLS 规则必须发布）: %v", servers)
	}
	server := sv.(map[string]interface{})

	// 形状①：TLS server 必须挂 proto 嗅探包装器（放最前=TLS 握手之前），
	// 且携带该端口跳转域名集与 https 目标端口。
	wrappers, ok := server["listener_wrappers"].([]interface{})
	if !ok || len(wrappers) != 2 {
		t.Fatalf("listener_wrappers=%v, want [lb_https_redirect, tls]", server["listener_wrappers"])
	}
	first := wrappers[0].(map[string]interface{})
	if first["wrapper"] != "lb_https_redirect" {
		t.Fatalf("首个包装器=%v, want lb_https_redirect（必须在 TLS 握手之前嗅探）", first)
	}
	if first["https_port"] != 666 {
		t.Fatalf("https_port=%v, want 666", first["https_port"])
	}
	domains := first["domains"].([]string)
	if len(domains) != 1 || domains[0] != "shop.example.test" {
		t.Fatalf("domains=%v, want [shop.example.test]（Host 限定=防反射开放重定向）", domains)
	}
	if wrappers[1].(map[string]interface{})["wrapper"] != "tls" {
		t.Fatalf("第二包装器=%v, want caddy.listeners.tls（TLS 位置占位）", wrappers[1])
	}

	// 形状②（回归）：纯 HTTP 规则端口不得挂包装器（无 https 目标）。
	plain := servers["http_80"]
	if plain == nil {
		t.Fatalf("server http_80 missing（跳转默认站必须在场）")
	}
	if _, has := plain.(map[string]interface{})["listener_wrappers"]; has {
		t.Fatal("纯 HTTP/跳转默认站不得挂 lb_https_redirect 包装器")
	}
}

// 形状③（fail-closed）：TLS 规则未开跳转时——包装器不挂载，明文打到该端口
// 维持既有姿态（Go 栈 400），不得顺手获得明文服务能力。
func TestGenerateCaddyConfig_tlsWithoutRedirectNoWrapper(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "noredirect.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect,enabled) VALUES ('lb-noredirect','noredirect','http','noredirect.example.test',667,'weighted_round_robin',1,'manual',?,?,0,1)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb-noredirect','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	config := GenerateCaddyConfig()
	if message, failed := config[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate: %s", message)
	}
	servers := config["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	sv, exists := servers["http_667"]
	if !exists {
		t.Fatal("server http_667 missing")
	}
	if _, has := sv.(map[string]interface{})["listener_wrappers"]; has {
		t.Fatal("未开跳转的 TLS 端口不得挂包装器（明文姿态必须与既有行为一致）")
	}
}

// 形状④（默认端口豁免，用户裁定）：443 默认端口维持既有 80→443 跳转通道
// （redirectRoutes on :80），同端口包装器只服务非标端口——明文 443 保持既有
// 姿态（Go 栈 400），80 跳转照常发射（Location 无端口后缀）。
func TestGenerateCaddyConfig_defaultPort443ExcludedFromSamePortWrapper(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "stdport.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect,enabled) VALUES ('lb-std443','std443','http','stdport.example.test',443,'weighted_round_robin',1,'manual',?,?,1,1)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb-std443','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	config := GenerateCaddyConfig()
	if message, failed := config[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate: %s", message)
	}
	servers := config["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	sv, exists := servers["http_443"]
	if !exists {
		t.Fatal("server http_443 missing")
	}
	if _, has := sv.(map[string]interface{})["listener_wrappers"]; has {
		t.Fatal("443 默认端口不得挂同端口包装器（80→443 通道已覆盖，明文保持 Go 栈 400 姿态）")
	}
	// 80 跳转通道仍在场：redirectRoutes 挂于 http_80（80→443，Location 无端口后缀）。
	if _, has80 := servers["http_80"]; !has80 {
		t.Fatal("server http_80 missing（80→443 跳转通道必须保留）")
	}
}

// 形状⑤（带外脏行 fail-soft 实证）：空域名 + TLS + 跳转的带外行（直改库/
// 旧备份，API 面已拒空域名）在渲染前置阶段即被跳过——本端口 server 整体
// 不发布，审计假设的「空 domains 包装器 Provision 冻结」经实证不可达
// （该形态下 len>0 守卫为纵深防御，正常路径不可达）。
func TestGenerateCaddyConfig_emptyDomainDirtyRuleFallsBack(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "dirty.example.test")
	// 带外形态：直改库写入空域名行（API 面已拒空域名，仅此通道可达）。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect,enabled) VALUES ('lb-dirty','dirty','http','',668,'weighted_round_robin',1,'manual',?,?,1,1)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	config := GenerateCaddyConfig()
	if message, failed := config[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate: %s", message)
	}
	servers := config["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	// fail-soft 实证：空域名行在渲染前置阶段被跳过（无生成错误、无 server、
	// 无包装器）——「空 domains 包装器冻结」形态不可达。
	if _, exists := servers["http_668"]; exists {
		t.Fatal("server http_668 should be absent（空域名行必须被 fail-soft 跳过）")
	}
	if _, exists := servers["http_80"]; !exists {
		t.Fatal("server http_80 missing（默认站/跳转通道不受脏行影响）")
	}
}
