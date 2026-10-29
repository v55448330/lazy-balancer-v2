package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 缺库降级（2026-09-24 用户裁定）：CRS 规则库或 IP2Region 库缺失时，
// 所有安全规则（预检/ACL/限流/WAF/GeoIP/信任直通包裹）整体不渲染——
// coraza Include 缺失文件会让 caddy validate 拒绝整份配置（负载均衡也被
// 拖死），降级为安全段缺席 + 告警，由用户补库后恢复。
// stubSecurityLibsAvailable 把 CRS 目录/IP2Region 库桩到临时可用形态——缺库降级
// （2026-09-24）后，凡断言安全链渲染的测试必须先桩可用，否则安全段整体缺席。
func stubSecurityLibsAvailable(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	crsDir := filepath.Join(tmp, "crs")
	// 目录含基础设施探针文件——SecurityLibraryStatus 与安装门同口径，
	// 空树不再算可用（949 抬码等发射门也以文件存在为条件）。
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", crsRulesProbeFile), []byte("# fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	xdb := filepath.Join(tmp, "ip2region.xdb")
	if err := os.WriteFile(xdb, []byte("xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := SetSecurityLibsDirsForTest(crsDir, xdb)
	t.Cleanup(restore)
}

func TestGenerateCaddyConfig_missingSecurityLibs_disablesSecurityChain(t *testing.T) {
	_, database := newClusterTestService(t)
	// Given：http 规则 + stage1 ACL 策略（deny 内联条目）+ 绑定
	if _, err := database.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled)
		VALUES ('lb-libs','libs','http','libs.example.com',80,'weighted_round_robin','',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb-libs','127.0.0.1',8080,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	res, err := database.Exec(`INSERT INTO security_policies (name,mode,enabled,policy_type,ip_acl_enabled,ip_acl_mode,ip_acl_list,rate_limit_enabled,rate_limit_rps)
		VALUES ('libs-acl','blocking',1,'stage1',1,'deny','["10.99.0.1/32"]',1,10)`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb-libs', ?)`, policyID); err != nil {
		t.Fatal(err)
	}
	seedStage0Policy(t, database, "lb-libs", `["10.99.0.9/32"]`, false)

	// 可用形态桩（共享 helper）：CRS 目录含基础设施探针文件 + ip2region 库非空
	stubSecurityLibsAvailable(t)
	tmp := t.TempDir()
	crsDir := crsDirectivesDir
	xdb := ip2regionLivePath

	render := func() string {
		cfg := GenerateCaddyConfig()
		if msg, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
			t.Fatalf("generate: %s", msg)
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	assertSecurityArtifacts := func(raw string, want bool) {
		t.Helper()
		for _, artifact := range []struct{ name, needle string }{
			{"WAF", `"handler":"waf"`},
			{"rate limit", `"handler":"rate_limit"`},
			{"blocked counter", `"handler":"lb_security_blocked_counter"`},
			{"timing pre", `"handler":"lb_security_timing_pre"`},
			{"timing end", `"handler":"lb_security_timing_end"`},
			{"trust passthrough matcher", "10.99.0.9"},
		} {
			if got := strings.Contains(raw, artifact.needle); got != want {
				t.Fatalf("%s presence=%v, want %v", artifact.name, got, want)
			}
		}
	}

	// 库齐全 → 整族安全处理器与信任直通包裹都在场，后续缺席断言具备反证力。
	crsDirectivesDir = crsDir
	t.Cleanup(OverrideWafLivePathsForTest(crsLiveDir, xdb))
	assertSecurityArtifacts(render(), true)
	// CRS 缺失 → 安全链整体不渲染，不得残留限流/计数/计时/信任包裹。
	crsDirectivesDir = filepath.Join(tmp, "crs-missing")
	assertSecurityArtifacts(render(), false)
	// CRS 恢复 + IP2Region 缺失 → 同样整族不渲染。
	crsDirectivesDir = crsDir
	t.Cleanup(OverrideWafLivePathsForTest(crsLiveDir, filepath.Join(tmp, "missing.xdb")))
	assertSecurityArtifacts(render(), false)
}

func TestSecurityLibraryStatus_matchesCRSIntegrityProbe(t *testing.T) {
	cases := []struct {
		name      string
		files     []string
		xdb       string // "valid" | "missing" | "empty"
		wantCRSOK bool
		wantXDBOK bool
	}{
		{name: "missing rules", xdb: "valid", wantCRSOK: false, wantXDBOK: true},
		{name: "empty rules", files: []string{}, xdb: "valid", wantCRSOK: false, wantXDBOK: true},
		{name: "unrelated conf only", files: []string{"REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"}, xdb: "valid", wantCRSOK: false, wantXDBOK: true},
		{name: "901 probe present", files: []string{crsRulesProbeFile}, xdb: "valid", wantCRSOK: true, wantXDBOK: true},
		// ip2region 空文件/缺失必须判不可用（st.Size()>0 分支此前零覆盖）。
		{name: "901 probe present, xdb missing", files: []string{crsRulesProbeFile}, xdb: "missing", wantCRSOK: true, wantXDBOK: false},
		{name: "901 probe present, xdb empty", files: []string{crsRulesProbeFile}, xdb: "empty", wantCRSOK: true, wantXDBOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			crsDir := filepath.Join(root, "crs")
			if tc.files != nil {
				if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
					t.Fatal(err)
				}
				for _, name := range tc.files {
					if err := os.WriteFile(filepath.Join(crsDir, "rules", name), []byte("# fixture"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			xdb := filepath.Join(root, "ip2region.xdb")
			switch tc.xdb {
			case "valid":
				if err := os.WriteFile(xdb, []byte("xdb"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(xdb, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			case "missing":
				// 不创建文件
			default:
				t.Fatalf("未知 xdb 形态 %q", tc.xdb)
			}
			restore := SetSecurityLibsDirsForTest(crsDir, xdb)
			t.Cleanup(restore)
			crsOK, ip2regionOK := SecurityLibraryStatus()
			if crsOK != tc.wantCRSOK || ip2regionOK != tc.wantXDBOK {
				t.Fatalf("SecurityLibraryStatus=(%v,%v), want (%v,%v)", crsOK, ip2regionOK, tc.wantCRSOK, tc.wantXDBOK)
			}
		})
	}
}

func TestSetSecurityLibsDirsForTest_forwardsCRSLiveRoot(t *testing.T) {
	original := CRSLiveDir()
	crsDir := filepath.Join(t.TempDir(), "crs")
	restore := SetSecurityLibsDirsForTest(crsDir, filepath.Join(t.TempDir(), "ip2region.xdb"))
	if got := CRSLiveDir(); got != crsDir {
		t.Fatalf("CRSLiveDir=%q, want forwarded test root %q", got, crsDir)
	}
	restore()
	if got := CRSLiveDir(); got != original {
		t.Fatalf("restore left CRSLiveDir=%q, want %q", got, original)
	}
}
