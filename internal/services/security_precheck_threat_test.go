package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

// 威胁情报库预检规则（v2.3.x）：合并文件存在且非空时，预检在 id:4 之后、
// GeoIP 链之前发射 id:14（@ipListFast 引用，denyStatus 与 id:2/4 同口径）；
// 文件缺失/为空 → 跳过（降级不阻塞渲染）。
func TestPrecheckThreatRule_emittedWhenMergedFilePresent(t *testing.T) {
	newClusterTestService(t)
	oldDir := ThreatDataDir
	// 威胁目录须落在算子白名单前缀下（TestMain 已对齐临时根）
	ThreatDataDir = filepath.Join(strings.TrimSuffix(wafiplist.AllowedPathPrefix, string(filepath.Separator)), "threat")
	t.Cleanup(func() { ThreatDataDir = oldDir })
	if err := os.MkdirAll(ThreatDataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ThreatDataDir, "intel-merged.txt"), []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 无其他 IP 控制时威胁规则也须让预检 handler 存在（门含威胁可用性）
	directives := mustDirectives(buildIPPrecheckDirectives(nil, 0))
	if !strings.Contains(directives, "@ipListFast ") ||
		!strings.Contains(directives, `"id:14,phase:1,deny,status:403,log,msg:'威胁情报库拦截',skipAfter:SECURITY_RULES_END"`) {
		t.Fatalf("预检须含 id:14 威胁情报库规则:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "intel-merged"); got != "203.0.113.0/24\n" {
		t.Fatalf("威胁合并名单文件内容=%q", got)
	}

	// denyStatus 抬码同 id:2/4 口径（阶段 1 拦截页 481）
	directives481 := mustDirectives(buildIPPrecheckDirectives(nil, 481))
	if !strings.Contains(directives481, `"id:14,phase:1,deny,status:481,log`) {
		t.Fatalf("id:14 须随 denyStatus 抬码 481:\n%s", directives481)
	}

	// 引擎门禁（R-10）：id:14 形状必须被 coraza 编译接受
	compileForEngineGate(t, directives)
}

func TestPrecheckThreatRule_skippedWhenFileMissingOrEmpty(t *testing.T) {
	newClusterTestService(t)
	oldDir := ThreatDataDir
	ThreatDataDir = t.TempDir()
	t.Cleanup(func() { ThreatDataDir = oldDir })

	// 缺失：无 id:14（且无其他控制时整个预检不发射——回归既有空串语义）
	if directives := mustDirectives(buildIPPrecheckDirectives(nil, 0)); strings.Contains(directives, "id:14") {
		t.Fatalf("合并文件缺失时不得发射 id:14:\n%s", directives)
	}
	// 空文件
	if err := os.WriteFile(filepath.Join(ThreatDataDir, "intel-merged.txt"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if directives := mustDirectives(buildIPPrecheckDirectives(nil, 0)); strings.Contains(directives, "id:14") {
		t.Fatalf("合并文件为空时不得发射 id:14:\n%s", directives)
	}
}

// 归因族（v2.3.x）：id:14 归入 IP 族（能力首选层/fallback 共用谓词）。
func TestThreatAttribution_id14IsIPFamily(t *testing.T) {
	if !securityEventsRuleIsIPFamily("14") {
		t.Fatal("id:14 必须归入 IP 族（securityEventsRuleIsIPFamily）")
	}
}
