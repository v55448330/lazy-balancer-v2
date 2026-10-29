package services

import (
	"path/filepath"
	"strings"
	"testing"
)

// 规则日志文件名主体单源（写侧 RuleLogPath 与 handlers 读侧共用同一函数）：
// 合法字母表 ID 原样保留、其余可逆编码、编码后不与其它 ID 碰撞，且路径恒由
// 该单源拼接（同名双层透传合并后行为不变）。
func TestRuleLogFileComponentReversibleAndUsedByPath(t *testing.T) {
	if got := RuleLogFileComponent("lb_plain-1"); got != "lb_plain-1" {
		t.Fatalf("字母表内 ID 必须原样保留, got %q", got)
	}
	encoded := RuleLogFileComponent("lb.dot")
	if !strings.HasPrefix(encoded, "%") {
		t.Fatalf("字母表外 ID 必须走可逆编码, got %q", encoded)
	}
	if encoded == RuleLogFileComponent("lbdot") {
		t.Fatalf("编码碰撞：lb.dot 与 lbdot 共用文件名 %q", encoded)
	}
	if decoded := decodeFileComponent(encoded); decoded != "lb.dot" {
		t.Fatalf("编码不可逆: %q → %q", encoded, decoded)
	}

	t.Cleanup(SetRuleLogDirForTest(t.TempDir()))
	want := filepath.Join(ruleLogDir, encoded+".log")
	if got := RuleLogPath("lb.dot"); got != want {
		t.Fatalf("RuleLogPath=%q, want 单源主体拼接 %q", got, want)
	}
}

// 非法 hex 字面量按原值返回（存量文件名恒可解析，向后兼容优先于严格性）；
// 合法 hex（含多字节 UTF-8）照常解码。
func TestDecodeFileComponent_invalidHexLiteral(t *testing.T) {
	cases := map[string]string{
		"%zz":     "%zz", // 非法 hex：按字面值原样返回
		"%":       "%",   // 空载荷：按字面值原样返回
		"%4":      "%4",  // 半字节载荷：解码失败按字面值返回
		"%41":     "A",   // 合法 hex 照常解码
		"%e4b8ad": "中",   // 合法多字节 UTF-8 照常解码
	}
	for in, want := range cases {
		if got := decodeFileComponent(in); got != want {
			t.Fatalf("decodeFileComponent(%q)=%q, want %q", in, got, want)
		}
	}
}
