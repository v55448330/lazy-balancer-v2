package services

// 投影名/临时名两条 GC regex 的 scope 白名单同源钉：任一投影命名形态必须
// 同时被两条 regex 认领（临时名=投影名加 `.` 前缀与 `-<数字>.tmp` 后缀）——
// 单侧增改 scope 而另一侧失配时，孤儿投影或其在役临时文件将永不回收。

import "testing"

func TestIPListGCRegexes_scopeWhitelistCrossConsistency(t *testing.T) {
	// 覆盖全部 scope 分支：u-*（含规则身份/大写/含点）、p<id>-角色、
	// crsxc 序号/哈希、tp、l4-* 族、旧内容寻址后缀。
	scopes := []string{
		"u-deny", "u-trust", "u-trust12", "u-bl", "u-allow", "u-allow-exempt",
		"u-deny-lb_2r8dosptk1", "u-deny-lb_2R8d.ptk1", "u-bl-My_Rule.1",
		"p12-acl", "p7-trust", "p3-bl",
		"p5-crsxc-0", "p5-crsxc-0123456789ab",
		"tp",
		"l4-trust-lb_tcp1", "l4-trust12-lb_tcp1", "l4-deny-lb_tcp1", "l4-bl-lb_tcp1", "l4-allow-lb_tcp1",
	}
	for _, scope := range scopes {
		for _, name := range []string{scope + ".txt", scope + "-deadbeef1234.txt"} {
			if !ipListProjectedFileName.MatchString(name) {
				t.Fatalf("投影命名 %q 应命中投影 GC regex", name)
			}
			tmp := "." + name + "-12345.tmp"
			if !ipListTempFileName.MatchString(tmp) {
				t.Fatalf("投影 %q 的原子写临时名 %q 应命中临时 GC regex（scope 白名单两侧必须同源）", name, tmp)
			}
		}
	}
	// 反向：非投影形态两侧都不得认领（用户文件不碰）。
	for _, name := range []string{"notes.txt", "backup-deadbeef1234.txt", "orphan-deadbeef0012.txt"} {
		if ipListProjectedFileName.MatchString(name) {
			t.Fatalf("非投影命名 %q 不应命中投影 GC regex", name)
		}
		if ipListTempFileName.MatchString("." + name + "-1.tmp") {
			t.Fatalf("非投影临时名 .%s-1.tmp 不应命中临时 GC regex", name)
		}
	}
}
