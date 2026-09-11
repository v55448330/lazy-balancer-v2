package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B-11(第 4 轮审计):dirBytes/timestampedRotations 全函数零落盘测试——
// 第 2/3 轮 Sys-N1 的 off-by-one 和 B-2 的聚合双计均因此缺测试而逃逸。
// 本测试用真实文件名 fixture 钉住三族轮转统计行为。
func TestDirBytes_countsAllRotationFamilies(t *testing.T) {
	dir := t.TempDir()

	// 运行日志族:lazy-balancer.log.YYYYMMDD-HHMMSS
	os.WriteFile(filepath.Join(dir, "app.log"), []byte("active"), 0644)
	os.WriteFile(filepath.Join(dir, "app.log.20260902-150405"), []byte("runtime-rotated"), 0644)
	// 自研 shift 族:.1-.9
	os.WriteFile(filepath.Join(dir, "app.log.1"), []byte("shift-rotated"), 0644)
	// timberjack 族:<stem>-<ts>-size.log(时间戳以数字开头)
	os.WriteFile(filepath.Join(dir, "app-20260902T15-04-05.000-size.log"), []byte("timberjack-rotated"), 0644)
	// 兄弟前缀(B-2):caddy-tls-... 不应被 caddy.log 的 stem='caddy' 吞入
	os.WriteFile(filepath.Join(dir, "caddy.log"), []byte("c"), 0644)
	os.WriteFile(filepath.Join(dir, "caddy-20260902T15-04-05.000-size.log"), []byte("caddy-own"), 0644)
	os.WriteFile(filepath.Join(dir, "caddy-tls-20260902T15-04-05.000-size.log"), []byte("caddy-tls-brother"), 0644)

	// 运行日志族:active(6) + runtime-rotated(16) + shift-rotated(14) + timberjack-rotated(19)
	active, rotated := dirBytes(filepath.Join(dir, "app.log"))
	if active != 6 {
		t.Errorf("app.log active=%d, want 6", active)
	}
	wantRotated := int64(15 + 13 + 18)
	if rotated != wantRotated {
		t.Errorf("app.log rotated=%d, want %d(runtime+shift+timberjack)", rotated, wantRotated)
	}

	// B-2:caddy.log 不应吞入 caddy-tls 兄弟的轮转
	// caddy.log 的 stem='caddy',timberjack 匹配 'caddy-...' 但不应匹配 'caddy-tls-...'
	cActive, cRotated := dirBytes(filepath.Join(dir, "caddy.log"))
	if cActive != 1 {
		t.Errorf("caddy.log active=%d, want 1", cActive)
	}
	if cRotated != 9 { // 只有 caddy-2026...(9字节),不含 caddy-tls-...(17字节)
		t.Errorf("caddy.log rotated=%d, want 10(只有 caddy-2026...=10字节,不含 caddy-tls-...=17字节;B-2)", cRotated)
	}
}

// F-A(第 6 轮审计):聚合视图(certjob/rule_access 无 caddy_id 形态)枚举时
// 跳过 timberjack 轮转副本——否则副本既计入 active(自身 dirBytes)又计入
// rotated(base 的 timestampedRotations),active 虚增 R+G。
// F-A(第 6 轮审计):isTimberjackRotationCopy 判定 timberjack 轮转副本。
// 聚合视图(certjob/rule_access 无 caddy_id 形态)枚举时用它跳过轮转副本,
// 否则副本既计入 active(自身 dirBytes)又计入 rotated(base 的
// timestampedRotations),active 虚增 R+G(total≈实际2倍)。
func TestIsTimberjackRotationCopy(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// timberjack 轮转副本(数字时间戳):跳过
		{"certjob-abc-20260902T150405-size.log", true},
		{"certjob-abc-20260902T150405.000-size.log", true},
		{"certjob-abc-20260902-150405-size.log", true},
		{"rule1-20260902T150405-size.log.gz", true},
		{"caddy-20260902T15-04-05.000-size.log", true},
		// 非 timberjack(不含 -size.log 后缀):不跳过
		{"certjob-abc.log", false},
		{"certjob-abc.log.1", false},
		{"certjob-abc.log.20260902-150405", false},
		{"app.log.gz", false},
		// 含 -size.log 后缀但时间戳段首字符为字母(B-2 边界):不跳过
		{"certjob-abc-tls-size.log", false},
		// caddy-tls-...-size.log 是 caddy-tls.log 的轮转(时间戳段以数字开头)
		// →聚合语境下跳过(由 caddy-tls.log 的 timestampedRotations 统计)
		{"caddy-tls-20260902T150405-size.log", true},
	}
	for _, tc := range cases {
		if got := isTimberjackRotationCopy(tc.name); got != tc.want {
			t.Errorf("isTimberjackRotationCopy(%q)=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// F-A 端到端:聚合视图 dirBytes 调用轮转副本被跳过后,active 不虚增。
// 用真实目录布局验证 GetLogStats 的 certjob 聚合分支的过滤逻辑单元——
// isTimberjackRotationCopy 过滤 + dirBytes 统计组合。
func TestDirBytes_aggregationWithRotationFilter(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "certjob-abc.log"), []byte("A"), 0644)                                 // active: 1B
	os.WriteFile(filepath.Join(dir, "certjob-abc-20260902T150405-size.log"), []byte("BB"), 0644)            // timberjack: 2B
	os.WriteFile(filepath.Join(dir, "certjob-abc-20260902T160405-size.log.gz"), []byte("CCC"), 0644)        // timberjack gz: 3B
	os.WriteFile(filepath.Join(dir, "certjob-abc.log.1"), []byte("DDDD"), 0644)                             // shift: 4B

	// 模拟聚合循环:枚举 + 过滤轮转副本 + dirBytes
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var active, rotated int64
	for _, e := range entries {
		// 复刻 GetLogStats certjob 聚合分支的真实过滤链
		if e.IsDir() || !strings.HasPrefix(e.Name(), "certjob-") || !strings.HasSuffix(e.Name(), ".log") && !strings.HasSuffix(e.Name(), ".log.gz") {
			continue
		}
		if isTimberjackRotationCopy(e.Name()) {
			continue
		}
		a, r := dirBytes(filepath.Join(dir, e.Name()))
		active += a
		rotated += r
	}
	// 修复后:active=1(仅 certjob-abc.log),rotated=2+3+4=9
	// 修复前:active=1+2+3=6(轮转副本也被计入 active),rotated=9 → 虚增
	if active != 1 {
		t.Errorf("aggregation active=%d, want 1 (rotation copies must be skipped, was double-counted pre-fix)", active)
	}
	if rotated != 9 {
		t.Errorf("aggregation rotated=%d, want 9", rotated)
	}
}
