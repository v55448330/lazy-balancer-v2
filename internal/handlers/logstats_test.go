package handlers

import (
	"os"
	"path/filepath"
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
