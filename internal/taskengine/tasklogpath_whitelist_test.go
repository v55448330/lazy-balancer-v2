package taskengine

// 第 77 轮 P5：TaskLogPath 净化从黑名单（剔除 '/'、'\\'）改白名单——只保留
// 注册任务 ID 全字母表 [A-Za-z0-9_.:-]，与 handlers sanitizeRuleID 白名单同族
// 口径（单一净化范式，畸形 ID 不再产出黑名单遗漏字符的文件名）。注册 ID 全集
// （taskengine_wire.go 18 个）仅用小写+数字+'-'+'.'+一个 ':'（
// startup:config-load），大写留作未来余量——既有 ID 零变化。

import (
	"path/filepath"
	"testing"
)

func TestTaskLogPath_whitelistAlphabet(t *testing.T) {
	dir := t.TempDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir("") })

	// 既有注册 ID 全字母表形态零变化（含 ':' 冒号任务）
	for _, id := range []string{"crs", "ip2region", "threat", "autoban", "startup:config-load", "security-events-ingestion", "cert-renewal-scan"} {
		if got, want := TaskLogPath(id), filepath.Join(dir, id+".log"); got != want {
			t.Fatalf("TaskLogPath(%q)=%q, want %q（合法注册 ID 不得变形）", id, got, want)
		}
	}

	// 白名单外字符剔除：'/'、'\\'、'?'、'#'、'%' 逐一剔除，字母表内字符保序保留
	if got := TaskLogPath(`a/b\c:d?e#f%`); got != filepath.Join(dir, "abc:def.log") {
		t.Fatalf("TaskLogPath 白名单净化=%q, want %q", got, filepath.Join(dir, "abc:def.log"))
	}

	// 目录穿越形态：分隔符剔除后收敛为目录内文件名（Join 语义无路径段，无逃逸）
	got := TaskLogPath(`../../etc/passwd`)
	if filepath.Dir(got) != dir {
		t.Fatalf("穿越形态净化=%q, want 收敛在目录 %q 内", got, dir)
	}
	if filepath.Base(got) != "....etcpasswd.log" {
		t.Fatalf("穿越形态净化基名=%q, want ....etcpasswd.log（分隔符剔除、字母表内字符保留）", filepath.Base(got))
	}

	// 未初始化目录=空串（既有契约）
	SetLogDir("")
	if got := TaskLogPath("crs"); got != "" {
		t.Fatalf("未初始化 TaskLogPath=%q, want 空串", got)
	}
}
