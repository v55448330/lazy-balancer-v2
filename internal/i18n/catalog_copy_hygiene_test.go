package i18n

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// 英文词条不得携带冒号后双空格（":  %s" 等）——中文母本不动。
func TestCatalogEnglishEntriesNoDoubleSpaceAfterColon(t *testing.T) {
	source, err := os.ReadFile("catalog_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`Register\(".*?", (".*?"), (".*?")\)`)
	matches := re.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("catalog_gen.go 未扫到任何 Register——守卫对象漂移")
	}
	for _, m := range matches {
		en, err := strconv.Unquote(m[2])
		if err != nil {
			t.Fatalf("英文词条解码失败: %v", err)
		}
		if strings.Contains(en, ":  ") {
			t.Errorf("英文词条含冒号后双空格: %q", en)
		}
	}
}

// 英文错误模板不得残留中文标点（全角括号/破折号等）——zh 母本保留中文标点。
func TestErrTplEnglishNoChinesePunctuation(t *testing.T) {
	source, err := os.ReadFile("errtpl_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`RegisterErrTpl\((".*?"), (".*?")\)`)
	matches := re.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("errtpl_gen.go 未扫到任何 RegisterErrTpl——守卫对象漂移")
	}
	for _, m := range matches {
		en, err := strconv.Unquote(m[2])
		if err != nil {
			t.Fatalf("英文模板解码失败: %v", err)
		}
		if strings.Contains(en, "——") {
			t.Errorf("英文模板残留中文双破折号: %q", en)
		}
		if i := strings.IndexAny(en, "（）：，。；！？「」"); i >= 0 {
			t.Errorf("英文模板残留中文标点 %q: %q", en[i:i+3], en)
		}
	}
}

// 自动备份水位线关停守卫错误串必须登记英文模板（与同函数兄弟消息
// 「读取/更新自动备份水位线（槽 %s）失败」同口径）：句柄注销与已关闭句柄
// 两个显性失败面，英文用户不得回落中文。
func TestTrErr_autoBackupWatermarkShutdownGuardsTranslate(t *testing.T) {
	cases := []struct{ msg, want string }{
		{"推进自动备份水位线失败：数据库未初始化或已关闭", "failed to advance the auto-backup watermark: database not initialized or already closed"},
		{"推进自动备份水位线失败（数据库不可用）: disk I/O error", "failed to advance the auto-backup watermark (database unavailable): disk I/O error"},
	}
	for _, c := range cases {
		if got := TrErr(c.msg, EN); got != c.want {
			t.Errorf("TrErr(%q)=%q, want %q", c.msg, got, c.want)
		}
		if got := TrErr(c.msg, ZH); got != c.msg {
			t.Errorf("zh 应原样回落: TrErr(%q)=%q", c.msg, got)
		}
	}
}
