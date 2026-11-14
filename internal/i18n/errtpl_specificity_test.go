package i18n

import (
	"strings"
	"testing"
)

// 模板匹配必须按静态字面量前缀长度优先：泛化模板（"写入 %s: %s"）先登记时，
// 不得抢先吞掉具体模板（"写入 CRS VERSION 标记: %s"）——否则具体 en 译文永不
// 生效，英文用户看到 "write CRS VERSION 标记: boom" 式中英混杂。
func TestTrErr_specificTemplateBeatsGenericPrefix(t *testing.T) {
	cases := []struct{ msg, want string }{
		{"写入 CRS VERSION 标记: boom", "write CRS VERSION marker: boom"},
		{"写入 CRS VERSION 标记失败且规则树回滚失败: boom", "failed to write the CRS VERSION marker and the rules tree rollback also failed: boom"},
		{"读取 .iplist feed-a: boom", "read .iplist feed-a: boom"},
	}
	for _, c := range cases {
		got := TrErr(c.msg, EN)
		if got != c.want {
			t.Errorf("TrErr(%q)=%q, want %q", c.msg, got, c.want)
		}
		if strings.ContainsFunc(got, isZh) {
			t.Errorf("TrErr(%q)=%q 仍含中文——具体模板被泛化模板抢先", c.msg, got)
		}
	}
	// 回归形状：泛化模板本身仍须命中（具体模板不得误吞泛化消息）。
	if got := TrErr("写入 custom.conf: boom", EN); got != "write custom.conf: boom" {
		t.Errorf("泛化模板回归: %q", got)
	}
}

// 登记顺序无关性：后登记的具体模板必须压过先登记的泛化模板（生产 catalog
// 的生成顺序不可控，匹配优先级不得依赖注册序）。
func TestTrErr_specificityIndependentOfRegistrationOrder(t *testing.T) {
	RegisterErrTpl("探测 %s: %s", "probe %s: %s")
	RegisterErrTpl("探测节点心跳: %s", "probe node heartbeat: %s")
	if got := TrErr("探测节点心跳: boom", EN); got != "probe node heartbeat: boom" {
		t.Fatalf("后登记具体模板未胜出: %q", got)
	}
	if got := TrErr("探测 端口: boom", EN); got != "probe 端口: boom" {
		t.Errorf("泛化模板回归: %q", got)
	}
}
