package i18n

import (
	"strings"
	"testing"
)

// 相邻 %s%s 占位符之间无字面量,matchTpl 的参数切分歧义(空字面量段被
// 跳过,args 与 en 模板错位,产出静默畸形译文)。登记期必须响亮拒绝,
// 不得带病入库;合法形态(首/尾占位、%% 转义字面量)不受影响。
func TestRegisterErrTpl_rejectsAdjacentPlaceholders(t *testing.T) {
	bad := []struct{ zh, en string }{
		{"甲%s%s乙", "A%s%sB"},
		{"甲%s乙", "A%s%sB"}, // en 侧相邻同样拒绝
		{"%s%s", "%s %s"},
	}
	for _, c := range bad {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("RegisterErrTpl(%q,%q) 应 panic 拒绝相邻占位", c.zh, c.en)
					return
				}
				msg, ok := r.(string)
				if !ok || (!strings.Contains(msg, c.zh) && !strings.Contains(msg, c.en)) {
					t.Errorf("panic 信息应含违规模板原文, got %v", r)
				}
			}()
			RegisterErrTpl(c.zh, c.en)
		}()
	}
	// 拒绝必须发生在入库前:被拒模板不得参与 TrErr 匹配(终态钉测)。
	if got := TrErr("甲XY乙", EN); got != "甲XY乙" {
		t.Errorf("被拒模板不得入库参与匹配, TrErr=%q", got)
	}
	// 合法形态回归:首占位/尾占位/%% 字面量不得误拒。
	ok := []struct{ zh, en, msg, want string }{
		{"前置%s收尾", "lead %s end", "前置X收尾", "lead X end"},
		{"尾随占位%s", "trailing %s", "尾随占位X", "trailing X"},
		{"比例 %s%% 达标", "ratio %s%% ok", "比例 90% 达标", "ratio 90% ok"},
	}
	for _, c := range ok {
		RegisterErrTpl(c.zh, c.en)
		if got := TrErr(c.msg, EN); got != c.want {
			t.Errorf("TrErr(%q)=%q want %q", c.msg, got, c.want)
		}
	}
}
