package apimsg_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/apimsg"
	i18n "lazy-balancer-v2/internal/i18n"
	"lazy-balancer-v2/internal/models"
)

func enCtx() tfCtx { return tfCtx{i18n.CtxLangKey: i18n.EN} }

// Envelope 是带键响应信封的构造入口：一次调用产出业务码、按请求语言渲染的
// message、稳定键 message_key 与模板参数 message_params。前端据键 + 参数用自己的
// 词条按界面语言渲染，渲染不出时回落 message。
//
// 为什么要有它：手写三字段（Code / Message / MessageKey）要把键抄两遍，已有 73 处
// 漏抄了键；补模板参数时若把实参再抄一份，实参里的函数调用（apimsg.ErrMsg、脱敏、
// 时间计算）会被执行两次。一次调用、实参只求值一次，两样都不可能出错。
//
// 形状：目标（键与参数随信封回传、线上 JSON 形态固定）、回归（无参数时与手写三字段
// 逐字相同——老客户端零感知）、畸形（实参类型五花八门时，参数仍是它被渲染进
// message 的那段文本）。

func TestEnvelope_carriesKeyAndParamsOnTheWire(t *testing.T) {
	got := apimsg.Envelope(zhCtx(), 400, "notify.dailyItemUnknown", "no_such_item")
	want := models.APIResponse{
		Code:          400,
		Message:       "未知的日报项目: no_such_item",
		MessageKey:    "notify.dailyItemUnknown",
		MessageParams: []string{"no_such_item"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Envelope 结果\n got %#v\nwant %#v", got, want)
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	const wantJSON = `{"code":400,"message":"未知的日报项目: no_such_item","message_key":"notify.dailyItemUnknown","message_params":["no_such_item"]}`
	if string(wire) != wantJSON {
		t.Fatalf("线上 JSON\n got %s\nwant %s", wire, wantJSON)
	}
}

func TestEnvelope_withoutArgs_matchesHandWrittenLiteral(t *testing.T) {
	// 回归：无参数时不产生 message_params，其余三字段与既有写法逐字相同。
	hand := models.APIResponse{Code: 404, Message: apimsg.T(zhCtx(), "user.notFound"), MessageKey: "user.notFound"}
	if got := apimsg.Envelope(zhCtx(), 404, "user.notFound"); !reflect.DeepEqual(got, hand) {
		t.Fatalf("无参数信封与手写字面量不一致\n got %#v\nwant %#v", got, hand)
	}
	wire, err := json.Marshal(apimsg.Envelope(zhCtx(), 404, "user.notFound"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"code":404,"message":"用户不存在","message_key":"user.notFound"}`; string(wire) != want {
		t.Fatalf("无参数信封的线上 JSON 多出了字段\n got %s\nwant %s", wire, want)
	}
}

func TestEnvelope_paramsAreTheTextRenderedIntoMessage(t *testing.T) {
	// 目标：实参无论什么类型，回传的参数都是它被渲染进 message 的那段文本——把参数
	// 按槽填回模板，必须逐字得到 message。前端就是这么渲染的。
	type point struct{ X, Y int }
	at := time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		args []any
	}{
		{"字符串", []any{"a、b"}},
		{"整数与小数", []any{3, 1.5}},
		{"布尔与空值", []any{true, nil}},
		{"错误", []any{errors.New("disk full")}},
		{"字节切片", []any{[]byte("raw")}},
		{"结构体与时间", []any{point{1, 2}, at}},
		{"超出双精度整数范围的整数", []any{int64(9007199254740993)}},
		{"实现了 Stringer 的类型", []any{time.Duration(1500 * time.Nanosecond)}},
	}
	const key = "caddy.unknownLogType" // 模板有两个槽：%q 与 %s
	for _, tc := range cases {
		for _, ctx := range []tfCtx{zhCtx(), enCtx()} {
			got := apimsg.Envelope(ctx, 400, key, tc.args...)
			if len(got.MessageParams) != len(tc.args) {
				t.Fatalf("%s: 参数个数 got %d, want %d", tc.name, len(got.MessageParams), len(tc.args))
			}
			params := make([]string, len(tc.args))
			for i, p := range got.MessageParams {
				if p == "" {
					t.Fatalf("%s: 第 %d 个参数为空串——归一丢了值", tc.name, i)
				}
				params[i] = p
			}
			if rendered := renderSlots(apimsg.T(ctx, key), params); rendered != got.Message {
				t.Fatalf("%s: 参数按槽填回模板与 message 不一致\n 填回 %q\nmessage %q", tc.name, rendered, got.Message)
			}
		}
	}
}

func TestEnvelope_nilContextRendersChinese(t *testing.T) {
	// 畸形：没有请求上下文（中间件未挂、测试直调）时按中文母本渲染，不崩溃。
	got := apimsg.Envelope(nil, 400, "notify.dailyItemUnknown", "x")
	if got.Message != "未知的日报项目: x" || got.MessageKey != "notify.dailyItemUnknown" || len(got.MessageParams) != 1 {
		t.Fatalf("nil 上下文下的信封 %#v", got)
	}
}

// renderSlots 是前端渲染算法在 Go 侧的镜像（web/src/utils/apiMessage.ts 的
// formatApiMessage），与 Tf 的槽位规则相同：%s / %d / %v / %q 各占一个槽、按序消费
// 参数；%q 给参数加引号；%% 是字面百分号；槽以外的写法原样保留、不消费参数；参数
// 用完后占位符原样留下，多出的参数忽略。循环体里会推进下标，保留显式循环。
func renderSlots(template string, params []string) string {
	var out strings.Builder
	next := 0
	for i := 0; i < len(template); i++ {
		if i+1 < len(template) && template[i:i+2] == "%%" {
			out.WriteByte('%')
			i++
			continue
		}
		if i+1 < len(template) && template[i] == '%' && strings.ContainsAny(template[i+1:i+2], "sdvq") {
			if next < len(params) {
				text := params[next]
				if template[i+1] == 'q' {
					text = `"` + text + `"`
				}
				out.WriteString(text)
				next++
			} else {
				out.WriteString(template[i : i+2])
			}
			i++
			continue
		}
		out.WriteByte(template[i])
	}
	return out.String()
}

// TestFormatFixture_parityWithFrontend 与前端共享同一份夹具（web/tests/fixtures/
// apiMessage_format.json）：后端渲染镜像与前端 formatApiMessage 对同一模板 + 参数
// 必须得出同一结果——前端成为文案来源时，用户看到的文字不变。前端侧的对等断言见
// web/tests/apiMessage.spec.ts 的第一条用例。
func TestFormatFixture_parityWithFrontend(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "apiMessage_format.json"))
	if err != nil {
		t.Fatalf("读共享夹具失败: %v", err)
	}
	var cases []struct {
		Template string   `json:"template"`
		Params   []string `json:"params"`
		Expected string   `json:"expected"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 10 {
		t.Fatalf("夹具只有 %d 条——对等守卫会空过", len(cases))
	}
	for _, item := range cases {
		if got := renderSlots(item.Template, item.Params); got != item.Expected {
			t.Errorf("renderSlots(%q, %v)\n got %q\nwant %q", item.Template, item.Params, got, item.Expected)
		}
	}
}
