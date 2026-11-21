package notify

// 跨栈共享夹具：web/tests/fixtures/daily-multivalue-md.json 同时被前端
// web/tests/mdPreview.spec.ts 的 dailyMultiValueMd 用例读取——日报多值变量
// 表格化在此前后端各写一份断言时曾漂移（单元格管道符转义、备注列缺省「—」、
// 坏行整项回退的判定），单侧改动不红。
//
// 比较口径：Go 块以换行结尾、前端 join 不带尾换行——统一去掉尾部换行后逐字
// 比较（块体语义相同，行尾差异不属于契约）。
//
// label 形参当前未参与渲染（PRES154-P3-02 记录的死参，归属 daily_report.go
// 收敛批次），本用例传空串显式声明「label 不影响输出」——若未来 label 参与
// 渲染，本用例会因输出变化而红。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type dailyMultiValueFixtureCase struct {
	Key      string  `json:"key"`
	Value    string  `json:"value"`
	Expected *string `json:"expected"`
}

func TestMDMultiValueTableMatchesFrontendFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "daily-multivalue-md.json"))
	if err != nil {
		t.Fatalf("读取跨栈夹具: %v", err)
	}
	var cases []dailyMultiValueFixtureCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("解析跨栈夹具: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("跨栈夹具为空")
	}
	for i, tc := range cases {
		got, ok := mdMultiValueTable(tc.Key, "", tc.Value)
		if tc.Expected == nil {
			if ok {
				t.Errorf("夹具第 %d 行（%s %q）：期望整项回退（ok=false），实际产出 %q", i+1, tc.Key, tc.Value, got)
			}
			continue
		}
		if !ok {
			t.Errorf("夹具第 %d 行（%s %q）：期望成表，实际回退", i+1, tc.Key, tc.Value)
			continue
		}
		if trimmed := strings.TrimRight(got, "\n"); trimmed != *tc.Expected {
			t.Errorf("夹具第 %d 行（%s %q）：表格输出与前端夹具不一致\n got: %q\nwant: %q", i+1, tc.Key, tc.Value, trimmed, *tc.Expected)
		}
	}
}
