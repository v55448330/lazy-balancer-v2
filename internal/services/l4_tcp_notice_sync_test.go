package services

// TCP 拦截提示双侧口径机械守卫：services.clampTCPNotice（渲染期剥离控制字符）
// 与 caddyl4sec.validateBlockNotice（模块期拒绝控制字符）的控制字符谓词必须
// 逐字同口径——caddyl4sec 是独立插件模块不能 import services，两侧只能人工
// 成对修改；本钉测把「成对」变成机器判定：任一侧字符集漂移即红。源码文本
// 对账手法与 l4sec_module_contract_test.go 同款。
import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const caddyl4secHandlerSource = "../../caddyl4sec/handler.go"

// goRunePredicateExtract 从 Go 源码中定位指定函数体，返回其中
// 「r < 0x20 …」形的 rune 拒绝谓词表达式（空白归一）。
func goRunePredicateExtract(t *testing.T, src, funcName string) string {
	t.Helper()
	decl := "func " + funcName + "("
	start := strings.Index(src, decl)
	if start < 0 {
		t.Fatalf("源码缺函数 %s（函数改名须双侧同步并更新本守卫）", funcName)
	}
	rest := src[start:]
	if end := strings.Index(rest[1:], "\nfunc "); end >= 0 {
		rest = rest[:end+1]
	}
	re := regexp.MustCompile(`r\s*<\s*0x20[^{;]*`)
	m := re.FindString(rest)
	if m == "" {
		t.Fatalf("%s 函数体缺控制字符拒绝谓词（r < 0x20 …）——剥离/拒绝口径被移除", funcName)
	}
	return strings.Join(strings.Fields(m), " ")
}

func TestTCPBlockNotice_predicateCharsetMirroredInModule(t *testing.T) {
	svcSrc, err := os.ReadFile("l4_tcp_notice.go")
	if err != nil {
		t.Fatalf("read l4_tcp_notice.go: %v", err)
	}
	modSrc, err := os.ReadFile(caddyl4secHandlerSource)
	if err != nil {
		t.Skipf("caddyl4sec 模块源码缺席（并行实现未落地）: %v", err)
	}
	svcPred := goRunePredicateExtract(t, string(svcSrc), "clampTCPNotice")
	modPred := goRunePredicateExtract(t, string(modSrc), "validateBlockNotice")

	if svcPred != modPred {
		t.Fatalf("控制字符谓词两侧漂移（改动必须成对）：\nservices.clampTCPNotice:      %s\ncaddyl4sec.validateBlockNotice: %s", svcPred, modPred)
	}
	// 边界字面量必须齐全：剥离/拒绝口径 = C0 区 + DEL + C1 区（U+0080-009F）
	// + Unicode 行/段分隔符（U+2028/U+2029）。任一侧丢任一边界即在此失败。
	for _, boundary := range []string{"0x20", "0x7F", "0x80", "0x9F", "0x2028", "0x2029"} {
		if !strings.Contains(svcPred, boundary) {
			t.Fatalf("services.clampTCPNotice 谓词缺边界 %s：%s", boundary, svcPred)
		}
		if !strings.Contains(modPred, boundary) {
			t.Fatalf("caddyl4sec.validateBlockNotice 谓词缺边界 %s：%s", boundary, modPred)
		}
	}
}
