package services

// PROXY v2 受信网段过宽门双侧判据机械守卫：渲染单源侧
// TrustedProxyPrefixCanonical/AllSpace/BelowMinBits/trustedProxyMinPrefixBits
// （写侧校验+渲染投影的生产门）与 caddyl4sec 模块 lb_l4_pp Provision 的
// ppAllow* 兜底门（带外直写 Caddy 配置文件时配置加载期拒绝）必须逐字同判据
// ——caddyl4sec 是独立插件模块不能 import services，两侧只能人工成对修改；
// 本钉测把「成对」变成机器判定：任一侧判据漂移即红。源码文本对账手法与
// l4_tcp_notice_sync_test.go 同款。
import (
	"os"
	"strings"
	"testing"
)

const caddyl4secPPSource = "../../caddyl4sec/pp.go"

// goFuncBodyExtract 定位函数体（func NAME( 起，至列 0 收括号「}」止），
// 空白归一。嵌套块收括号在 gofmt 下恒缩进，列 0 首现即函数收口。
func goFuncBodyExtract(t *testing.T, src, funcName string) string {
	t.Helper()
	decl := "func " + funcName + "("
	start := strings.Index(src, decl)
	if start < 0 {
		t.Fatalf("源码缺函数 %s（函数改名须双侧同步并更新本守卫）", funcName)
	}
	rest := src[start:]
	if end := strings.Index(rest, "\n}"); end >= 0 {
		rest = rest[:end+2]
	}
	return strings.Join(strings.Fields(rest), " ")
}

// ppAllowNameNormalize 模块侧函数名归一到渲染侧命名空间（ppAllowPrefix→
// TrustedProxyPrefix、ppAllowMin→trustedProxyMin），函数体内互调随之对齐。
func ppAllowNameNormalize(body string) string {
	body = strings.ReplaceAll(body, "ppAllowPrefix", "TrustedProxyPrefix")
	return strings.ReplaceAll(body, "ppAllowMin", "trustedProxyMin")
}

func TestL4PPAllowGate_prefixWidthJudgmentsMirroredInModule(t *testing.T) {
	svcSrc, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("read caddy.go: %v", err)
	}
	modSrc, err := os.ReadFile(caddyl4secPPSource)
	if err != nil {
		t.Skipf("caddyl4sec 模块源码缺席（并行实现未落地）: %v", err)
	}

	pairs := [][2]string{
		{"TrustedProxyPrefixCanonical", "ppAllowPrefixCanonical"},
		{"trustedProxyMinPrefixBits", "ppAllowMinPrefixBits"},
		{"TrustedProxyPrefixAllSpace", "ppAllowPrefixAllSpace"},
		{"TrustedProxyPrefixBelowMinBits", "ppAllowPrefixBelowMinBits"},
	}
	for _, pair := range pairs {
		svcBody := goFuncBodyExtract(t, string(svcSrc), pair[0])
		modBody := ppAllowNameNormalize(goFuncBodyExtract(t, string(modSrc), pair[1]))
		if svcBody != modBody {
			t.Fatalf("过宽门判据两侧漂移（改动必须成对）：\nservices.%s: %s\ncaddyl4sec.%s: %s", pair[0], svcBody, pair[1], modBody)
		}
	}

	// 边界字面量必须齐全：全空间三形态 + v4/v6 最小前缀长度。任一侧丢任一
	// 边界即在此失败。
	svcAllSpace := goFuncBodyExtract(t, string(svcSrc), "TrustedProxyPrefixAllSpace")
	modAllSpace := ppAllowNameNormalize(goFuncBodyExtract(t, string(modSrc), "ppAllowPrefixAllSpace"))
	for _, form := range []string{"0.0.0.0/8", "0.0.0.0/0", "::/0"} {
		if !strings.Contains(svcAllSpace, `"`+form+`"`) {
			t.Fatalf("services.TrustedProxyPrefixAllSpace 缺全空间形态 %s：%s", form, svcAllSpace)
		}
		if !strings.Contains(modAllSpace, `"`+form+`"`) {
			t.Fatalf("caddyl4sec.ppAllowPrefixAllSpace 缺全空间形态 %s：%s", form, modAllSpace)
		}
	}
	svcMinBits := goFuncBodyExtract(t, string(svcSrc), "trustedProxyMinPrefixBits")
	modMinBits := ppAllowNameNormalize(goFuncBodyExtract(t, string(modSrc), "ppAllowMinPrefixBits"))
	for _, bound := range []string{"29", "8"} {
		if !strings.Contains(svcMinBits, bound) {
			t.Fatalf("services.trustedProxyMinPrefixBits 缺最小前缀长度 %s：%s", bound, svcMinBits)
		}
		if !strings.Contains(modMinBits, bound) {
			t.Fatalf("caddyl4sec.ppAllowMinPrefixBits 缺最小前缀长度 %s：%s", bound, modMinBits)
		}
	}
}
