package services

// 「每规则取最新适用行」单源守卫：启动物化（MaterializeAllCertsFromDB）与 6h
// 文件对账（reconcileMissingCertFiles）此前各写一份 SELECT+seenRules 循环，
// 判定已经分叉——对账只看文件是否存在（不比对内容/权限），物化按内容+权限判
// changed。两条链路的**选择**（哪一行代表该规则）必须同源：顺序颠倒（先 seen
// 后适用性）会让最新旧域行短路较旧的适用行，整条规则被跳过——物化端有测试
// 钉住，对账端漏同步即静默失效。
//
// 机制：
//   - 选择单源：两处都必须调用 latestApplicableACMECertMaterials，源码里不得再
//     出现自建的「JOIN lb_rules + ORDER BY j.updated_at DESC」选择查询；
//   - 写判据差异必须显式留痕：reconcileMissingCertFiles 的文档必须写明「不比对
//     内容/权限」，否则读者会把它当成与物化同判据而据此推断行为。

import (
	"os"
	"strings"
	"testing"
)

func TestLatestApplicableACMECertSelection_hasSingleSource(t *testing.T) {
	for _, source := range []struct {
		file     string
		function string
	}{
		{"certstore.go", "MaterializeAllCertsFromDB"},
		{"certificates.go", "reconcileMissingCertFiles"},
	} {
		body := declarationText(t, source.file, source.function)
		if !strings.Contains(body, "latestApplicableACMECertMaterials(") {
			t.Errorf("%s 未调用 latestApplicableACMECertMaterials：每规则最新适用行的选择在该落点被重新内联", source.function)
		}
		if strings.Contains(body, "ORDER BY j.updated_at DESC") || strings.Contains(body, "ORDER BY j.rule_id") {
			t.Errorf("%s 仍自带行选择 SQL：选择必须单源", source.function)
		}
	}

	// 对账侧「只按存在性判定」必须写进文档：这是与物化（内容+权限判 changed）
	// 的口径差异，不能靠读代码推断。
	data, err := os.ReadFile("certificates.go")
	if err != nil {
		t.Fatalf("read certificates.go: %v", err)
	}
	text := string(data)
	docStart := strings.Index(text, "// reconcileMissingCertFiles ")
	if docStart < 0 {
		t.Fatal("certificates.go 未找到 reconcileMissingCertFiles 文档注释")
	}
	docEnd := strings.Index(text[docStart:], "func reconcileMissingCertFiles(")
	if docEnd < 0 {
		t.Fatal("reconcileMissingCertFiles 文档与函数声明之间结构异常")
	}
	if doc := text[docStart : docStart+docEnd]; !strings.Contains(doc, "不比对内容") {
		t.Errorf("reconcileMissingCertFiles 文档未声明「不比对内容」的口径差异:\n%s", doc)
	}
}
