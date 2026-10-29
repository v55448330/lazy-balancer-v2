package acme

// 账户密钥生命周期守卫：`removeStaleAccountKeys` 的删除分支在「账户密钥路径
// 公式含 directory|email|KID|HMAC 摘要」下恒不可达（metadata == 本任务元数据
// 即 metadataPath 就是本账户密钥文件），陈旧密钥永不回收——保留一套永不执行
// 的清理机制只会让人误以为存在回收能力（并配三条只测该不可达函数的用例）。
// 裁定是「轮换后的旧 HMAC 密钥必须保留」（不同账户身份），因此清理机制整体
// 退役，裁定注释上移到 accountKeyMetadata 作为后续维护的依据。
//
// 守卫双向：①源码里重新出现清理机制（函数声明/注册后调用）= 有人复活了
// 不可达路径（FAIL）；②accountKeyMetadata 的文档丢失「旧 HMAC 密钥必须保留」
// 裁定 = 退役理由被抹掉，后续维护者会再次尝试加回清理（FAIL）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

const accountKeyRetentionRuling = "旧 HMAC 密钥必须保留"

func TestAccountKeyLifecycle_hasNoUnreachableStaleCleanup(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "client.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse client.go: %v", err)
	}

	var metadataDoc string
	retired := map[string]bool{
		"removeStaleAccountKeys":    false,
		"removeStaleAccountKeyPair": false,
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.FuncDecl:
			if _, tracked := retired[typed.Name.Name]; tracked {
				retired[typed.Name.Name] = true
			}
		case *ast.GenDecl:
			// 单条 type 声明的文档注释挂在 GenDecl 上，多条的挂在 TypeSpec 上。
			for _, spec := range typed.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != "accountKeyMetadata" {
					continue
				}
				if typeSpec.Doc != nil {
					metadataDoc = typeSpec.Doc.Text()
				}
				if metadataDoc == "" && typed.Doc != nil {
					metadataDoc = typed.Doc.Text()
				}
			}
		}
		return true
	})
	for name, declared := range retired {
		if declared {
			t.Errorf("client.go 仍声明 %s：账户密钥路径公式下其删除分支恒不可达，"+
				"陈旧密钥永不回收——清理机制应整体退役（裁定：%s）", name, accountKeyRetentionRuling)
		}
	}
	if metadataDoc == "" {
		t.Fatal("accountKeyMetadata 缺少文档注释：保留裁定必须在该类型上留痕")
	}
	if !strings.Contains(metadataDoc, accountKeyRetentionRuling) {
		t.Errorf("accountKeyMetadata 文档未重申「%s」裁定: %q", accountKeyRetentionRuling, metadataDoc)
	}
}
