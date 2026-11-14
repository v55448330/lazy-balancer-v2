package dnsprovider

// zone/domain ID 缓存多实现对齐守卫：dnspod 的 domainIDCache 与 cloudflare 的
// zoneIDCache 是有意保留的同构双实现（账户+zone→id 进程内 LRU 正缓存 + 短 TTL
// 负缓存；底层凭据形态与解析 API 不同，抽象共享的耦合成本高于重复成本）。
// 多实现的风险不是重复本身，而是**漂移**：只改一侧（如负缓存 TTL 语义、容量
// 淘汰口径、LRU 触碰时机、作废时正负缓存与使用序的清除范围）会让两家 provider
// 在同一配置错误/限流场景下的行为不同，而单侧测试永远绿。
//
// 本守卫把缓存骨架的函数体做成「命名归一后逐字相等」的钉：两侧函数体在
// domainID↔zoneID 命名替换后必须完全一致（空白无关），且容量/负 TTL 常量
// 取值必须相等。任一侧改语义必须同步另一侧与本守卫。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// zoneCacheSource 是缓存双实现的源文件（相对本包目录）。
var zoneCacheSource = map[string]string{
	"cloudflare": "cloudflare/cloudflare.go",
	"dnspod":     "dnspod/dnspod.go",
}

// zoneCacheFuncPairs 是必须逐字对齐的缓存函数对（dnspod 名 → cloudflare 名）。
var zoneCacheFuncPairs = [][2]string{
	{"domainIDCacheTouchLRU", "zoneIDCacheTouchLRU"},
	{"domainIDCacheEvictLRU", "zoneIDCacheEvictLRU"},
	{"getDomainIDCache", "getZoneIDCache"},
	{"putDomainIDCache", "putZoneIDCache"},
	{"invalidateDomainIDCache", "invalidateZoneIDCache"},
}

// zoneCacheConstPairs 是必须取值相等的容量常量对。
var zoneCacheConstPairs = [][2]string{
	{"domainIDCacheCapacity", "zoneIDCacheCapacity"},
}

// zoneCacheTTLPairs 是必须取值相等的负缓存 TTL 变量对（var 供测试收窄）。
var zoneCacheTTLPairs = [][2]string{
	{"domainIDNegativeTTL", "zoneIDNegativeTTL"},
}

// zoneCacheFuncBody 从源文件取函数体文本（AST 定位，注释与字符串内的花括号
// 不干扰边界）。
func zoneCacheFuncBody(t *testing.T, path, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		t.Fatalf("解析 %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(data[start:end])
	}
	t.Fatalf("%s 未找到函数 %s", path, name)
	return ""
}

// normalizeZoneCacheBody 把 dnspod 侧命名归一到 cloudflare 形态并折叠空白：
// 命名差异（domainID/zoneID、loginToken/apiToken）不是漂移，语义差异才是。
func normalizeZoneCacheBody(body string) string {
	body = strings.ReplaceAll(body, "domainID", "zoneID")
	body = strings.ReplaceAll(body, "domain_id", "zone_id")
	body = strings.ReplaceAll(body, "loginToken", "apiToken")
	return strings.Join(strings.Fields(body), " ")
}

// zoneCacheValueExpr 取包级常量/变量声明的右值表达式文本（AST 定位）。
func zoneCacheValueExpr(t *testing.T, path, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		t.Fatalf("解析 %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name || i >= len(vs.Values) {
					continue
				}
				start := fset.Position(vs.Values[i].Pos()).Offset
				end := fset.Position(vs.Values[i].End()).Offset
				return string(data[start:end])
			}
		}
	}
	t.Fatalf("%s 未找到常量/变量 %s", path, name)
	return ""
}

// TestZoneIDCacheImplementationsStayInSync 是缓存双实现对齐门禁：只改一侧的
// 缓存骨架（LRU 触碰/容量淘汰/负缓存清除/作废范围）或容量/TTL 取值必须在此
// 红灯，而不是在单家 provider 的线上行为里。
func TestZoneIDCacheImplementationsStayInSync(t *testing.T) {
	dnspodPath := zoneCacheSource["dnspod"]
	cloudflarePath := zoneCacheSource["cloudflare"]
	for _, pair := range zoneCacheFuncPairs {
		dnspodBody := normalizeZoneCacheBody(zoneCacheFuncBody(t, dnspodPath, pair[0]))
		cloudflareBody := normalizeZoneCacheBody(zoneCacheFuncBody(t, cloudflarePath, pair[1]))
		if dnspodBody != cloudflareBody {
			t.Fatalf("缓存骨架漂移 %s/%s（任一侧修改 LRU/容量/负缓存/作废逻辑时必须同步另一侧）:\n  dnspod:     %s\n  cloudflare: %s",
				pair[0], pair[1], dnspodBody, cloudflareBody)
		}
	}
	for _, pair := range zoneCacheConstPairs {
		dnspodValue := zoneCacheValueExpr(t, dnspodPath, pair[0])
		cloudflareValue := zoneCacheValueExpr(t, cloudflarePath, pair[1])
		if dnspodValue != cloudflareValue {
			t.Fatalf("缓存容量漂移 %s=%s / %s=%s（两侧必须同值）", pair[0], dnspodValue, pair[1], cloudflareValue)
		}
	}
	for _, pair := range zoneCacheTTLPairs {
		dnspodValue := zoneCacheValueExpr(t, dnspodPath, pair[0])
		cloudflareValue := zoneCacheValueExpr(t, cloudflarePath, pair[1])
		if dnspodValue != cloudflareValue {
			t.Fatalf("负缓存 TTL 漂移 %s=%s / %s=%s（两侧必须同值）", pair[0], dnspodValue, pair[1], cloudflareValue)
		}
	}
}

// TestZoneCacheNormalization_detectsSingleSideChanges 是守卫自检：归一比较器
// 必须能对单侧语义改动报红，否则真实源码对比恒绿是无 RED 能力的空转。
func TestZoneCacheNormalization_detectsSingleSideChanges(t *testing.T) {
	aligned := "func() { cache[key] = id; touchLRU(key); evictLRU() }"
	if normalizeZoneCacheBody(aligned) != normalizeZoneCacheBody(aligned) {
		t.Fatal("对齐样本被误判漂移")
	}
	// 命名差异不是漂移：domainID↔zoneID 归一后必须相等。
	dnspodForm := "func() { domainIDCache[key] = id; domainIDCacheTouchLRU(key) }"
	cloudflareForm := "func() { zoneIDCache[key] = id; zoneIDCacheTouchLRU(key) }"
	if normalizeZoneCacheBody(dnspodForm) != normalizeZoneCacheBody(cloudflareForm) {
		t.Fatal("命名差异被误判为语义漂移")
	}
	// 单侧语义改动必须可检出（漏掉容量淘汰）。
	dropped := "func() { zoneIDCache[key] = id; zoneIDCacheTouchLRU(key) }"
	if normalizeZoneCacheBody(aligned) == normalizeZoneCacheBody(dropped) {
		t.Fatal("单侧语义改动未被检出")
	}
}
