package services

// 结构化 CRS 规则索引的解析与缓存重建测试（自 70fb0c37 恢复，剥离参数级
// 豁免部分）。索引消费方三条——GET /security/crs/rule-index 端点、保存侧
// 6 位 ID/组号存在性校验与 BuildCorazaDirectives 的混合展开/陈旧过滤，
// 各处必须命中同一份缓存。

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seedCRSRuleIndexFixture 在临时目录写入两个 CRS 形态的 conf 文件并覆盖
// CRSRuleIndexDir（导出的测试缝）。返回目录路径。
// 文件 A（排序靠前）：多行反斜杠续行形态，含单引号 msg（带转义引号）与
// 被注释掉的规则；文件 B：单行形态 + 双引号 msg + 与文件 A 重复的规则 ID。
func seedCRSRuleIndexFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fileA := `# spam comment mentioning id:999999 that must be ignored
SecRule REQUEST_HEADERS:Accept "@rx ^.*$" \
    "id:920120,\
    phase:2,\
    pass,\
    msg:'User-Agent: Missing Accept\' Header',\
    tag:'protocol-structure'"

# SecRule REQUEST_URI "@rx ." "id:999998,phase:1,pass,msg:'commented out'"
SecRule &REQUEST_HEADERS:Accept "@eq 0" "id:920100,phase:1,log,deny,status:406,msg:'Request Missing an Accept Header'"
`
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-920-PROTOCOL-ANOMALY.conf"), []byte(fileA), 0o644); err != nil {
		t.Fatalf("seed file A: %v", err)
	}
	fileB := `SecRule ARGS "@rx (?i)union.*select" "id:942100,phase:2,block,msg:\"SQL Injection Attack Detected\""
SecRule ARGS_NAMES "@rx ^id$" "id:942550,phase:2,pass,msg:'SQLi benchmark'"
SecRule ARGS "@rx dup" "id:920100,phase:2,pass,msg:'duplicate id keeps first msg'"
`
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), []byte(fileB), 0o644); err != nil {
		t.Fatalf("seed file B: %v", err)
	}
	oldDir := CRSRuleIndexDir
	CRSRuleIndexDir = dir
	t.Cleanup(func() { CRSRuleIndexDir = oldDir })
	return dir
}

func findIndexEntry(t *testing.T, index *CRSRuleIndex, id string) *CRSRuleIndexEntry {
	t.Helper()
	for i := range index.Rules {
		if index.Rules[i].ID == id {
			return &index.Rules[i]
		}
	}
	return nil
}

func TestGetCRSRuleIndex_parsesAndSortsFixture(t *testing.T) {
	seedCRSRuleIndexFixture(t)

	index := GetCRSRuleIndex()

	// 排序：id 升序（字符串序对六位数字等价数值序）
	wantOrder := []string{"920100", "920120", "942100", "942550"}
	if len(index.Rules) != len(wantOrder) {
		t.Fatalf("rules = %+v, want %d entries", index.Rules, len(wantOrder))
	}
	for i, want := range wantOrder {
		if index.Rules[i].ID != want {
			t.Fatalf("rules[%d].ID = %q, want %q (full: %+v)", i, index.Rules[i].ID, want, index.Rules)
		}
	}

	// 多行续行形态：单引号 msg + 转义引号还原
	e := findIndexEntry(t, index, "920120")
	if e == nil {
		t.Fatalf("920120 missing: %+v", index.Rules)
	}
	if e.Msg != "User-Agent: Missing Accept' Header" {
		t.Fatalf("920120 msg = %q, want unescaped single-quote form", e.Msg)
	}
	if e.File != "REQUEST-920-PROTOCOL-ANOMALY.conf" || e.Category != "协议异常" {
		t.Fatalf("920120 file/category = (%q,%q)", e.File, e.Category)
	}

	// 单行形态：双引号 msg
	e = findIndexEntry(t, index, "942100")
	if e == nil {
		t.Fatalf("942100 missing: %+v", index.Rules)
	}
	if e.Msg != `SQL Injection Attack Detected` {
		t.Fatalf("942100 msg = %q, want double-quoted content", e.Msg)
	}
	if e.Category != "SQL 注入" {
		t.Fatalf("942100 category = %q, want SQL 注入", e.Category)
	}

	// 注释行内的 id:999999/999998 必须被剔除
	if findIndexEntry(t, index, "999999") != nil || findIndexEntry(t, index, "999998") != nil {
		t.Fatalf("commented rule ids leaked into index: %+v", index.Rules)
	}

	// 重复 ID（920100 出现在 A、B 两文件）：保留首个 msg（文件名排序靠前的 A）
	e = findIndexEntry(t, index, "920100")
	if e == nil || e.Msg != "Request Missing an Accept Header" || e.File != "REQUEST-920-PROTOCOL-ANOMALY.conf" {
		t.Fatalf("duplicate id 920100 must keep first occurrence, got %+v", e)
	}

	// 存在性查询
	if !index.Has("942550") || index.Has("999999") {
		t.Fatalf("Has() lookup broken for 942550/999999")
	}
}

func TestGetCRSRuleIndex_cacheRebuildOnMtimeTouch(t *testing.T) {
	dir := seedCRSRuleIndexFixture(t)

	first := GetCRSRuleIndex()
	if findIndexEntry(t, first, "943100") != nil {
		t.Fatalf("fixture must not contain 943100: %+v", first.Rules)
	}

	// 改写文件内容（新增规则）并显式前移 mtime——mtime+size 进入缓存键，
	// 键变 → 重建；命中旧缓存则新规则不可见。
	path := filepath.Join(dir, "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf")
	content := `SecRule REQUEST_COOKIE "@rx sess" "id:943100,phase:2,pass,msg:'Session Fixation'"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("append fixture: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("bump mtime: %v", err)
	}

	second := GetCRSRuleIndex()
	if findIndexEntry(t, second, "943100") == nil {
		t.Fatalf("cache must rebuild on mtime/size change, 943100 missing: %+v", second.Rules)
	}

	// 版本行变化同样触发重建：键含 security_crs_version 行值。
	// （版本读取在 db.DB 为 nil 时回落 ""；此处只验证同键命中缓存的稳定性：
	//   不改文件再取一次，两个指针必须共享同一份缓存实例。）
	again := GetCRSRuleIndex()
	if again != second {
		t.Fatalf("unchanged key must hit cache (identity), got distinct instances")
	}
}

func TestGetCRSRuleIndex_missingDirYieldsEmptyRules(t *testing.T) {
	oldDir := CRSRuleIndexDir
	CRSRuleIndexDir = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { CRSRuleIndexDir = oldDir })

	index := GetCRSRuleIndex()
	if index == nil || index.Rules == nil || len(index.Rules) != 0 {
		t.Fatalf("missing dir must yield empty non-nil rules, got %+v", index)
	}
	if index.Has("942100") {
		t.Fatalf("empty index must not report any id")
	}
}
