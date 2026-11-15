package services

// ApplyLogLevel 的句柄单快照契约：与同文件 refreshLocation 同形——
// nil 判定与查询必须针对同一个 *sql.DB 局部快照。db.DB 双读（判一次、
// 再读一次查询）在关停交错下第二次读可能已置 nil → nil 解引用 panic。
// 句柄未就绪（nil）时按默认级别应用，不读库。

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 关停尾部句柄已置 nil（db.Close 形态：DB 与 GetDB 同时清空）。
// When 装配点调用 ApplyLogLevel。
// Then 不 panic，按默认级别应用（nil 库不得触发读库）。
func TestApplyLogLevel_nilHandleAppliesDefaultWithoutPanic(t *testing.T) {
	snapshotLocationState(t)
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	db.DB, db.MetricsDB, db.AuditDB = nil, nil, nil
	db.SetDB(nil)
	t.Cleanup(func() {
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldCurrent)
	})
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })
	if err := ConfigureLogLevel("error"); err != nil {
		t.Fatal(err)
	}

	ApplyLogLevel() // nil 双读形态在此 panic（判 nil 后第二次读已置 nil）

	if got := CurrentLogLevel(); got != db.DefaultLogLevel {
		t.Fatalf("nil 库时日志级别=%q, want 默认 %q", got, db.DefaultLogLevel)
	}
}

// AST 守卫扩面至 tz.go：ApplyLogLevel 不得直接消费包级 db.DB——
// 必须取局部快照（database := db.DB 或 db.GetDB()）后对快照判 nil 与查询，
// 与 refreshLocation/引擎族同形（双读在关停交错下 nil 解引用）。
func TestApplyLogLevel_usesLocalHandleSnapshot(t *testing.T) {
	src := readServiceRepoFile(t, "tz.go")
	body, ok := goFuncBody(src, "func ApplyLogLevel(")
	if !ok {
		t.Fatal("tz.go 中找不到 ApplyLogLevel 函数体")
	}
	if containsBareDBRead(body) {
		t.Fatalf("ApplyLogLevel 仍直接读包级 db.DB（双读关停交错会 nil 解引用）——必须局部快照:\n%s", body)
	}
}

// containsBareDBRead 报告函数体是否直接消费 db.DB（快照赋值右侧除外）。
func containsBareDBRead(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		if comment := strings.Index(line, "//"); comment >= 0 {
			line = line[:comment] // 注释里的 db.DB 字样不是消费点
		}
		idx := 0
		for {
			pos := strings.Index(line[idx:], "db.DB")
			if pos < 0 {
				break
			}
			pos += idx
			// 「:= db.DB」/「= db.DB」是快照赋值本身，合法。
			prefix := strings.TrimRight(line[:pos], " \t")
			if !strings.HasSuffix(prefix, ":=") && !strings.HasSuffix(prefix, "=") {
				return true
			}
			idx = pos + len("db.DB")
		}
	}
	return false
}
