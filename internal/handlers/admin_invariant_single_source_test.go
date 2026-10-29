package handlers

// 「至少保留一个启用管理员」不变量的判定必须单源：三个写端点（管理员改角色、
// 启停、删除用户）此前各写了一套 SQL——两处内联 EXISTS 谓词、一处独立 COUNT
// 查询，三份实现各自演化且并发网只覆盖了其中一条路径（改角色）。
// 本文件同时给出：
//  1. 结构守卫：判定谓词只允许出现在 ensureOtherEnabledAdmin 内，且三个
//     handler 都必须经它判定；
//  2. 行为网：两个启用管理员并发互删 → 一个 200、一个 409，最终仍保留 1 个
//     启用管理员（删除路径此前没有任何并发覆盖）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// enabledAdminInvariantPredicate 是「除本人之外还有启用管理员」的判定片段
// （单源 SQL 只允许在 ensureOtherEnabledAdmin 内出现一次）。
const enabledAdminInvariantPredicate = `id <> ? AND role = 'admin' AND is_enabled = 1`

func TestEnabledAdminInvariantIsSingleSource(t *testing.T) {
	source, err := os.ReadFile("users.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(source), enabledAdminInvariantPredicate); got != 1 {
		t.Fatalf("不变量谓词出现 %d 次，want 仅 ensureOtherEnabledAdmin 内一次（三处写路径必须共用同一判定）", got)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "users.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	callers := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "ensureOtherEnabledAdmin" {
				callers[fn.Name.Name] = true
			}
			return true
		})
	}
	for _, handler := range []string{"UpdateUser", "ToggleUserStatus", "DeleteUser"} {
		if !callers[handler] {
			t.Errorf("%s 未经 ensureOtherEnabledAdmin 判定「至少保留一个启用管理员」", handler)
		}
	}
}

// TestDeleteUser_concurrentMutualDeletionKeepsOneAdministrator 两个启用管理员
// 同时互删（各删对方）：写事务经 DSN 的 immediate 事务锁串行化，先到的成功，
// 后到的必须 409，最终启用管理员数量恒为 1。
func TestDeleteUser_concurrentMutualDeletionKeepsOneAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "bystander", "user", true) // 占位（非 admin，不参与计数）
	seedUserAuditTest(t, 3, "admin-3", "admin", true)
	seedUserAuditTest(t, 4, "admin-4", "admin", true)

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var workers sync.WaitGroup
	for _, pair := range [][2]int{{3, 4}, {4, 3}} { // (操作者, 目标)
		workers.Add(1)
		go func(actor, target int) {
			defer workers.Done()
			<-start
			response := serveUserMutation(h, http.MethodDelete, "/users/"+strconv.Itoa(target), "", actor, h.DeleteUser)
			statuses <- response.Code
		}(pair[0], pair[1])
	}
	close(start)
	workers.Wait()
	close(statuses)

	seenOK, seenConflict := false, false
	for status := range statuses {
		seenOK = seenOK || status == http.StatusOK
		seenConflict = seenConflict || status == http.StatusConflict
	}
	if !seenOK || !seenConflict {
		t.Fatalf("并发互删要求一个 200 与一个 409")
	}
	var admins int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin' AND is_enabled=1").Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins != 1 {
		t.Fatalf("enabled administrators=%d, want 1", admins)
	}
}
