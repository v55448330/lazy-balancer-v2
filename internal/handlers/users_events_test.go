package handlers

// v2.4.5：auth.user_updated 只在角色/显示名实际变更时发布（纯启停走
// auth.user_status_changed，不双发）。

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// assertNotifyBusUnassembled 显式核验本包条数断言的前提：测试进程内全局通知
// 总线未装配，因而 notify.Publish 对每个目录内事件都计入 DroppedCount（可用作
// 「发布条数」观测）。前提被破坏时立即报红，而不是让断言静默失真。
func assertNotifyBusUnassembled(t *testing.T) {
	t.Helper()
	before := notify.DroppedCount()
	notify.Publish(notify.Event{Type: notify.EvtUserUpdated})
	if got := notify.DroppedCount() - before; got != 1 {
		t.Fatalf("测试前提失效：全局 notify 总线已被装配（Publish 未计入 DroppedCount）——本包用例依赖 Publish 在未装配总线下计数；检查是否有 notify.Start/Bootstrap 被测试调用")
	}
}

// capturePublishedEvents 在断言窗口内捕获运行日志并统计发布条数：
//   - 返回值 = DroppedCount 差值（未装配总线下 = 目录内事件发布条数）；
//   - 日志出现「不在目录中」即失败——把「发布了未登记事件类型、被 Publish 静默
//     丢弃」也纳入判别，而不是像旧断言一样让这种实现错误恰好计 0 判绿。
func capturePublishedEvents(t *testing.T, run func()) int64 {
	t.Helper()
	assertNotifyBusUnassembled(t)
	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldOutput)
	before := notify.DroppedCount()
	run()
	published := notify.DroppedCount() - before
	if strings.Contains(logs.String(), "不在目录中") {
		t.Fatalf("发布的事件类型不在 notify 目录（被静默丢弃）:\n%s", logs.String())
	}
	return published
}

// TestHandlersTestsNeverAssembleNotifyBus 静态守卫：全局总线由进程启动链
// （cmd/server/main.go 的 notify.Bootstrap）唯一装配。测试若装配它，
// DroppedCount 不再代表发布条数，上面两条用例的前提即被打破——这里用
// 静态扫描把「无意引入」变成编译后的测试失败。
func TestHandlersTestsNeverAssembleNotifyBus(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	// 拼接 needle，避免本文件自身的字面量命中扫描。
	needles := []string{"notify." + "Start(", "notify." + "Bootstrap(", "notify." + "Stop("}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		source, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		for _, needle := range needles {
			if bytes.Contains(source, []byte(needle)) {
				t.Errorf("%s 调用了 %s——全局通知总线只允许由 cmd/server 启动链装配（否则本包发布条数断言失效）", name, needle)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何测试文件——静态守卫会静默恒绿")
	}
}

func TestUpdateUser_publishesProfileChangeOnly(t *testing.T) {
	delta := func(t *testing.T, body string) int64 {
		t.Helper()
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 1, "admin", "admin", true)
		seedUserAuditTest(t, 2, "target", "user", true)
		return capturePublishedEvents(t, func() {
			rec := serveUserMutationAs(h, http.MethodPut, "/users/2", body, 1, "admin", h.UpdateUser)
			if rec.Code != http.StatusOK {
				t.Fatalf("body=%s status=%d resp=%s", body, rec.Code, rec.Body.String())
			}
		})
	}

	if got := delta(t, `{"display_name":"新昵称","role":"admin"}`); got != 1 {
		t.Fatalf("角色+显示名变更发布 %d 条事件, want 1（user_updated）", got)
	}
	if got := delta(t, `{"role":"admin"}`); got != 1 {
		t.Fatalf("角色变更发布 %d 条事件, want 1", got)
	}
	// 无实际变更（空 display_name 与库中空值相同、role 缺省）：不发。
	if got := delta(t, `{"display_name":""}`); got != 0 {
		t.Fatalf("无变更提交发布 %d 条事件, want 0", got)
	}
	// 纯改密：由密码事件族承载，不并入 user_updated。
	if got := delta(t, `{"password":"StrongPass123!"}`); got != 0 {
		t.Fatalf("纯改密发布 %d 条事件, want 0（避免双发）", got)
	}
}

func TestUpdateCurrentUser_selfProfileAndPasswordEvents(t *testing.T) {
	// 自助改显示名 → user_updated（1 条）；自助改密 → password_changed（1 条）；
	// 两者同提 → 2 条（互不吞并、不双发 user_updated）。
	delta := func(t *testing.T, body string) int64 {
		t.Helper()
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 5, "self", "user", true)
		hash, err := bcrypt.GenerateFromPassword([]byte("OldPass123!"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`UPDATE users SET password_hash=? WHERE id=5`, string(hash)); err != nil {
			t.Fatal(err)
		}
		return capturePublishedEvents(t, func() {
			rec := serveUserMutationAs(h, http.MethodPatch, "/users/me", body, 5, "user", h.UpdateCurrentUser)
			if rec.Code != http.StatusOK {
				t.Fatalf("body=%s status=%d resp=%s", body, rec.Code, rec.Body.String())
			}
		})
	}
	if got := delta(t, `{"display_name":"新昵称"}`); got != 1 {
		t.Fatalf("自助改显示名发布 %d 条事件, want 1（user_updated）", got)
	}
	if got := delta(t, `{"password":"StrongPass123!","current_password":"OldPass123!"}`); got != 1 {
		t.Fatalf("自助改密发布 %d 条事件, want 1（password_changed，不得双发 user_updated）", got)
	}
	if got := delta(t, `{"display_name":"新昵称","password":"StrongPass123!","current_password":"OldPass123!"}`); got != 2 {
		t.Fatalf("昵称+密码同提发布 %d 条事件, want 2（两事件各一条）", got)
	}
}
