package handlers

// v2.4.5：auth.user_updated 只在角色/显示名实际变更时发布（纯启停走
// auth.user_status_changed，不双发）。

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/notify"
)

func TestUpdateUser_publishesProfileChangeOnly(t *testing.T) {
	delta := func(t *testing.T, body string) int64 {
		t.Helper()
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 1, "admin", "admin", true)
		seedUserAuditTest(t, 2, "target", "user", true)
		before := notify.DroppedCount()
		rec := serveUserMutationAs(h, http.MethodPut, "/users/2", body, 1, "admin", h.UpdateUser)
		if rec.Code != http.StatusOK {
			t.Fatalf("body=%s status=%d resp=%s", body, rec.Code, rec.Body.String())
		}
		return notify.DroppedCount() - before
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
		before := notify.DroppedCount()
		rec := serveUserMutationAs(h, http.MethodPatch, "/users/me", body, 5, "user", h.UpdateCurrentUser)
		if rec.Code != http.StatusOK {
			t.Fatalf("body=%s status=%d resp=%s", body, rec.Code, rec.Body.String())
		}
		return notify.DroppedCount() - before
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
