package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// 自助改密并发改写守卫：当前密码确认读落在事务外——
// 确认读之后、写事务 BEGIN 之前，管理员并发重置（password_version 抬升）
// 落库时，旧实现仍以旧 hash 验证通过并覆盖写新 hash（最终密码为后提交者，
// 双方各自 bump version——无提权，但「以当前密码确认」语义失效）。
// 修复=UPDATE 带 password_version 乐观守卫，版本被并发改写时 409 拒绝。
// 注入点=确认读之后、BeginTx 之前（DSN _txlock=immediate 使事务内写窗口
// 归零，残余竞态恰在此间隙；事务内再注入会撞 immediate 写锁 busy 等待）。

func TestUpdateCurrentUser_passwordConcurrentChangeRejected(t *testing.T) {
	database := setupAuthTestDB(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("first-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version) VALUES (1,'alice',?,'admin','Alice',1,4)`, string(hash)); err != nil {
		t.Fatal(err)
	}

	// 真实失败机制：第二条写入在确认读与事务之间提交（真实 DB 行改写，
	// 非 mock 返回值）——模拟管理员并发重置抬升 password_version。
	restore := updateUserPasswordRaceHook
	updateUserPasswordRaceHook = func() {
		if _, err := database.Exec(`UPDATE users SET password_version = 5 WHERE id = 1`); err != nil {
			t.Errorf("race injection: %v", err)
		}
	}
	t.Cleanup(func() { updateUserPasswordRaceHook = restore })

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"password":"second-password","current_password":"first-password"}`))
	request.Header.Set("Content-Type", "application/json")
	context, _ := gin.CreateTestContext(recorder)
	context.Request = request
	context.Set("user_id", 1)
	(&Handlers{}).UpdateCurrentUser(context)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（并发改写必须被乐观版本守卫拒绝）", recorder.Code, recorder.Body.String())
	}

	// 终态断言：并发写（v=5）不被覆盖，密码仍为 first-password。
	var version int
	var storedHash string
	if err := database.QueryRow(`SELECT password_version, password_hash FROM users WHERE id=1`).Scan(&version, &storedHash); err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Fatalf("password_version=%d, want 5（并发写保留，不得被本请求覆盖）", version)
	}
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte("first-password")) != nil {
		t.Fatal("并发改写后密码哈希不得被旧确认语义覆盖")
	}
}

// 回归形状：无并发时改密照常成功（守卫不影响正常路径）。
func TestUpdateCurrentUser_passwordChangeSucceedsWithoutConcurrency(t *testing.T) {
	database := setupAuthTestDB(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("first-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version) VALUES (1,'alice',?,'admin','Alice',1,4)`, string(hash)); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"password":"second-password","current_password":"first-password"}`))
	request.Header.Set("Content-Type", "application/json")
	context, _ := gin.CreateTestContext(recorder)
	context.Request = request
	context.Set("user_id", 1)
	(&Handlers{}).UpdateCurrentUser(context)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（无并发时正常改密）", recorder.Code, recorder.Body.String())
	}
	var version int
	if err := database.QueryRow(`SELECT password_version FROM users WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Fatalf("password_version=%d, want 5（4+1 正常递增）", version)
	}
}
