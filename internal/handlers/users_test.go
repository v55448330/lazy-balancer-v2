package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestDeleteUser_deletesOwnedAPIKeys(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 2, "target", "user", true)
	if _, err := db.DB.Exec(`INSERT INTO api_keys (name,key_hash,key_prefix,created_by) VALUES ('owned','hash','prefix',2)`); err != nil {
		t.Fatal(err)
	}

	response := serveUserMutation(h, http.MethodDelete, "/users/2", "", 1, h.DeleteUser)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var users, keys int
	if err := db.DB.QueryRow("SELECT (SELECT COUNT(*) FROM users WHERE id=2), (SELECT COUNT(*) FROM api_keys WHERE created_by=2)").Scan(&users, &keys); err != nil {
		t.Fatal(err)
	}
	if users != 0 || keys != 0 {
		t.Fatalf("remaining users=%d keys=%d", users, keys)
	}
}

func TestDeleteUser_rejectsSelfDeletion(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	response := serveUserMutation(h, http.MethodDelete, "/users/1", "", 1, h.DeleteUser)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDeleteUser_rejectsLastEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	response := serveUserMutation(h, http.MethodDelete, "/users/1", "", 99, h.DeleteUser)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestToggleUserStatus_rejectsDisablingLastEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	response := serveUserMutation(h, http.MethodPut, "/users/1", `{"is_enabled":false}`, 1, h.ToggleUserStatus)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUpdateUser_rejectsDemotingLastEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	response := serveUserMutation(h, http.MethodPut, "/users/1", `{"role":"user"}`, 1, h.UpdateUser)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUpdateUser_concurrentDemotionsPreserveEnabledAdministrator(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-1", "admin", true)
	seedUserAuditTest(t, 2, "admin-2", "admin", true)

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var workers sync.WaitGroup
	for id := 1; id <= 2; id++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			<-start
			response := serveUserMutation(h, http.MethodPut, "/users/"+strconv.Itoa(id), `{"role":"user"}`, id, h.UpdateUser)
			statuses <- response.Code
		}(id)
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
		t.Fatalf("concurrent statuses require one 200 and one 409")
	}
	var admins int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin' AND is_enabled=1").Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins != 1 {
		t.Fatalf("enabled administrators=%d, want 1", admins)
	}
}

func TestLastAdministratorGuard_allowsChangeWhenAnotherEnabledAdministratorExists(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-1", "admin", true)
	seedUserAuditTest(t, 2, "admin-2", "admin", true)
	response := serveUserMutation(h, http.MethodPut, "/users/1", `{"is_enabled":false}`, 1, h.ToggleUserStatus)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUpdateUser_validatesUsernameLength(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)

	// When: 用户名过短
	response := serveUserMutation(h, http.MethodPut, "/users/1", `{"username":"ab"}`, 1, h.UpdateUser)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("short username status=%d body=%s, want 400", response.Code, response.Body.String())
	}

	// When: 用户名满足 min=3
	response = serveUserMutation(h, http.MethodPut, "/users/1", `{"username":"abc"}`, 1, h.UpdateUser)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("valid username status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func TestUpdateCurrentUser_validatesDisplayNameLength(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'current','old-hash','admin','Before')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.PATCH("/users/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })

	// When: display_name 超过 50 字符
	request := httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"display_name":"`+strings.Repeat("名", 51)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("51-char display_name status=%d body=%s, want 400", response.Code, response.Body.String())
	}

	// When: display_name 恰好 50 字符
	request = httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"display_name":"`+strings.Repeat("名", 50)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("50-char display_name status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func seedUserAuditTest(t *testing.T, id int, username, role string, enabled bool) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (?,?,?,?,?)", id, username, "hash", role, enabled); err != nil {
		t.Fatal(err)
	}
}

func serveUserMutation(h *Handlers, method, path, body string, actorID int, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	context.Request.Header.Set("Content-Type", "application/json")
	context.Params = gin.Params{{Key: "id", Value: strings.TrimPrefix(path, "/users/")}}
	context.Set("user_id", actorID)
	handler(context)
	return response
}
