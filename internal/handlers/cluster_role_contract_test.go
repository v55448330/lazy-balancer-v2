package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestRequireMasterResult_MachineErrorCodeTruthTable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		isMaster   bool
		err        error
		options    masterGateOptions
		wantAllow  bool
		wantStatus int
		wantCode   string
	}{
		{
			name:       "default master_required",
			options:    masterGateOptions{forbidden: "仅主节点"},
			wantStatus: http.StatusForbidden,
			wantCode:   "master_required",
		},
		{
			name:       "role query error has no role code",
			err:        errors.New("role db down"),
			options:    masterGateOptions{queryFailure: "角色查询失败", forbidden: "仅主节点"},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "master allowed",
			isMaster:   true,
			options:    masterGateOptions{forbidden: "仅主节点"},
			wantAllow:  true,
			wantStatus: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/test", nil)
			allowed := requireMasterResult(ctx, tc.isMaster, tc.err, tc.options)
			if allowed != tc.wantAllow || recorder.Code != tc.wantStatus {
				t.Fatalf("allowed=%v status=%d, want %v/%d", allowed, recorder.Code, tc.wantAllow, tc.wantStatus)
			}
			if got := recorder.Header().Get("X-LB-Error-Code"); got != tc.wantCode {
				t.Fatalf("X-LB-Error-Code=%q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestUpdateClusterSettings_RoleCheckPrecedesRequestSemantics(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/cluster/settings", h.UpdateClusterSettings)

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "empty object", body: `{}`},
		{name: "locked sync_users", body: `{"sync_users":false}`},
		{name: "invalid interval", body: `{"sync_interval":5}`},
	} {
		t.Run("slave "+tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s, want slave 403 before request-specific semantics", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("X-LB-Error-Code"); got != masterRequiredErrorCode {
				t.Fatalf("X-LB-Error-Code=%q, want %q", got, masterRequiredErrorCode)
			}
		})
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "empty object remains idempotent", body: `{}`, wantStatus: http.StatusOK},
		{name: "sync_users lock remains client error", body: `{"sync_users":false}`, wantStatus: http.StatusBadRequest},
		{name: "interval validation remains client error", body: `{"sync_interval":5}`, wantStatus: http.StatusBadRequest},
	} {
		t.Run("master "+tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPut, "/cluster/settings", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(recorder, request)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
		})
	}
}

func TestSetClusterMode_MissingSyncServiceReturnsUnavailable(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.syncService = nil
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/cluster/mode", h.SetClusterMode)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/cluster/mode", strings.NewReader(`{"mode":"slave","master_url":"https://master.example:8443","register_token":"one-time","node_name":"slave-a"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503 instead of nil syncService panic", recorder.Code, recorder.Body.String())
	}
	var isMaster bool
	if err := db.DB.QueryRow(`SELECT is_master FROM global_config WHERE id=1`).Scan(&isMaster); err != nil {
		t.Fatal(err)
	}
	if !isMaster {
		t.Fatal("missing syncService changed the local node role")
	}
}
