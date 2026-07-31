package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDBQueryNotFoundDistinguishesMissingRowsFromDatabaseErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "missing", err: fmt.Errorf("query: %w", sql.ErrNoRows), want: http.StatusNotFound},
		{name: "database failure", err: errors.New("database is closed"), want: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(response)
			if !dbQueryNotFound(context, tt.err, "not found", "test query") {
				t.Fatal("error was not handled")
			}
			if response.Code != tt.want {
				t.Fatalf("status=%d, want %d", response.Code, tt.want)
			}
		})
	}
}

func TestIDHandlersRejectNonPositiveIDs(t *testing.T) {
	h := &Handlers{}
	tests := []struct {
		name   string
		method string
		path   string
		route  string
		handle gin.HandlerFunc
	}{
		{name: "get cert job", method: http.MethodGet, path: "/jobs/0", route: "/jobs/:id", handle: h.GetCertJob},
		{name: "get cert job logs", method: http.MethodGet, path: "/jobs/-1/logs", route: "/jobs/:id/logs", handle: h.GetCertJobLogs},
		{name: "get CA provider", method: http.MethodGet, path: "/ca/0", route: "/ca/:id", handle: h.GetCAProvider},
		{name: "update CA provider", method: http.MethodPut, path: "/ca/-1", route: "/ca/:id", handle: h.UpdateCAProvider},
		{name: "test CA provider", method: http.MethodPost, path: "/ca/0/test", route: "/ca/:id/test", handle: h.TestCAProvider},
		{name: "registration status", method: http.MethodGet, path: "/registration/0", route: "/registration/:id", handle: h.GetClusterRegistrationStatus},
		{name: "test certificate config", method: http.MethodPost, path: "/certificate-configs/0/test", route: "/certificate-configs/:id/test", handle: h.TestCertificateConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Handle(tt.method, tt.route, tt.handle)
			request := httptest.NewRequest(tt.method, tt.path, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
		})
	}
}
