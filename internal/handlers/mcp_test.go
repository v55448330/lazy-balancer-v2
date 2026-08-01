package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/mcpserver"
)

func TestGetMCPTools_returns_complete_public_registry(t *testing.T) {
	// Given
	gin.SetMode(gin.TestMode)
	handler := NewHandlers(Dependencies{})
	router := gin.New()
	router.GET("/api/v1/mcp/tools", handler.GetMCPTools)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Code    int                  `json:"code"`
		Message string               `json:"message"`
		Data    []mcpserver.ToolSpec `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != 0 || body.Message == "" || len(body.Data) != len(mcpserver.ListToolSpecs()) {
		t.Fatalf("unexpected response: %+v", body)
	}
	var hasReadOnly, hasWrite bool
	for _, spec := range body.Data {
		hasReadOnly = hasReadOnly || spec.ReadOnly
		hasWrite = hasWrite || !spec.ReadOnly
	}
	if !hasReadOnly || !hasWrite {
		t.Fatalf("registry classifications read=%v write=%v", hasReadOnly, hasWrite)
	}
	if strings.Contains(response.Body.String(), "schema") {
		t.Fatalf("handler leaked internal schema: %s", response.Body.String())
	}
}
