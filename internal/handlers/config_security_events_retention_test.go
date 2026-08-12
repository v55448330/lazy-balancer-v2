package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityEventsRetention_roundtrip_through_PUT_and_GET(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)
	updateRequest := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"source":"basic","security_events_retention_days":45,"security_events_retention_max":5000}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	router.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("update retention status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}

	// When
	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/config", nil))

	// Then
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get config status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	var body struct {
		Data struct {
			SecurityEventsRetentionDays int `json:"security_events_retention_days"`
			SecurityEventsRetentionMax  int `json:"security_events_retention_max"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResponse.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	if body.Data.SecurityEventsRetentionDays != 45 || body.Data.SecurityEventsRetentionMax != 5000 {
		t.Fatalf("retention roundtrip = %#v, want days=45 max=5000", body.Data)
	}
}

func TestUpdateConfig_rejectsNonPositiveSecurityEventsRetention(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	// When / Then: non-positive values are rejected with 400
	for _, payload := range []string{
		`{"source":"basic","security_events_retention_days":0}`,
		`{"source":"basic","security_events_retention_days":-3}`,
		`{"source":"basic","security_events_retention_max":0}`,
		`{"source":"basic","security_events_retention_max":-1}`,
	} {
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("payload %s: status=%d body=%s, want 400", payload, response.Code, response.Body.String())
		}
	}
}
