package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestConfigProxyTimeouts_roundtrip_through_PUT_and_GET(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)
	updateRequest := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"source":"caddy","proxy_dial_timeout":11,"proxy_response_header_timeout":22,"proxy_read_timeout":33,"proxy_write_timeout":44,"proxy_stream_timeout":55,"proxy_flush_interval":-1,"proxy_stream_close_delay":10}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	router.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("update proxy timeouts status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}

	// When
	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/config", nil))

	// Then
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get proxy timeouts status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	var body struct {
		Data struct {
			ProxyDialTimeout           int `json:"proxy_dial_timeout"`
			ProxyResponseHeaderTimeout int `json:"proxy_response_header_timeout"`
			ProxyReadTimeout           int `json:"proxy_read_timeout"`
			ProxyWriteTimeout          int `json:"proxy_write_timeout"`
			ProxyStreamTimeout         int `json:"proxy_stream_timeout"`
			ProxyFlushInterval         int `json:"proxy_flush_interval"`
			ProxyStreamCloseDelay      int `json:"proxy_stream_close_delay"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResponse.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	if body.Data.ProxyDialTimeout != 11 || body.Data.ProxyResponseHeaderTimeout != 22 || body.Data.ProxyReadTimeout != 33 || body.Data.ProxyWriteTimeout != 44 || body.Data.ProxyStreamTimeout != 55 || body.Data.ProxyFlushInterval != -1 || body.Data.ProxyStreamCloseDelay != 10 {
		t.Fatalf("proxy timeout roundtrip = %#v", body.Data)
	}
}
