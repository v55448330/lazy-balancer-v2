package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGlobalConfig_serializes_DNS_credentials(t *testing.T) {
	// Given
	config := GlobalConfig{DNSCredentials: "id,token"}

	// When
	data, err := json.Marshal(config)

	// Then
	if err != nil {
		t.Fatalf("marshal GlobalConfig: %v", err)
	}
	if !strings.Contains(string(data), `"dns_credentials":"id,token"`) {
		t.Fatalf("GlobalConfig JSON=%s, want DNS credentials", data)
	}
}
