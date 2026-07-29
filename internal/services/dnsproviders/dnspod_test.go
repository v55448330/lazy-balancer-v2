package dnsproviders

import (
	"strings"
	"testing"
)

func TestDNSPod_Validate_rejects_whitespace_test_domain(t *testing.T) {
	// Given
	provider := &DNSPod{}
	credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}

	// When
	err := provider.Validate(credentials, "   ")

	// Then
	if err == nil || !strings.Contains(err.Error(), "测试域名不能为空") {
		t.Fatalf("validation error=%v, want empty-domain error", err)
	}
}
