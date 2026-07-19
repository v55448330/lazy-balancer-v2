package middleware

import "testing"

func TestIsSynchronizedWrite_classifies_only_snapshot_content_mutations(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{"PUT", "/api/v1/config", true},
		{"POST", "/api/v1/config/preview", false},
		{"PUT", "/api/v1/caddy/config", true},
		{"POST", "/api/v1/rules", true},
		{"POST", "/api/v1/rules/cert-info", false},
		{"PATCH", "/api/v1/users/me", true},
		{"DELETE", "/api/v1/api-keys/:id", true},
		{"POST", "/api/v1/cluster/mode", false},
	}
	for _, test := range tests {
		if got := isSynchronizedWrite(test.method, test.path); got != test.want {
			t.Errorf("isSynchronizedWrite(%s %s)=%v, want %v", test.method, test.path, got, test.want)
		}
	}
}
