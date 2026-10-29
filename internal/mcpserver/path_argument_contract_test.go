package mcpserver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForwardPathArgTrailingSlashIsRejected(t *testing.T) {
	for _, tc := range []struct {
		tool, arg, payload string
	}{
		{tool: "get_rule", arg: "caddy_id", payload: `{"caddy_id":%q}`},
		{tool: "delete_rule", arg: "caddy_id", payload: `{"caddy_id":%q}`},
		{tool: "update_rule", arg: "caddy_id", payload: `{"caddy_id":%q,"name":"changed"}`},
	} {
		for _, value := range []string{"lb_x/", " lb_x/ ", "lb_x//"} {
			t.Run(fmt.Sprintf("%s/%s", tc.tool, value), func(t *testing.T) {
				restCalls := 0
				rest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					restCalls++
					_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
				}))
				defer rest.Close()
				handler := NewForTest(rest.URL+"/api/v1", rest.Client())
				result := callTool(t, handler, tc.tool, fmt.Sprintf(tc.payload, value))
				if !strings.Contains(result, `"isError":true`) || !strings.Contains(result, "参数非法 "+tc.arg) {
					t.Fatalf("result=%q, want invalid path argument error", result)
				}
				if restCalls != 0 {
					t.Fatalf("upstream calls=%d, want 0", restCalls)
				}
			})
		}
	}
}
