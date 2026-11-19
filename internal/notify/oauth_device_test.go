package notify

// SMTP OAuth2 设备码协议回归（RFC 8628）：DeviceCodeStart 成功/缺 client_id；
// DeviceCodePoll 全状态（authorization_pending→completed / slow_down /
// expired_token / invalid_grant / 缺 refresh_token）。端点经 var 覆写为 httptest。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func useDeviceEndpointMock(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	old := oauthDeviceEndpoint
	oauthDeviceEndpoint = func(string) string { return srv.URL }
	t.Cleanup(func() { oauthDeviceEndpoint = old; srv.Close() })
}

func TestDeviceCodeStart_Success(t *testing.T) {
	useDeviceEndpointMock(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("client_id") != "cid" {
			t.Errorf("client_id=%q, want cid", r.PostForm.Get("client_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"DC","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`))
	})
	dc, err := DeviceCodeStart(context.Background(), "cid", "common", "")
	if err != nil {
		t.Fatalf("DeviceCodeStart: %v", err)
	}
	if dc.DeviceCode != "DC" || dc.UserCode != "ABCD-EFGH" || dc.VerificationURI != "https://microsoft.com/devicelogin" || dc.Interval != 5 {
		t.Errorf("设备码字段不符: %+v", dc)
	}
}

func TestDeviceCodeStart_MissingClientID(t *testing.T) {
	if _, err := DeviceCodeStart(context.Background(), "", "common", ""); err == nil {
		t.Fatalf("缺 client_id 应返回错误")
	}
}

func TestDeviceCodePoll_StateMachine(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus string
		wantToken  string
		wantErrSub string
	}{
		{"pending", `{"error":"authorization_pending"}`, "pending", "", ""},
		{"slow_down", `{"error":"slow_down"}`, "slow_down", "", ""},
		{"expired", `{"error":"expired_token"}`, "expired", "", ""},
		{"invalid_grant", `{"error":"invalid_grant","error_description":"declined"}`, "error", "", "invalid_grant"},
		{"completed", `{"access_token":"AT","refresh_token":"RT","expires_in":3600}`, "completed", "RT", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useOAuthTokenMock(t, func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
					t.Errorf("grant_type=%q, want device_code", r.PostForm.Get("grant_type"))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			res, err := DeviceCodePoll(context.Background(), "cid", "common", "DC")
			if err != nil {
				t.Fatalf("DeviceCodePoll: %v", err)
			}
			if res.Status != tc.wantStatus {
				t.Errorf("status=%q, want %q", res.Status, tc.wantStatus)
			}
			if res.RefreshToken != tc.wantToken {
				t.Errorf("refresh_token=%q, want %q", res.RefreshToken, tc.wantToken)
			}
			if tc.wantErrSub != "" && !strings.Contains(res.Error, tc.wantErrSub) {
				t.Errorf("error=%q, want 含 %q", res.Error, tc.wantErrSub)
			}
		})
	}
}

func TestDeviceCodePoll_CompletedMissingRefreshToken(t *testing.T) {
	useOAuthTokenMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","expires_in":3600}`))
	})
	// scope 缺 offline_access → 无 refresh_token → fail-loud
	if _, err := DeviceCodePoll(context.Background(), "cid", "common", "DC"); err == nil {
		t.Fatalf("completed 缺 refresh_token 应返回错误")
	}
}
