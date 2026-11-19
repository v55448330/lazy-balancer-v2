package notify

// 微信发送响应业务错误码回归（用户实测"提示发送成功但实际未收到"）：
// HTTP 200 仍可能 ret/errcode 非 0（context_token 过期等），须解析 body
// fail-loud，不能只查 HTTP 状态。-14=会话过期上抛 errWxSessionExpired。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendWxMessageParsesBusinessError(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantErr     bool
		wantSession bool
	}{
		{"success", `{"ret":0,"errmsg":"ok"}`, false, false},
		{"session_expired", `{"ret":-14,"errmsg":"session expired"}`, true, true},
		{"business_error", `{"ret":-1,"errmsg":"invalid context_token"}`, true, false},
		{"errcode_nonzero", `{"ret":0,"errcode":40001,"errmsg":"bad token"}`, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/ilink/bot/sendmessage") {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			cred := wxBotCred{Token: "T", BaseURL: srv.URL, AccountID: "B"}
			err := sendWxMessage(context.Background(), cred, "user1", "测试正文", "ctx-token")
			if tc.wantErr && err == nil {
				t.Fatalf("body=%s 应返回业务错误，got nil（误报成功）", tc.body)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("body=%s 应成功，got %v", tc.body, err)
			}
			if tc.wantSession && !errors.Is(err, errWxSessionExpired) {
				t.Errorf("ret=-14 应上抛 errWxSessionExpired, got %v", err)
			}
		})
	}
}
