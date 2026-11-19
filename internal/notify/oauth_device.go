package notify

// SMTP OAuth2 设备码流（RFC 8628，Outlook/Office365 公共客户端）：全程出站，
// 契合免公网形态（无 redirect_uri/入站回调）。DeviceCodeStart 申请 device_code
// +user_code+verification_uri；DeviceCodePoll 轮询令牌端点（authorization_pending
// 继续/slow_down 退避/expired_token 终止/成功下发 refresh_token）。端点经
// oauthDeviceEndpoint/oauthTokenEndpoint var 覆写供测试。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DeviceCode 设备码发起结果（面板展示 user_code+verification_uri 供用户同意）。
type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// DeviceCodeStart 申请设备码（client_id 必填；tenant/scope 缺省回落）。
func DeviceCodeStart(ctx context.Context, clientID, tenant, scope string) (*DeviceCode, error) {
	if clientID == "" {
		return nil, fmt.Errorf("请先填写应用程序（客户端）ID")
	}
	if tenant == "" {
		tenant = oauthDefaultTenant
	}
	if scope == "" {
		scope = oauthDefaultScope
	}
	form := url.Values{"client_id": {clientID}, "scope": {scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthDeviceEndpoint(tenant), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: oauthHTTPTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("设备码申请失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var pr struct {
		DeviceCode       string `json:"device_code"`
		UserCode         string `json:"user_code"`
		VerificationURI  string `json:"verification_uri"`
		ExpiresIn        int    `json:"expires_in"`
		Interval         int    `json:"interval"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &pr); err != nil {
		return nil, fmt.Errorf("设备码响应解析失败 status=%d: %.256s", resp.StatusCode, string(raw))
	}
	if pr.Error != "" {
		return nil, fmt.Errorf("设备码申请被拒: %s: %s", pr.Error, pr.ErrorDescription)
	}
	if pr.DeviceCode == "" || pr.UserCode == "" {
		return nil, fmt.Errorf("设备码响应缺 device_code/user_code status=%d", resp.StatusCode)
	}
	if pr.Interval <= 0 {
		pr.Interval = 5
	}
	return &DeviceCode{
		DeviceCode: pr.DeviceCode, UserCode: pr.UserCode, VerificationURI: pr.VerificationURI,
		ExpiresIn: pr.ExpiresIn, Interval: pr.Interval,
	}, nil
}

// DevicePollResult 设备码轮询结果。Status：pending（继续）/slow_down（退避）/
// completed（成功，RefreshToken 非空）/expired（设备码过期）/error（其它失败）。
type DevicePollResult struct {
	Status       string `json:"status"`
	RefreshToken string `json:"-"`
	ExpiresIn    int    `json:"-"`
	Error        string `json:"error,omitempty"`
}

// DeviceCodePoll 轮询设备码令牌（grant_type=device_code）。
func DeviceCodePoll(ctx context.Context, clientID, tenant, deviceCode string) (DevicePollResult, error) {
	if tenant == "" {
		tenant = oauthDefaultTenant
	}
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {clientID},
		"device_code": {deviceCode},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthTokenEndpoint(tenant), strings.NewReader(form.Encode()))
	if err != nil {
		return DevicePollResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: oauthHTTPTimeout}).Do(req)
	if err != nil {
		return DevicePollResult{}, fmt.Errorf("设备码轮询失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var pr struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &pr); err != nil {
		return DevicePollResult{}, fmt.Errorf("设备码令牌响应解析失败 status=%d: %.256s", resp.StatusCode, string(raw))
	}
	switch pr.Error {
	case "":
		if pr.RefreshToken == "" {
			return DevicePollResult{}, fmt.Errorf("设备码授权成功但缺 refresh_token（scope 需含 offline_access）")
		}
		return DevicePollResult{Status: "completed", RefreshToken: pr.RefreshToken, ExpiresIn: pr.ExpiresIn}, nil
	case "authorization_pending":
		return DevicePollResult{Status: "pending"}, nil
	case "slow_down":
		return DevicePollResult{Status: "slow_down"}, nil
	case "expired_token":
		return DevicePollResult{Status: "expired", Error: "设备码已过期，请重新发起授权"}, nil
	default:
		return DevicePollResult{Status: "error", Error: pr.Error + ": " + pr.ErrorDescription}, nil
	}
}
