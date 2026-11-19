package notify

// SMTP OAuth2（XOAUTH2）令牌管理：Outlook/Office365 公共客户端设备码流。
// access_token 内存缓存 + 临期(<5min)刷新 + 互斥单飞（并发投递串行刷新，
// 首个刷新后其余命中缓存）；invalid_grant 等刷新失败 fail-loud（不静默回退
// 基本认证）。refresh_token 静态加密落库（secretbox），读路径解密。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 微软 identity platform v2.0 端点（var 供测试覆写）。
var (
	oauthTokenEndpoint = func(tenant string) string {
		return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)
	}
	oauthDeviceEndpoint = func(tenant string) string {
		return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", tenant)
	}
)

const (
	oauthDefaultTenant = "common"
	oauthDefaultScope  = "https://outlook.office365.com/SMTP.Send offline_access"
	oauthHTTPTimeout   = 15 * time.Second
)

// oauthConfig SMTP OAuth 配置（公共客户端：仅 client_id，无 secret）。
type oauthConfig struct {
	Tenant       string
	ClientID     string
	RefreshToken string
	Scope        string
}

func (c oauthConfig) configured() bool { return c.ClientID != "" && c.RefreshToken != "" }

func loadOAuthConfig() oauthConfig {
	kv := GetSettings(KeySMTPOAuthTenant, KeySMTPOAuthClientID, KeySMTPOAuthRefreshToken, KeySMTPOAuthScope)
	c := oauthConfig{
		Tenant:       kv[KeySMTPOAuthTenant],
		ClientID:     kv[KeySMTPOAuthClientID],
		RefreshToken: kv[KeySMTPOAuthRefreshToken],
		Scope:        kv[KeySMTPOAuthScope],
	}
	if c.Tenant == "" {
		c.Tenant = oauthDefaultTenant
	}
	if c.Scope == "" {
		c.Scope = oauthDefaultScope
	}
	return c
}

// OAuthConfigured SMTP OAuth 是否已配置（client_id + refresh_token 非空）。
func OAuthConfigured() bool { return loadOAuthConfig().configured() }

var (
	oauthMu     sync.Mutex
	oauthAccess string
	oauthExpiry time.Time
)

// OAuthAccessToken 取有效 access_token（缓存命中或刷新）。互斥单飞：并发
// 调用串行，首个刷新后其余 double-check 命中缓存。刷新失败 fail-loud。
func OAuthAccessToken(ctx context.Context) (string, error) {
	cfg := loadOAuthConfig()
	if !cfg.configured() {
		return "", fmt.Errorf("SMTP OAuth 未配置（client_id/refresh_token）")
	}
	oauthMu.Lock()
	defer oauthMu.Unlock()
	if oauthAccess != "" && time.Now().Before(oauthExpiry.Add(-5*time.Minute)) {
		return oauthAccess, nil
	}
	tok, exp, err := refreshOAuthToken(ctx, cfg)
	if err != nil {
		return "", err
	}
	oauthAccess, oauthExpiry = tok, exp
	return tok, nil
}

// invalidateOAuthToken 解绑/重授权时清空缓存。
func invalidateOAuthToken() {
	oauthMu.Lock()
	oauthAccess, oauthExpiry = "", time.Time{}
	oauthMu.Unlock()
}

// InvalidateOAuthToken 解绑/重授权清空令牌缓存（REST 侧跨包调用）。
func InvalidateOAuthToken() { invalidateOAuthToken() }

// SetOAuthEndpointsForTest 覆写设备码/令牌端点（跨包测试缝，返回还原函数）。
func SetOAuthEndpointsForTest(device, token func(string) string) func() {
	od, ot := oauthDeviceEndpoint, oauthTokenEndpoint
	oauthDeviceEndpoint, oauthTokenEndpoint = device, token
	invalidateOAuthToken()
	return func() { oauthDeviceEndpoint, oauthTokenEndpoint = od, ot; invalidateOAuthToken() }
}

// refreshOAuthToken grant_type=refresh_token 换新 access_token。
func refreshOAuthToken(ctx context.Context, cfg oauthConfig) (string, time.Time, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {cfg.ClientID},
		"refresh_token": {cfg.RefreshToken},
		"scope":         {cfg.Scope},
	}
	tok, exp, err := postOAuthToken(ctx, oauthTokenEndpoint(cfg.Tenant), form)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("SMTP OAuth 令牌刷新失败: %w", err)
	}
	return tok, exp, nil
}

// postOAuthToken POST 令牌端点（form-encoded），解析 access_token/expires_in
// 或 error/error_description（invalid_grant=refresh_token 失效需重授权）。
func postOAuthToken(ctx context.Context, endpoint string, form url.Values) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: oauthHTTPTimeout}).Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var pr struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &pr); err != nil {
		return "", time.Time{}, fmt.Errorf("令牌响应解析失败 status=%d: %.256s", resp.StatusCode, string(raw))
	}
	if pr.Error != "" {
		return "", time.Time{}, fmt.Errorf("%s: %s", pr.Error, pr.ErrorDescription)
	}
	if pr.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("令牌响应缺 access_token status=%d", resp.StatusCode)
	}
	if pr.ExpiresIn <= 0 {
		pr.ExpiresIn = 3600
	}
	return pr.AccessToken, time.Now().Add(time.Duration(pr.ExpiresIn) * time.Second), nil
}
