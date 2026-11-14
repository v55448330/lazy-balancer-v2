package cloudflare

// 账户级验证回退的独立时间预算钉测。
//
// 用户级 verify 返回「值无效」后，VerifyToken 枚举 /accounts 并逐账户打
// /accounts/{id}/tokens/verify。回退链没有独立预算时，无效 Token + 慢端点
// 会让保存请求挂起「账户数 × 单请求重试包络」——数十分钟级。回退必须有
// 自己的时间上界（与 services 侧保存前探针的基础预算×重试包络同口径），
// 且以调用方请求 ctx 为上界（客户端断开立即中止）。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// slowAccountVerifyTransport 包装真实底座：用户级 verify 立即返回 400
// code=9109（值无效信号，触发账户级回退）；/accounts 枚举正常透传；
// 账户级 verify 端点挂起 delay 后才响应——构造「无效 Token + 慢端点」形态。
// verifyCalls 统计账户级 verify 请求次数。
type slowAccountVerifyTransport struct {
	base        http.RoundTripper
	delay       time.Duration
	verifyCalls atomic.Int64
}

func (tr *slowAccountVerifyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	path := request.URL.Path
	switch {
	case strings.HasSuffix(path, "/user/tokens/verify"):
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":9109,"message":"Invalid API Token"}],"messages":[],"result":null}`)),
			Request:    request,
		}, nil
	case strings.Contains(path, "/accounts/") && strings.HasSuffix(path, "/tokens/verify"):
		tr.verifyCalls.Add(1)
		select {
		case <-time.After(tr.delay):
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		return tr.base.RoundTrip(request)
	default:
		return tr.base.RoundTrip(request)
	}
}

// 无效 Token + 慢账户级端点：回退必须在独立预算内收手（不得逐账户跑满
// 重试包络）。预算收窄到毫秒级保持墙钟快速；生产预算口径由常量钉住。
func TestProvider_VerifyToken_accountFallbackStopsWithinBudget(t *testing.T) {
	s := newCloudflareTestServer(t)
	accounts := make([]string, 50)
	for i := range accounts {
		accounts[i] = fmt.Sprintf("acc%02d", i)
	}
	s.accounts = accounts
	// 全部账户非 active：回退必须逐账户尝试——预算缺失时会跑满全部账户
	// （每个挂起 delay），而不是首个账户即通过。
	s.accountVerify = make(map[string]string, len(accounts))
	for _, id := range accounts {
		s.accountVerify[id] = "disabled"
	}
	p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
	slow := &slowAccountVerifyTransport{base: p.client.Transport, delay: 200 * time.Millisecond}
	p.client.Transport = slow

	oldBudget := accountVerifyFallbackBudget
	accountVerifyFallbackBudget = 50 * time.Millisecond
	t.Cleanup(func() { accountVerifyFallbackBudget = oldBudget })

	start := time.Now()
	err := p.VerifyToken(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("无效 Token 必须验证失败")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want 预算耗尽（context.DeadlineExceeded）", err)
	}
	// 预算 50ms + 单次慢端点 200ms 的上界内必须收手——不得逐账户挂起。
	if elapsed > time.Second {
		t.Fatalf("elapsed=%v, want 预算内收手（回退无独立预算会逐账户挂起）", elapsed)
	}
	if calls := slow.verifyCalls.Load(); calls > 2 {
		t.Fatalf("account verify calls=%d, want ≤2（预算耗尽即停止逐账户尝试）", calls)
	}
}

// 回归形状：预算充足时账户级回退照常工作（任一 active 即通过），不得因
// 预算引入误伤。
func TestProvider_VerifyToken_accountFallbackSucceedsWithinBudget(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.accounts = []string{"acc1", "acc2"}
	s.accountVerifyStatus = map[string]int{"acc1": http.StatusForbidden}
	p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
	p.client.Transport = &slowAccountVerifyTransport{base: p.client.Transport, delay: time.Millisecond}

	oldBudget := accountVerifyFallbackBudget
	accountVerifyFallbackBudget = 5 * time.Second
	t.Cleanup(func() { accountVerifyFallbackBudget = oldBudget })

	if err := p.VerifyToken(context.Background()); err != nil {
		t.Fatalf("VerifyToken（acc2 active 须通过）: %v", err)
	}
}

// 调用方请求 ctx 是回退的上界：客户端断开/取消必须立即中止逐账户尝试，
// 不得跑满内部预算。
func TestProvider_VerifyToken_accountFallbackRespectsCallerCancel(t *testing.T) {
	s := newCloudflareTestServer(t)
	s.accounts = []string{"acc1", "acc2", "acc3"}
	p := newCloudflareTestProvider(t, "cfat_"+strings.Repeat("a", 40), s)
	p.client.Transport = &slowAccountVerifyTransport{base: p.client.Transport, delay: 200 * time.Millisecond}

	oldBudget := accountVerifyFallbackBudget
	accountVerifyFallbackBudget = 10 * time.Second
	t.Cleanup(func() { accountVerifyFallbackBudget = oldBudget })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := p.VerifyToken(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("取消后必须验证失败")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Fatalf("elapsed=%v, want 取消立即中止", elapsed)
	}
}
