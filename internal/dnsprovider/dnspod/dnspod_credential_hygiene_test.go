package dnspod

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// permissionDeniedTransport 模拟受限 Token：Domain.List 正常，
// Record.Create/Remove 恒返回 code 7（官方码表：You don't have the permission）。
type permissionDeniedTransport struct {
	mu        sync.Mutex
	listCalls int
	creates   int
	removes   int
}

func (transport *permissionDeniedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if _, err := io.Copy(io.Discard, request.Body); err != nil {
		return nil, err
	}
	if closeErr := request.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	transport.mu.Lock()
	switch {
	case strings.HasSuffix(request.URL.Path, "Domain.List"):
		transport.listCalls++
		responseBody = `{"status":{"code":"1","message":"ok"},"domains":[{"id":"7","name":"example.com"}],"info":{"domain_total":1}}`
	case strings.HasSuffix(request.URL.Path, "Record.Create"):
		transport.creates++
		responseBody = `{"status":{"code":"7","message":"没有权限"}}`
	case strings.HasSuffix(request.URL.Path, "Record.Remove"):
		transport.removes++
		responseBody = `{"status":{"code":"7","message":"没有权限"}}`
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

// code 7 是「没有权限」而非「域名不存在」——权限拒绝必须按普通失败上抛：
// 不作废 zone→domain_id 缓存、不触发全量 Domain.List 重扫、不重复写。
// （历史缺陷：code 7 误入域名失效分类，受限 Token 下一次权限错误被放大为
// 缓存抖动 + 双倍调用。）
func TestProvider_Present_permissionErrorDoesNotInvalidateDomainIDCache(t *testing.T) {
	// Given
	seedDomainIDCache(t, "id,token", map[string]string{})
	transport := &permissionDeniedTransport{}
	provider := New("id,token")
	provider.client.Transport = transport

	// When
	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then: plain failure, no stale classification, exactly one resolve + one create
	if err == nil {
		t.Fatal("权限拒绝必须上抛为普通错误")
	}
	if errors.Is(err, errStaleDomainID) {
		t.Fatalf("权限错误不得标记为域名失效: %v", err)
	}
	transport.mu.Lock()
	listCalls, creates := transport.listCalls, transport.creates
	transport.mu.Unlock()
	if listCalls != 1 {
		t.Fatalf("Domain.List calls=%d, want 1（权限错误不得作废缓存触发重扫）", listCalls)
	}
	if creates != 1 {
		t.Fatalf("Record.Create calls=%d, want 1（权限错误不得触发自愈重试）", creates)
	}
	// 缓存保持有效：第二次 Present 仍命中缓存（不再新增 Domain.List）
	_ = provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.listCalls != 1 {
		t.Fatalf("第二次 Present 后 Domain.List calls=%d, want 1（缓存不得被权限错误作废）", transport.listCalls)
	}
}

// ownership 模式下兜底表（Present 双失败回填的 owned 条目）仍以
// domainID+"|"+subDomain 为键——domain_id 自愈换代后，排空失败回填必须落在
// 新键，否则条目对后续清理永不可达（内存泄漏 + TXT 残留）。
func TestDNSPodCleanUp_ownershipModeFallbackEntryMigratesToFreshKey(t *testing.T) {
	// Given：ownership 模式 + 缓存的 domain_id 已陈旧（API 侧重建为 2）+
	// 兜底表携带陈旧键条目（Present 双失败回填形态）
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "1"})
	transport := &staleRemoveTransport{currentID: "1", records: map[string]string{}}
	provider, err := NewPersistent("id,token", t.TempDir())
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	provider.mu.Lock()
	provider.owned["1|_acme-challenge"] = []ownedRecord{{recordID: "300", value: "this-task"}}
	provider.mu.Unlock()
	transport.flipStaleDomain("1", "2", true) // 自愈后对新 ID 的删除也失败

	// When：清理触发陈旧自愈，但新 ID 删除仍失败 → 条目须回填到「新键」
	err = provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then
	if err == nil {
		t.Fatal("清理失败必须上抛")
	}
	provider.mu.Lock()
	_, underStaleKey := provider.owned["1|_acme-challenge"]
	freshEntries := provider.owned["2|_acme-challenge"]
	provider.mu.Unlock()
	if underStaleKey {
		t.Fatal("排空失败条目回填到自愈前的旧键——后续清理按新键查找将永不可达")
	}
	if len(freshEntries) != 1 || freshEntries[0].recordID != "300" {
		t.Fatalf("fresh key entries=%+v, want 回填条目 recordID=300", freshEntries)
	}

	// 恢复删除成功后再次清理：条目按新键可达并被删除
	transport.mu.Lock()
	transport.failFreshID = false
	transport.mu.Unlock()
	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("second clean up: %v", err)
	}
	transport.mu.Lock()
	removes := append([][2]string(nil), transport.removes...)
	transport.mu.Unlock()
	wantTail := [2]string{"2", "300"}
	if len(removes) == 0 || removes[len(removes)-1] != wantTail {
		t.Fatalf("Record.Remove sequence=%v, want 末次 %v（新键条目可重试删除）", removes, wantTail)
	}
	provider.mu.Lock()
	remaining := len(provider.owned["2|_acme-challenge"])
	provider.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("owned entries left=%d, want 0（删除成功后兜底表清空）", remaining)
	}
}

// HTTP 错误体取样可能回声请求表单里的 login_token（中间网关/WAF 拦截页形态）
// ——错误文案经 failJob 落任务日志（全体登录用户可读），凭据必须脱敏。
func TestSanitizeHTTPErrorBody(t *testing.T) {
	t.Run("回声凭据脱敏", func(t *testing.T) {
		body := `Bad Request: login_token=12345,s3cr3tkey&domain_id=9 rejected`
		got := sanitizeHTTPErrorBody(body)
		if strings.Contains(got, "s3cr3tkey") {
			t.Fatalf("凭据明文进入错误文案: %q", got)
		}
		if !strings.Contains(got, "login_token=***") || !strings.Contains(got, "domain_id=9") {
			t.Fatalf("脱敏后应保留排障上下文: %q", got)
		}
	})
	t.Run("异常分隔fail-closed", func(t *testing.T) {
		// 非 & 分隔的 login_token 形态正则不命中——宁可整段丢弃也不冒险放行。
		body := `echo: "login_token=12345,s3cr3tkey"`
		got := sanitizeHTTPErrorBody(body)
		if strings.Contains(got, "s3cr3tkey") {
			t.Fatalf("凭据明文进入错误文案: %q", got)
		}
	})
	t.Run("干净原文保留", func(t *testing.T) {
		body := "  gateway timeout from upstream  "
		if got := sanitizeHTTPErrorBody(body); got != "gateway timeout from upstream" {
			t.Fatalf("干净错误体被误伤: %q", got)
		}
	})
}

func TestProvider_apiCall_redactsEchoedLoginToken(t *testing.T) {
	provider := New("12345,s3cr3tkey")
	provider.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`Bad Gateway: login_token=12345,s3cr3tkey refused`)),
			Request:    request,
		}, nil
	})
	var result apiStatus
	err := provider.apiCall(t.Context(), "Record.Create", url.Values{}, &result)
	if err == nil {
		t.Fatal("5xx 必须返回错误")
	}
	if strings.Contains(err.Error(), "s3cr3tkey") {
		t.Fatalf("凭据随错误体进入错误链: %v", err)
	}
	if !strings.Contains(err.Error(), "login_token=***") {
		t.Fatalf("错误文案缺少脱敏标记: %v", err)
	}
}

// String/%+v 任何形态都不得回显凭据（导出字段时代一次误打印即泄密）。
func TestProvider_StringRedactsCredential(t *testing.T) {
	provider := New("12345,s3cr3tkey")
	for _, form := range []string{fmt.Sprintf("%s", provider), fmt.Sprintf("%+v", provider), provider.String()} {
		if strings.Contains(form, "s3cr3tkey") || strings.Contains(form, "12345,") {
			t.Fatalf("字符串形态泄露凭据: %q", form)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

// 凭据脱敏必须与回声的编码形态无关：已知明文定向替换覆盖 JSON 键值、无分隔
// 文案等任意形态；形态正则只是兜底。错误文案经 failJob 落 cert_jobs（全体
// 登录用户可读），任一形态漏脱敏即凭据泄露。
func TestSanitizeHTTPErrorBody_knownPlaintextCoversAnyShape(t *testing.T) {
	const secret = "12345,s3cr3tkeyvalue"
	cases := map[string]string{
		"JSON 键值":    `{"status":{"code":"6","message":"域名ID错误","login_token":"12345,s3cr3tkeyvalue"}}`,
		"JSON 数字 ID": `{"login_token": 12345, "message":"rejected"}`,
		"无分隔文案":      `credential 12345,s3cr3tkeyvalue rejected by upstream`,
		"仅令牌分段":      `echo: token s3cr3tkeyvalue not allowed`,
		"查询式冒号":      `login_token: 12345,s3cr3tkeyvalue`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got := sanitizeHTTPErrorBody(body, secret)
			if strings.Contains(got, "s3cr3tkeyvalue") {
				t.Fatalf("凭据明文进入错误文案: %q", got)
			}
			// JSON 数字 ID 形态不含已知明文，形态正则必须兜住。
			if name == "JSON 数字 ID" && strings.Contains(got, "12345") {
				t.Fatalf("login_token 形态未脱敏: %q", got)
			}
		})
	}
}

// 业务层 status.message（厂商/网关回声）与 HTTP 错误体必须共用同一脱敏口径：
// 三处 status.message 拼接点全部经 Provider.sanitizeMessage。
func TestProvider_businessMessageRedacted(t *testing.T) {
	const secret = "12345,s3cr3tkeyvalue"
	provider := New(secret)
	// 复用扫描（createRecord 内的 Record.List）走进程内缓存解析 domain_id，
	// 预置缓存让扫描直接命中 Record.List 分支（code 10 空结果放行）。
	seedDomainIDCache(t, secret, map[string]string{"example.com": "9"})
	provider.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		// code 6 只注入 Record.Create：复用扫描（Record.List）按空结果放行，
		// 让本用例继续覆盖 Record.Create 的 status.message 拼接点。
		if !strings.HasSuffix(request.URL.Path, "Record.Create") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"10","message":"无记录"}}`)),
				Request:    request,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"status":{"code":"6","message":"域名ID错误 login_token=` + secret + `"}}`)),
			Request: request,
		}, nil
	})
	_, err := provider.createRecord(t.Context(), "example.com", "9", "_acme-challenge", "value", 600)
	if err == nil {
		t.Fatal("业务码非 1 必须返回错误")
	}
	if strings.Contains(err.Error(), "s3cr3tkeyvalue") {
		t.Fatalf("业务层 message 凭据未脱敏: %v", err)
	}
	if !strings.Contains(err.Error(), "***") {
		t.Fatalf("错误文案缺少脱敏标记: %v", err)
	}
}
