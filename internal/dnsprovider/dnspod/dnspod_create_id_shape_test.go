package dnspod

// Record.Create 响应 record.id 形态钉测（与 Record.List / Domain.List 的
// id 读取同口径）：数字 id（官方形态）与带引号数字 id（历史变体）都必须
// 原样读出；空串 id 是畸形形态——必须走 createRecord 的显式空检查
// （"returned no record ID"），不得让整个响应解码失败把显式检查变不可达。

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// createIDShapeProvider 构造按原始 JSON token 下发 Record.Create record.id
// 的 provider：复用扫描（Record.List）按空结果（code 10）放行，Record.Remove
// 的 record_id 留档到 removes 供清理终态断言。
func createIDShapeProvider(t *testing.T, idToken string, removes *[]string) *Provider {
	t.Helper()
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "9"})
	provider := New("id,token")
	provider.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		params, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		responseBody := `{"status":{"code":"1","message":"ok"}}`
		switch {
		case strings.HasSuffix(request.URL.Path, "Record.List"):
			responseBody = `{"status":{"code":"10","message":"empty"}}`
		case strings.HasSuffix(request.URL.Path, "Record.Create"):
			responseBody = `{"status":{"code":"1","message":"ok"},"record":{"id":` + idToken + `}}`
		case strings.HasSuffix(request.URL.Path, "Record.Remove"):
			*removes = append(*removes, params.Get("record_id"))
		}
		return progressTestJSONResponse(request, responseBody), nil
	})
	return provider
}

func TestProvider_createRecord_idShapes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		idToken string
		wantID  string
		wantErr string
	}{
		{"numeric id", `321`, "321", ""},
		{"quoted numeric id", `"321"`, "321", ""},
		{"empty string id", `""`, "", "Record.Create returned no record ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var removes []string
			provider := createIDShapeProvider(t, tc.idToken, &removes)

			id, err := provider.createRecord(t.Context(), "example.com", "9", "_acme-challenge", "shape-value", 600)

			if tc.wantErr != "" {
				// 精确匹配显式错误文案：解码错误（decode Record.Create response…）
				// 不得冒充空 ID 检查。
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err=%v, want 显式空 ID 错误 %q（不得是解码错误）", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("createRecord: %v", err)
			}
			if id != tc.wantID {
				t.Fatalf("recordID=%q, want %q", id, tc.wantID)
			}
		})
	}
}

// 空串 id 走 Present 消费链：显式报错且不得登记为已归属（与缺 record.id
// 的 TestProvider_Present_createWithoutRecordIDFails 同族，形态互补）。
func TestProvider_Present_emptyCreateIDFailsWithoutOwnership(t *testing.T) {
	var removes []string
	provider := createIDShapeProvider(t, `""`, &removes)

	err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	if err == nil || !strings.Contains(err.Error(), "no record ID") {
		t.Fatalf("err=%v, want Record.Create returned no record ID", err)
	}
	provider.mu.Lock()
	owned := 0
	for _, entries := range provider.owned {
		owned += len(entries)
	}
	provider.mu.Unlock()
	if owned != 0 {
		t.Fatalf("owned records=%d, want 0（空 ID 记录不得登记为已归属）", owned)
	}
}

// 数字 id 端到端：Present 登记后 CleanUp 必须按创建返回的 id 发起删除并
// 排空内存兜底表——id 形态收敛不得破坏清理消费链。
func TestProvider_Present_numericCreateIDCleanUpDeletesCreatedRecord(t *testing.T) {
	var removes []string
	provider := createIDShapeProvider(t, `321`, &removes)

	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present: %v", err)
	}
	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("clean up: %v", err)
	}

	if !reflect.DeepEqual(removes, []string{"321"}) {
		t.Fatalf("Record.Remove record_ids=%v, want [321]（按创建返回的数字 id 删除）", removes)
	}
	provider.mu.Lock()
	left := len(provider.owned["9|_acme-challenge"])
	provider.mu.Unlock()
	if left != 0 {
		t.Fatalf("owned entries=%d, want 0（成功删除后兜底表排空）", left)
	}
}
