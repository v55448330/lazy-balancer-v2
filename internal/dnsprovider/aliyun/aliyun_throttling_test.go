package aliyun

// throttlingTransport 的限流判定匹配钉测。
//
// 历史形态是紧凑字节匹配（`"Code":"Throttling` 前缀）——依赖 Alidns 错误体
// 的紧凑 JSON 序列化（冒号后无空白）。厂商对序列化空白的承诺不可离线实证
// （标 INFERENCE 项）：保守修复 = 紧凑字节匹配保留为快路径，未命中时按
// JSON 解析 Code 字段再判定（与 parseAPIError 同形态），两类路径都不命中
// 才按普通 400 透传。改写语义不变：body 原样保留（错误解析仍读真实
// Code/Message），只改状态码。

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// passthroughTransport 记录响应状态与 body 后原样返回（快路径断言用）。
type passthroughTransport struct {
	responseBody string
}

func (t *passthroughTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(t.responseBody))),
		Request:    request,
	}, nil
}

func TestThrottlingTransport_rewriteForms(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want429 bool
	}{
		{"紧凑序列化", `{"Code":"Throttling","Message":"Request throttled.","RequestId":"r"}`, true},
		{"带空白序列化", `{"Code": "Throttling", "Message": "Request throttled.", "RequestId": "r"}`, true},
		{"Throttling 子码", `{"Code":"Throttling.SlowDown","Message":"slow down","RequestId":"r"}`, true},
		{"非限流 400 原样透传", `{"Code":"InvalidRecordId","Message":"not found","RequestId":"r"}`, false},
		{"非 JSON 网关错误页透传", `<html>gateway error</html>`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &throttlingTransport{base: &passthroughTransport{responseBody: tc.body}}
			response, err := transport.RoundTrip(httptest.NewRequest(http.MethodPost, "https://alidns.aliyuncs.com/", nil))
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			defer response.Body.Close()
			wantStatus := http.StatusBadRequest
			if tc.want429 {
				wantStatus = http.StatusTooManyRequests
			}
			if response.StatusCode != wantStatus {
				t.Fatalf("status=%d, want %d", response.StatusCode, wantStatus)
			}
			// body 原样保留：错误解析仍读到真实 Code/Message。
			body, readErr := io.ReadAll(response.Body)
			if readErr != nil {
				t.Fatalf("read body: %v", readErr)
			}
			if string(body) != tc.body {
				t.Fatalf("body=%q, want 原样保留 %q", body, tc.body)
			}
		})
	}
}
