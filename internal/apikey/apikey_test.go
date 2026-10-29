package apikey

import (
	"net/http"
	"testing"
)

const sampleJWTBearer = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"

// TestFromHeader_extractionRules 钉住「认证侧接受 ⇔ 转发侧可提取」的唯一规则
// 来源：两处调用（REST 认证中间件 / MCP 内部转发）都不再各自解析请求头。
func TestFromHeader_extractionRules(t *testing.T) {
	cases := []struct {
		name          string
		apiKeyHeader  string
		authorization string
		want          string
	}{
		{"x-api-key wins", "lb_sk_direct", "Bearer lb_sk_other", "lb_sk_direct"},
		{"x-api-key trims surrounding whitespace", " \tlb_sk_direct \t", "", "lb_sk_direct"},
		{"blank x-api-key falls back to bearer", " \t ", "Bearer lb_sk_bearer", "lb_sk_bearer"},
		{"blank x-api-key without bearer", " \t", "", ""},
		{"bearer api key", "", "Bearer lb_sk_bearer", "lb_sk_bearer"},
		// 方案与凭据之间多写空白的手工客户端（"Bearer   <key>"）必须照常
		// 提取：凭据拿去哈希比对，残留空白会表现为「密钥无效」，把排障方向
		// 从格式误导到密钥本身。
		{"extra spaces after scheme", "", "Bearer   lb_sk_spaces", "lb_sk_spaces"},
		{"trailing whitespace", "", "Bearer lb_sk_trailing \t", "lb_sk_trailing"},
		{"tab separator", "", "Bearer\tlb_sk_tab", "lb_sk_tab"},
		{"no separator", "", "Bearerlb_sk_nosep", ""},
		{"empty token", "", "Bearer   ", ""},
		{"scheme only", "", "Bearer", ""},
		{"lowercase bearer api key", "", "bearer lb_sk_lower", "lb_sk_lower"},
		{"uppercase bearer api key", "", "BEARER lb_sk_upper", "lb_sk_upper"},
		{"jwt bearer is not api key", "", sampleJWTBearer, ""},
		{"bare api key without scheme", "", "lb_sk_bare", ""},
		{"empty request", "", "", ""},
	}
	for _, tc := range cases {
		header := http.Header{}
		if tc.apiKeyHeader != "" {
			header.Set("X-API-Key", tc.apiKeyHeader)
		}
		if tc.authorization != "" {
			header.Set("Authorization", tc.authorization)
		}
		if got := FromHeader(header); got != tc.want {
			t.Errorf("%s: FromHeader = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestIsAPIKeyAuthorization_matchesFromHeader 是两侧语义等价的绊线：认证侧用
// IsAPIKeyAuthorization 区分「API Key Bearer」与「JWT Bearer」，转发侧用
// FromHeader 提取——两者对同一 header 的判断必须一致，否则出现「认证通过但
// 转发提取为空」。
func TestIsAPIKeyAuthorization_matchesFromHeader(t *testing.T) {
	for _, authorization := range []string{
		"Bearer lb_sk_abc",
		sampleJWTBearer,
		"bearer lb_sk_abc",
		"lb_sk_abc",
		"",
	} {
		header := http.Header{"Authorization": []string{authorization}}
		extracted := FromHeader(header) != ""
		if decided := IsAPIKeyAuthorization(authorization); decided != extracted {
			t.Errorf("Authorization=%q: IsAPIKeyAuthorization=%v but FromHeader extracts=%v", authorization, decided, extracted)
		}
	}
}
