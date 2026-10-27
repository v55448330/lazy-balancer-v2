package retryafter

import (
	"math"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// 表驱动用例覆盖两个消费方共享的全部形态：delay-seconds（含前导空白以外的
// 整数形态）、HTTP-date 的未来/过去、空串与垃圾输入、非正秒数。
func TestParse(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	future := now.Add(90 * time.Second).Format(http.TimeFormat)
	past := now.Add(-90 * time.Second).Format(http.TimeFormat)

	cases := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"empty", "", 0},
		{"seconds", "120", 120 * time.Second},
		{"zero seconds", "0", 0},
		{"negative seconds", "-5", 0},
		{"leading space is not a number", " 30", 0},
		{"garbage", "soon", 0},
		{"http date future", future, 90 * time.Second},
		{"http date past", past, 0},
		{"rfc850 future", now.Add(30 * time.Second).Format(time.RFC850), 30 * time.Second},
		{"ansi c future", now.Add(45 * time.Second).Format(time.ANSIC), 45 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Parse(tc.header, now); got != tc.want {
				t.Fatalf("Parse(%q, now)=%v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

// 边界：HTTP-date 恰好等于 now 时不返回负值（下游 >0 判断据此放行重试）。
func TestParse_httpDateEqualToNowIsZero(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if got := Parse(now.Format(http.TimeFormat), now); got != 0 {
		t.Fatalf("Parse(now)=%v, want 0", got)
	}
}

// 超大秒数的乘法溢出：time.Duration 是 int64 纳秒，`seconds * time.Second` 会
// 绕回——可解析的异常上游值（如 18446744074 → 约 290ms、9223372037 → 负值）
// 会让退避从「长期等待」变成「立刻重试」，反而加剧限流。超界必须饱和为最大
// 时长，由消费方既有的 3h/30s 上限继续收敛。
func TestParse_saturatesOverflowingSeconds(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	maxSeconds := int64(math.MaxInt64 / int64(time.Second))

	cases := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"max safe seconds", strconv.FormatInt(maxSeconds, 10), time.Duration(maxSeconds) * time.Second},
		{"one second past safe", strconv.FormatInt(maxSeconds+1, 10), time.Duration(math.MaxInt64)},
		{"wraps to negative", "9223372037", time.Duration(math.MaxInt64)},
		{"wraps to sub-second", "18446744074", time.Duration(math.MaxInt64)},
		{"max int", strconv.FormatInt(math.MaxInt64, 10), time.Duration(math.MaxInt64)},
		{"ordinary seconds unaffected", "120", 120 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.header, now)
			if got != tc.want {
				t.Fatalf("Parse(%q)=%v, want %v", tc.header, got, tc.want)
			}
			if got < 120*time.Second {
				t.Fatalf("Parse(%q)=%v：溢出绕回成短等待", tc.header, got)
			}
		})
	}
}

// 超出 int64 的 delay-seconds：Atoi 失败曾让它落进 HTTP-date 分支并最终归零，
// 语义从「长期退避」翻转成「立刻重试」——比可解析的溢出更危险（后者至少走了
// 钳制）。超界必须饱和为最大时长；负向超界仍是「非正值」语义，按零处理。
func TestParse_saturatesSecondsBeyondInt64(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"one past int64", "9223372036854775808", time.Duration(math.MaxInt64)},
		{"far past int64", "99999999999999999999", time.Duration(math.MaxInt64)},
		{"negative beyond int64 stays non-positive", "-99999999999999999999", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Parse(tc.header, now); got != tc.want {
				t.Fatalf("Parse(%q)=%v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
