package middleware

import (
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

// 请求日志格式串曾传入两次 param.Method——每行输出
// 形如「| GET | GET "/path"」，method 重复且占用了其他字段的列。钉死：
// method 与 path 各出现一次，列结构为 [time] status | latency | ip | METHOD "path"。
func TestRequestLogFormatterPrintsMethodAndPathOnce(t *testing.T) {
	line := requestLogFormatter(gin.LogFormatterParams{
		TimeStamp:  time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		Method:     "POST",
		StatusCode: 200,
		Latency:    1500 * time.Microsecond,
		ClientIP:   "192.0.2.1",
		Path:       "/api/v1/rules",
	})
	if n := strings.Count(line, "POST"); n != 1 {
		t.Fatalf("method 出现 %d 次，want 1（不得重复输出）: %q", n, line)
	}
	if n := strings.Count(line, `"/api/v1/rules"`); n != 1 {
		t.Fatalf("path 出现 %d 次，want 1: %q", n, line)
	}
	for _, column := range []string{" 200 ", "1.5ms", "192.0.2.1"} {
		if !strings.Contains(line, column) {
			t.Fatalf("缺少列 %q: %q", column, line)
		}
	}
}

func TestRequestLogFormatterOmitsQueryCredentials(t *testing.T) {
	line := requestLogFormatter(gin.LogFormatterParams{
		TimeStamp:  time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		Method:     "GET",
		StatusCode: 302,
		Latency:    time.Millisecond,
		ClientIP:   "192.0.2.1",
		Path:       "/api/v1/auth/oidc/callback?code=oidc-code-secret&state=oidc-state-secret",
	})
	for _, secret := range []string{"oidc-code-secret", "oidc-state-secret"} {
		if strings.Contains(line, secret) {
			t.Fatalf("query credential %q leaked into request log: %q", secret, line)
		}
	}
	if !strings.Contains(line, `"/api/v1/auth/oidc/callback"`) {
		t.Fatalf("route path missing after query redaction: %q", line)
	}
}

// c.Error() 附加的错误须有日志落点——formatter 尾部追加 ErrorMessage 列
// （有值才输出）；无错误时列结构不变（上方列结构钉测覆盖）。
func TestRequestLogFormatterAppendsErrorMessage(t *testing.T) {
	withErr := requestLogFormatter(gin.LogFormatterParams{
		TimeStamp:    time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		Method:       "POST",
		StatusCode:   500,
		Latency:      time.Millisecond,
		ClientIP:     "192.0.2.1",
		Path:         "/api/v1/rules",
		ErrorMessage: "集群版本触发器不可用",
	})
	if !strings.Contains(withErr, "集群版本触发器不可用") {
		t.Fatalf("ErrorMessage 未输出: %q", withErr)
	}
	withoutErr := requestLogFormatter(gin.LogFormatterParams{
		TimeStamp:  time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		Method:     "GET",
		StatusCode: 200,
		Latency:    time.Millisecond,
		ClientIP:   "192.0.2.1",
		Path:       "/api/v1/rules",
	})
	if strings.Count(withoutErr, "|") != 3 {
		t.Fatalf("无错误时列结构变化: %q（want 3 个分隔符，无尾部错误列）", withoutErr)
	}
}

func TestShouldLogRequestAppliesConfiguredThreshold(t *testing.T) {
	oldLevel, oldMode := services.CurrentLogLevel(), gin.Mode()
	t.Cleanup(func() {
		_ = services.ConfigureLogLevel(oldLevel)
		gin.SetMode(oldMode)
	})
	tests := []struct {
		name    string
		level   string
		status  int
		latency time.Duration
		want    bool
	}{
		{name: "info records successful request", level: "info", status: 200, want: true},
		{name: "warn filters routine success", level: "warn", status: 200, want: false},
		{name: "warn records client error", level: "warn", status: 404, want: true},
		{name: "warn records slow success", level: "warn", status: 200, latency: time.Second, want: true},
		{name: "error filters client error", level: "error", status: 404, want: false},
		{name: "error records server error", level: "error", status: 500, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			if err := services.ConfigureLogLevel(test.level); err != nil {
				t.Fatal(err)
			}

			// When
			got := shouldLogRequest(test.status, test.latency)

			// Then
			if got != test.want {
				t.Fatalf("shouldLogRequest(%d,%v)=%v, want %v", test.status, test.latency, got, test.want)
			}
		})
	}
}

func TestRequestLogThresholdTest_restoresLevelAndGinMode(t *testing.T) {
	oldLevel, oldMode := services.CurrentLogLevel(), gin.Mode()
	t.Cleanup(func() {
		_ = services.ConfigureLogLevel(oldLevel)
		gin.SetMode(oldMode)
	})

	for _, level := range []string{"warn", "debug"} {
		t.Run(level, func(t *testing.T) {
			if err := services.ConfigureLogLevel(level); err != nil {
				t.Fatal(err)
			}
			wantMode := gin.Mode()
			t.Run("threshold cases", TestShouldLogRequestAppliesConfiguredThreshold)
			if got := services.CurrentLogLevel(); got != level {
				t.Fatalf("清理后日志级别=%q, want %q", got, level)
			}
			if got := gin.Mode(); got != wantMode {
				t.Fatalf("清理后 Gin mode=%q, want %q", got, wantMode)
			}
		})
	}
}
