// Package retryafter 提供 Retry-After 头的唯一解析实现。
//
// 两个消费方（services 的 CA 限流冷却、dnsprovider/internal/retry 的 DNS API
// 重试）曾各写一份同语义实现，靠注释互相约束「任一侧变更 MUST 同步」——这类
// 约束没有机器拦截，一侧支持新形态（毫秒、负值处理）后另一侧会静默分叉，最终
// 表现为同一份 429 响应在证书域与 DNS 域得到不同退避时长。收敛为单源后两侧
// 只保留委托。
//
// 语义口径（改动此处即同时改变两个域）：接受 delay-seconds 与 HTTP-date；
// 空串、不可解析、非正值（零/负数秒、已过去的日期）一律归零。
package retryafter

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Parse 把 Retry-After 头值解析为等待时长；now 是 HTTP-date 分支的基准时刻
// （生产传 time.Now()，测试可注入固定时刻）。
func Parse(header string, now time.Time) time.Duration {
	if header == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(header, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		// 乘法前钳制：time.Duration 是 int64 纳秒，超出安全秒数的值会让
		// `seconds * time.Second` 绕回——18446744074 得到约 290ms、
		// 9223372037 得到负值，消费方（CA 冷却 3h 上限、DNS MaxBackoff）收到的
		// 退避会比上游要求的短几个数量级，异常限流下的重试反而更频繁。超界饱和
		// 为最大时长，由消费方既有的上限继续收敛。
		if seconds > math.MaxInt64/int64(time.Second) {
			return time.Duration(math.MaxInt64)
		}
		return time.Duration(seconds) * time.Second
	} else if errors.Is(err, strconv.ErrRange) {
		// 文本本身就超出 int64：它是「远大于任何上限」的 delay-seconds，不是
		// HTTP-date——若落到下面的 date 分支会归零（退避从长期等待翻转成立刻
		// 重试）。负向超界仍是「非正值」语义，按零处理。
		if strings.HasPrefix(strings.TrimSpace(header), "-") {
			return 0
		}
		return time.Duration(math.MaxInt64)
	}
	if date, err := http.ParseTime(header); err == nil {
		if until := date.Sub(now); until > 0 {
			return until
		}
	}
	return 0
}
