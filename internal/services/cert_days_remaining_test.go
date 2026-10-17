package services

// 第 76 轮 CERT 域冗余收敛：剩余天数口径单一出口钉。原 certjobs/certinfo/
// certificates/admintls/helpers 五份同表达式（R66/R67 已统一为向零截断），
// CertDaysRemaining 固化单一出口——回归口径：未过期 23h→0、恰好 48h→2、
// 过期 1 天 3 小时→-1（向零截断非 floor 的判别形态：-27h→-1 而 floor 会
// 给 -2）；过期判定不以返回值 ≤0 兼判（-1h→0）。

import (
	"log"
	"strings"
	"testing"
	"time"
)

func TestCertDaysRemaining_truncationTowardZero(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		offset time.Duration
		want   int
	}{
		{"未过期23小时向零截断为0", 23 * time.Hour, 0},
		{"恰好48小时为2", 48 * time.Hour, 2},
		{"过期1小时仍为0", -1 * time.Hour, 0},
		{"过期27小时为-1非floor", -27 * time.Hour, -1},
		{"恰好48小时前为-2", -48 * time.Hour, -2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CertDaysRemaining(now.Add(tc.offset), now); got != tc.want {
				t.Fatalf("CertDaysRemaining(offset=%v)=%d, want %d", tc.offset, got, tc.want)
			}
		})
	}
}

// L04-02（第 78 轮）：cert_renewal_days 读侧——库值 0/负值（带外直写/导入
// 遗留）此前静默改 30，无任何可观测痕迹；读取失败分支已 error 留痕，非法值
// 分支必须同口径显性留痕（值 + 降级结果），再取治理默认 30。
func TestGetCertRenewalDays_logsNonPositiveStoredValue(t *testing.T) {
	_, database := newClusterTestService(t)
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	for _, days := range []int{0, -5} {
		buf.Reset()
		if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=? WHERE id=1", days); err != nil {
			t.Fatalf("seed cert_renewal_days=%d: %v", days, err)
		}

		// When
		got := GetCertRenewalDays()

		// Then：返回治理默认 30，且 error 级留痕含库值与字段名
		if got != 30 {
			t.Fatalf("cert_renewal_days=%d: GetCertRenewalDays()=%d, want 30", days, got)
		}
		if !strings.Contains(buf.String(), "cert_renewal_days") || !strings.Contains(buf.String(), "ERROR") || !strings.Contains(buf.String(), "30") {
			t.Fatalf("cert_renewal_days=%d: log=%q, want error 级留痕（字段名 + 降级值）", days, buf.String())
		}
	}

	// 回归形状：合法值原样生效且不告警
	buf.Reset()
	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=45 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := GetCertRenewalDays(); got != 45 {
		t.Fatalf("GetCertRenewalDays()=%d, want 45", got)
	}
	if strings.Contains(buf.String(), "ERROR") {
		t.Fatalf("合法值不应告警，log=%q", buf.String())
	}
}
