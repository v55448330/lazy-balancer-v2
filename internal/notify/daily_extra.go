package notify

// 日报扩展数据源：进程运行时长、应用版本、认证日计数、REST 调用指针、
// 列表/字节/时长格式化。认证计数由 bus.Publish 对 auth.* 事件累加（按日重置）。

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// processStartedAt 面板进程启动时刻（包初始化），日报「运行时长」单源。
var processStartedAt = time.Now()

// AppVersion 应用版本（ldflags 注入，由 cmd/server 启动时赋值；缺省 dev）。
var AppVersion = "dev"

// DailyRESTCalls 当日 REST 调用数指针（services 注入，避免 notify→services 循环）。
var DailyRESTCalls func() int64

type authDayCounters struct {
	mu   sync.Mutex
	date string
	ok   int64
	fail int64
	mfa  int64
}

var authCounters authDayCounters

// noteAuthEvent 由 Publish 调用：按日累加登录成功/失败/MFA 失败。
func noteAuthEvent(typ string) {
	var kind int // 0=忽略 1=ok 2=fail 3=mfa
	switch typ {
	case EvtLoginSuccess:
		kind = 1
	case EvtLoginFailed:
		kind = 2
	case EvtMFAVerifyFailed:
		kind = 3
	default:
		return
	}
	today := time.Now().Format("2006-01-02")
	authCounters.mu.Lock()
	defer authCounters.mu.Unlock()
	if authCounters.date != today {
		// 字段级重置（不可整体赋值换掉 mu——持锁期间换 mutex 致 defer unlock 未锁 panic）。
		authCounters.date = today
		authCounters.ok, authCounters.fail, authCounters.mfa = 0, 0, 0
	}
	switch kind {
	case 1:
		authCounters.ok++
	case 2:
		authCounters.fail++
	case 3:
		authCounters.mfa++
	}
}

func readAuthCounters() (ok, fail, mfa int64) {
	authCounters.mu.Lock()
	defer authCounters.mu.Unlock()
	return authCounters.ok, authCounters.fail, authCounters.mfa
}

// joinLimitRows 把 (label,count) 行集合格式化为多行列表（每行「label ×n」，空=无）。
// 多值拆行避免表格单元格挤排错乱；渲染层按通道形态展开（html=<br>、文本=独立行）。
func joinLimitRows(rows [][2]string) string {
	if len(rows) == 0 {
		return "无"
	}
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, r[0]+" ×"+r[1])
	}
	return strings.Join(parts, "\n")
}

// formatBytes 字节数→人类可读（GB/MB/KB/B）。
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// formatUptime 时长→「N 天 H 小时」/「H 小时 M 分」。
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	}
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%d 小时 %d 分", hours, mins)
}

// topPairs 执行 (label,count) 查询返回行集合（查询失败=空）。
func topPairs(ctx context.Context, query string, args ...any) [][2]string {
	rows, err := db.MetricsDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var label string
		var n int64
		if err := rows.Scan(&label, &n); err != nil {
			continue
		}
		if label == "" {
			label = "-"
		}
		out = append(out, [2]string{label, fmt.Sprintf("%d", n)})
	}
	return out
}

// certExpiringList 30 天内到期的已签发证书（域名 · 到期日，单行列表）。
func certExpiringList(ctx context.Context, now time.Time) string {
	limit := now.AddDate(0, 0, 30).Format("2006-01-02 15:04:05")
	rows, err := db.DB.QueryContext(ctx, `SELECT domain, expires_at FROM cert_jobs
		WHERE status='issued' AND COALESCE(expires_at,'')<>'' AND expires_at<=? ORDER BY expires_at LIMIT 5`, limit)
	if err != nil {
		return "无"
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var domain, exp string
		if err := rows.Scan(&domain, &exp); err != nil {
			continue
		}
		if t, err := time.Parse("2006-01-02 15:04:05", exp); err == nil {
			exp = t.Format("2006-01-02")
		}
		parts = append(parts, domain+" · "+exp)
	}
	if len(parts) == 0 {
		return "无"
	}
	return strings.Join(parts, "\n")
}

// threatDBVersion 威胁库当前版本（CRS + IP2Region）。
func threatDBVersion(ctx context.Context) string {
	var crs, ip string
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(version,'') FROM security_crs_version WHERE id=1`).Scan(&crs)
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(version,'') FROM security_ip2region_version WHERE id=1`).Scan(&ip)
	if crs == "" && ip == "" {
		return "未安装"
	}
	return fmt.Sprintf("CRS %s · IP库 %s", crs, ip)
}
