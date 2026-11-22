package notify

// 日报扩展数据源：进程运行时长、应用版本、认证日计数、REST 调用指针、
// 列表/字节/时长格式化。认证计数由 bus.Publish 对 auth.* 事件按本地日历日
// 分桶累加（日报次日读昨日桶，跨零点不丢）。

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

// authDayCount 单日登录成功/失败/MFA 失败的累加桶。
type authDayCount struct {
	ok   int64
	fail int64
	mfa  int64
}

// authCounters 按「本地日历日」分桶的认证事件计数（Publish 累加；进程内）。
// 按日分桶而非单日覆盖：日报在次日读「昨日」桶，旧实现的单日重置会让跨零点
// 后的读数把昨日统计清零（两日相互覆盖）。有界=只保留昨天及更晚的桶（删除
// 早于昨天的标签；时区变更带来的「未来」桶最多偏移一天，见 noteAuthEventAt）。
var authCounters struct {
	mu   sync.Mutex
	days map[string]authDayCount
}

// noteAuthEvent 由 Publish 调用：按日累加登录成功/失败/MFA 失败。
func noteAuthEvent(typ string) { noteAuthEventAt(typ, time.Now()) }

// noteAuthEventAt 带时刻的累加入口（测试缝：同一进程可构造跨日序列）。
func noteAuthEventAt(typ string, at time.Time) {
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
	date := at.In(dailyLocation()).Format("2006-01-02")
	authCounters.mu.Lock()
	defer authCounters.mu.Unlock()
	if authCounters.days == nil {
		authCounters.days = map[string]authDayCount{}
	}
	c := authCounters.days[date]
	switch kind {
	case 1:
		c.ok++
	case 2:
		c.fail++
	case 3:
		c.mfa++
	}
	authCounters.days[date] = c
	// 有界：日报只读昨日，保留昨天及更晚的桶即可（长跑进程不随天数无限增长）。
	// 不按「恰好 {date, date-1}」白名单删：时区变更（设置页切时区）会让本地
	// 日期标签整体前移——旧实现会把原时区下的「今天」桶（新时区下标签是明天）
	// 当陈旧数据删掉，昨日报告读数从 0 起算。保留 ≥ 昨天（含「未来」标签桶）
	// 只截断更早的桶；偏移最大一天，次日自然落到昨天/今天再被清理，仍然有界。
	prev := previousDailyDate(date)
	if prev == "" {
		return
	}
	for d := range authCounters.days {
		if d < prev {
			delete(authCounters.days, d)
		}
	}
}

// previousDailyDate 本地日历日的前一天标签（解析失败返回空串=不保留昨天）。
func previousDailyDate(date string) string {
	t, err := time.ParseInLocation("2006-01-02", date, dailyLocation())
	if err != nil {
		return ""
	}
	return t.AddDate(0, 0, -1).Format("2006-01-02")
}

// readAuthCounters 读指定日历日（"2006-01-02"）的认证计数；日报读 d.Date 当日。
// 计数是进程内状态：重启后当日/昨日桶从 0 起算（事实源为 auth 审计日志，
// 日报只作概览——与旧实现同边界，分桶修复不改变该限制）。
func readAuthCounters(date string) (ok, fail, mfa int64) {
	authCounters.mu.Lock()
	defer authCounters.mu.Unlock()
	c := authCounters.days[date]
	return c.ok, c.fail, c.mfa
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
	// 下界=now：已过期证书不属于「临期」，旧查询只有上界会把过期多年的一并
	// 列成临期（用户看到「还剩 -370 天」）。
	rows, err := db.DB.QueryContext(ctx, `SELECT domain, expires_at FROM cert_jobs
		WHERE status='issued' AND COALESCE(expires_at,'')<>'' AND expires_at>=? AND expires_at<=?
		ORDER BY expires_at LIMIT 5`, now.Format("2006-01-02 15:04:05"), limit)
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
	if len(parts) == 5 {
		// LIMIT 5 命中即提示截断（可能还有更多，用户知道去看证书页全量）。
		parts = append(parts, "（仅列前 5 条）")
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
