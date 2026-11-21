package notify

// API 密钥临期预警巡检（apikey.expiry_warning）：周期任务每日扫描 7 天内到期
// 的启用密钥，逐键发布预警（参数序契约：1=名称 2=到期日 3=剩余天数）。

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

// apiKeyExpiryLayouts 到期时间解析布局。api_keys.expires_at 是 DATETIME 列：
// 写入走 time.Time（glebarez 驱动落 "2026-11-19 16:00:00+00:00"），历史行可能
// 是裸墙钟串；读回时 Scan 到 string 的形态随驱动/写入路径变化，逐布局宽容解析。
var apiKeyExpiryLayouts = []string{
	"2006-01-02 15:04:05",       // 裸墙钟（历史写入；按 UTC 解释，与旧行为一致）
	"2006-01-02 15:04:05Z07:00", // glebarez 读回形态（带空格 + 时区后缀）
	"2006-01-02 15:04:05.999999999Z07:00",
	time.RFC3339,          // 2006-01-02T15:04:05Z07:00
	"2006-01-02T15:04:05", // 无时区 RFC3339 形态
}

// apiKeyExpiryPrefixRE 日期时间前缀（截断时区/小数秒尾巴后的兜底重试）。
var apiKeyExpiryPrefixRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}`)

// parseAPIKeyExpiry 宽容解析到期时间：先按布局列表逐个试，失败再截断到日期
// 时间前缀重试（覆盖 "+00:00"/"-05:00" 等时区尾巴）。无时区的值按 UTC 解释
// （与旧实现 time.Parse 的语义一致，避免存量数据的到期日整体漂移）。
func parseAPIKeyExpiry(raw string) (time.Time, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range apiKeyExpiryLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	if prefix := apiKeyExpiryPrefixRE.FindString(s); prefix != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", strings.Replace(prefix, "T", " ", 1)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// apiKeyExpiryDays 剩余天数（本地日历日差，向上取整到日：当日到期=0、明日=1）。
// 旧实现 int(d.Hours()/24) 截断，7 天 2 小时会被算成 7 天、7 天 23 小时算成 7
// 天——与「到期日」展示相差一天。
func apiKeyExpiryDays(exp, now time.Time) int {
	loc := dailyLocation()
	nd := now.In(loc)
	ed := exp.In(loc)
	day0 := time.Date(nd.Year(), nd.Month(), nd.Day(), 0, 0, 0, 0, loc)
	day1 := time.Date(ed.Year(), ed.Month(), ed.Day(), 0, 0, 0, 0, loc)
	return int(day1.Sub(day0).Hours() / 24)
}

// CheckAPIKeyExpiry 扫描临期（≤7 天）启用 API 密钥并发布预警。每日一次（周期
// 任务 24h），不重复刷屏；无临期密钥静默返回。
func CheckAPIKeyExpiry() error { return checkAPIKeyExpiryAt(time.Now()) }

// checkAPIKeyExpiryAt 带时刻的巡检入口（测试缝）。
func checkAPIKeyExpiryAt(now time.Time) error {
	if db.DB == nil {
		return nil
	}
	rows, err := db.DB.Query(`SELECT name, expires_at FROM api_keys
		WHERE COALESCE(is_enabled,1)=1 AND COALESCE(expires_at,'')<>''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, exp string
		if err := rows.Scan(&name, &exp); err != nil {
			continue
		}
		t, ok := parseAPIKeyExpiry(exp)
		if !ok {
			continue
		}
		days := apiKeyExpiryDays(t, now)
		if days < 0 || days > 7 {
			continue
		}
		Publish(Event{
			Type: EvtAPIKeyExpiryWarning, Level: LevelWarn,
			Fields: map[string]string{"1": name, "2": t.In(dailyLocation()).Format("2006-01-02"), "3": strconv.Itoa(days)},
		})
	}
	return rows.Err()
}
