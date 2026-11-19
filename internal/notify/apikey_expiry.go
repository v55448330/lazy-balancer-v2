package notify

// API 密钥临期预警巡检（apikey.expiry_warning）：周期任务每日扫描 7 天内到期
// 的启用密钥，逐键发布预警（参数序契约：1=名称 2=到期日 3=剩余天数）。

import (
	"strconv"
	"time"

	"lazy-balancer-v2/internal/db"
)

// CheckAPIKeyExpiry 扫描临期（≤7 天）启用 API 密钥并发布预警。每日一次（周期
// 任务 24h），不重复刷屏；无临期密钥静默返回。
func CheckAPIKeyExpiry() error {
	if db.DB == nil {
		return nil
	}
	now := time.Now()
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
		t, err := time.Parse("2006-01-02 15:04:05", exp)
		if err != nil {
			t, err = time.Parse(time.RFC3339, exp)
			if err != nil {
				continue
			}
		}
		days := int(t.Sub(now).Hours() / 24)
		if days < 0 || days > 7 {
			continue
		}
		Publish(Event{
			Type: EvtAPIKeyExpiryWarning, Level: LevelWarn,
			Fields: map[string]string{"1": name, "2": t.Format("2006-01-02"), "3": strconv.Itoa(days)},
		})
	}
	return rows.Err()
}