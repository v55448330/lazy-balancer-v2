package notify

// 证书临期预警巡检（cert.expiry_warning）：目录可订阅（默认订阅）但全仓
// 此前零发布点——订阅用户永远收不到。发布点挂在续期扫描（CheckExpiration →
// scanRenewalCandidates）逐行发布，与 apikey.expiry_warning 同形态
//（参数序契约：1=域名 2=到期日 3=剩余天数），每证书每去重窗一次。

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// certExpiryPublisher 发布缝（测试捕获；生产= Publish）。
var certExpiryPublisher = Publish

// certExpiryWarnWindow 去重窗（续期扫描 6h 节拍 → 每证书每日最多一条预警）。
var certExpiryWarnWindow = 24 * time.Hour

var (
	certExpiryWarnMu   sync.Mutex
	certExpiryWarnSeen = map[string]time.Time{} // 键=任务 id|到期时刻 → 上次发布时间
)

// certExpiryWarnKey 去重键：同任务续期成功后到期时刻变化即视为新证书，
// 允许再次预警；未变化则同一窗内不重复刷屏。
func certExpiryWarnKey(jobID int, expiresAt time.Time) string {
	return fmt.Sprintf("%d|%d", jobID, expiresAt.Unix())
}

// PublishCertExpiryWarning 发布证书临期预警（每证书每去重窗一次）。
// 域名空时回退「证书任务 #id」——预警仍可见，不静默丢弃。
func PublishCertExpiryWarning(jobID int, domain string, expiresAt time.Time, now time.Time) {
	if expiresAt.IsZero() {
		return
	}
	key := certExpiryWarnKey(jobID, expiresAt)
	certExpiryWarnMu.Lock()
	last, seen := certExpiryWarnSeen[key]
	if seen && now.Sub(last) < certExpiryWarnWindow {
		certExpiryWarnMu.Unlock()
		return
	}
	certExpiryWarnSeen[key] = now
	pruneCertExpiryWarnLocked(now)
	certExpiryWarnMu.Unlock()

	label := strings.TrimSpace(domain)
	if label == "" {
		label = fmt.Sprintf("证书任务 #%d", jobID)
	}
	days := apiKeyExpiryDays(expiresAt, now)
	if days < 0 {
		days = 0
	}
	certExpiryPublisher(Event{
		Type: EvtCertExpiryWarning, Level: LevelWarn,
		Fields: map[string]string{
			"1": label,
			"2": expiresAt.In(dailyLocation()).Format("2006-01-02"),
			"3": strconv.Itoa(days),
		},
	})
}

// pruneCertExpiryWarnLocked 回收过期去重键（无界增长防御：证书任务有界，
// 但改名/重签会不断产生新键；保留一个窗内的键足以判定重复）。
// 调用方必须持 certExpiryWarnMu。
func pruneCertExpiryWarnLocked(now time.Time) {
	for key, last := range certExpiryWarnSeen {
		if now.Sub(last) >= certExpiryWarnWindow {
			delete(certExpiryWarnSeen, key)
		}
	}
}
