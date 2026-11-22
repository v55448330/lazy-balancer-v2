package notify

// 证书临期预警发布器（cert.expiry_warning）钉测：
// 参数序契约（1=域名 2=到期日 3=剩余天数）/ 每证书每去重窗一次 /
// 续期后到期时刻变化可再次预警 / 空域名回退任务 id。

import (
	"strconv"
	"testing"
	"time"
)

func resetCertExpiryWarnForTest(t *testing.T) {
	t.Helper()
	certExpiryWarnMu.Lock()
	certExpiryWarnSeen = map[string]time.Time{}
	certExpiryWarnMu.Unlock()
	t.Cleanup(func() {
		certExpiryWarnMu.Lock()
		certExpiryWarnSeen = map[string]time.Time{}
		certExpiryWarnMu.Unlock()
	})
}

func TestPublishCertExpiryWarning_payloadAndDedupWindow(t *testing.T) {
	resetCertExpiryWarnForTest(t)
	oldPublisher := certExpiryPublisher
	var captured []Event
	certExpiryPublisher = func(evt Event) { captured = append(captured, evt) }
	t.Cleanup(func() { certExpiryPublisher = oldPublisher })

	now := time.Date(2026, 11, 22, 10, 0, 0, 0, dailyLocation())
	expires := now.AddDate(0, 0, 3)

	PublishCertExpiryWarning(7, "a.example.test", expires, now)
	if len(captured) != 1 {
		t.Fatalf("events=%d，want 1", len(captured))
	}
	evt := captured[0]
	if evt.Type != EvtCertExpiryWarning || evt.Level != LevelWarn {
		t.Fatalf("event=%+v，want cert.expiry_warning/warn", evt)
	}
	if evt.Fields["1"] != "a.example.test" {
		t.Fatalf("fields[1]=%q，want 域名", evt.Fields["1"])
	}
	if evt.Fields["2"] != expires.Format("2006-01-02") {
		t.Fatalf("fields[2]=%q，want 到期日", evt.Fields["2"])
	}
	if evt.Fields["3"] != strconv.Itoa(3) {
		t.Fatalf("fields[3]=%q，want 3（剩余天数）", evt.Fields["3"])
	}

	// 同一证书同一到期时刻，窗内重复扫描不重复发布。
	PublishCertExpiryWarning(7, "a.example.test", expires, now.Add(6*time.Hour))
	if len(captured) != 1 {
		t.Fatalf("窗内重扫 events=%d，want 1（每证书每窗一次）", len(captured))
	}
	// 窗过后再发。
	PublishCertExpiryWarning(7, "a.example.test", expires, now.Add(certExpiryWarnWindow+time.Minute))
	if len(captured) != 2 {
		t.Fatalf("窗后 events=%d，want 2", len(captured))
	}
	// 续期成功（到期时刻变化）=新证书，立即可再预警。
	PublishCertExpiryWarning(7, "a.example.test", expires.AddDate(0, 2, 0), now.Add(certExpiryWarnWindow+2*time.Minute))
	if len(captured) != 3 {
		t.Fatalf("续期后 events=%d，want 3（新到期时刻不得被旧键吞掉）", len(captured))
	}
	// 空域名回退任务 id。
	PublishCertExpiryWarning(99, "  ", now.AddDate(0, 0, 1), now)
	if len(captured) != 4 || captured[3].Fields["1"] != "证书任务 #99" {
		t.Fatalf("空域名回退=%+v，want 证书任务 #99", captured)
	}
}
