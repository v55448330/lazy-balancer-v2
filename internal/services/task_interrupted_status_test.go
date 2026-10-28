package services

// 启动期持久化活动态归一：上次进程退出时残留的「更新中」状态不代表本进程
// 有任何执行——不归一则规则库页与任务视图恒显更新中（运行/取消按钮失效）。

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestNormalizeInterruptedUpdateStatuses(t *testing.T) {
	newClusterTestService(t)
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, auto_update, update_status, message)
		VALUES (1, 'v4.30.0', 1, 'downloading', 'crash-sim')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_ip2region_version (id, version, auto_update, update_status, message)
		VALUES (1, 'v3.18.0', 1, 'installing', 'crash-sim')`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='running', message='crash-sim' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='running', message='crash-sim'`); err != nil {
		t.Fatal(err)
	}

	normalizeInterruptedUpdateStatuses()

	for _, tc := range []struct{ table, task string }{
		{table: "security_crs_version", task: "crs"},
		{table: "security_ip2region_version", task: "ip2region"},
	} {
		var status, message string
		if err := db.DB.QueryRow(`SELECT update_status, COALESCE(message,'') FROM `+tc.table+` WHERE id=1`).
			Scan(&status, &message); err != nil {
			t.Fatalf("%s: %v", tc.task, err)
		}
		if status != "failed" {
			t.Fatalf("%s 残留活动态应归一为 failed, got %q", tc.task, status)
		}
		if !strings.Contains(message, "进程重启回收") {
			t.Fatalf("%s 归一后 message 应说明回收原因, got %q", tc.task, message)
		}
	}
	for _, table := range []string{"security_threat_sources", "security_crawler_sources"} {
		var active, recovered int
		if err := db.DB.QueryRow(`SELECT SUM(update_status='running'), SUM(update_status='failed' AND message LIKE '%进程重启回收%') FROM `+table).Scan(&active, &recovered); err != nil {
			t.Fatal(err)
		}
		if active != 0 || recovered < 1 {
			t.Fatalf("%s 源表活动态未逐行归一: running=%d recovered=%d", table, active, recovered)
		}
	}

	// 终态与非活动态不受影响（归一不得改写真实结果）。
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET update_status='success', message='ok' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET update_status='cancelled', message='user' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	normalizeInterruptedUpdateStatuses()
	for _, tc := range []struct{ table, wantStatus, wantMessage string }{
		{table: "security_crs_version", wantStatus: "success", wantMessage: "ok"},
		{table: "security_ip2region_version", wantStatus: "cancelled", wantMessage: "user"},
	} {
		var status, message string
		if err := db.DB.QueryRow(`SELECT update_status, COALESCE(message,'') FROM `+tc.table+` WHERE id=1`).
			Scan(&status, &message); err != nil {
			t.Fatal(err)
		}
		if status != tc.wantStatus || message != tc.wantMessage {
			t.Fatalf("%s 终态被归一改写: status=%q message=%q, want %q/%q",
				tc.table, status, message, tc.wantStatus, tc.wantMessage)
		}
	}
}
