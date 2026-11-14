package services

// 首槽武装的版本行读取失败必须留痕：同函数种子写失败/槽写失败都有 warn，
// 唯独读失败静默 continue——启动武装跳过无排障信号（自动更新停摆无从定位）。

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 版本行存在但 auto_update 列为非布尔脏值（Scan 失败=真实读故障，
// 连接本身健康——种子 INSERT OR IGNORE 照常成功）。
// When armSecurityLibraryFirstSlots。
// Then 读失败留 warn 含表名（不得静默跳过武装）。
func TestArmSecurityLibraryFirstSlots_versionRowReadFailureWarns(t *testing.T) {
	setupIsolatedDB(t)
	buf := captureLogf(t)
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		if _, err := db.DB.Exec(`INSERT INTO ` + table + ` (id, version, auto_update) VALUES (1, 'v-test', 'corrupt')
			ON CONFLICT(id) DO UPDATE SET auto_update='corrupt'`); err != nil {
			t.Fatalf("seed corrupt %s: %v", table, err)
		}
	}

	armSecurityLibraryFirstSlots()

	logs := buf.String()
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		if !strings.Contains(logs, table) || !strings.Contains(strings.ToLower(logs), "warn") {
			t.Fatalf("%s 版本行读失败必须 warn 留痕, log=%q", table, logs)
		}
	}
}

// Given 健康版本行（auto_update=1、空槽）。
// When armSecurityLibraryFirstSlots。
// Then 首槽照常武装且零告警（回归形状：留痕不得误伤健康路径）。
func TestArmSecurityLibraryFirstSlots_healthyRowArmsWithoutWarn(t *testing.T) {
	setupIsolatedDB(t)
	buf := captureLogf(t)
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		if _, err := db.DB.Exec(`INSERT INTO ` + table + ` (id, version, auto_update, next_update) VALUES (1, 'v-test', 1, '')
			ON CONFLICT(id) DO UPDATE SET auto_update=1, next_update=''`); err != nil {
			t.Fatalf("seed healthy %s: %v", table, err)
		}
	}

	armSecurityLibraryFirstSlots()

	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		var next string
		if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM ` + table + ` WHERE id=1`).Scan(&next); err != nil {
			t.Fatal(err)
		}
		if next == "" {
			t.Fatalf("%s 健康行未武装首槽", table)
		}
	}
	if strings.Contains(strings.ToLower(buf.String()), "warn") {
		t.Fatalf("健康路径不得产生告警: %q", buf.String())
	}
}
