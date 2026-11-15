package handlers

// 自动封禁的解封/处置与清桶必须走单一入口——
//  1. 预置名单两条解封路径（remove-ip 端点、差集全量保存）+ 加名单主动处置
//     （AddIPToList 追加、CreateIPList「创建并加入」种子条目：手动加入任何
//     名单=抹累犯前科+停计数）必须调用 services.AutobanForgetIPs（机制侧行为
//     由 services 层 TestAutobanForgetIPs_deleteThenNoNewEventsNoReban 钉死，
//     本钉测锁定调用点不旁路：securityiplists.go 源扫描恰 4 次）；
//  2. 唯一生产入口 importConfigBackupCore（HTTP 导入+自动备份还原双面共用）
//     必须在 commit 成功后调用 services.ResetAutobanCounters（Ruling：全量替换
//     语义下整体清桶，差集 ForgetIPs 不更正确——见
//     config_backup_autoban_r77_test.go 头注），且调用点在 session.commit 之后。
//     扫描不再单文件：securityiplists.go + config_backup.go 双文件。
//
// 另附预置名单 remove-ip HTTP 行为冒烟（200+条目更新——走新清桶接线,空桶下
// 为 no-op）。

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestAutobanUnban_bucketClearWiringPinned(t *testing.T) {
	src, err := os.ReadFile("securityiplists.go")
	if err != nil {
		t.Fatalf("read securityiplists.go: %v", err)
	}
	if got := strings.Count(string(src), "services.AutobanForgetIPs("); got != 4 {
		t.Fatalf("services.AutobanForgetIPs 调用点=%d, want 恰 4（remove-ip 端点+差集全量保存+AddIPToList 追加+CreateIPList 创建并加入；新增解封/处置面必须走同一入口并更新本钉测）", got)
	}
}

// 清桶调用点钉测——config_backup.go 恰 1 处 services.ResetAutobanCounters，且位于
// session.commit 调用点之后（commit 前/失败路径清桶=回滚后观察态被误清）。
func TestAutobanImportReset_wiringPinned(t *testing.T) {
	src, err := os.ReadFile("config_backup.go")
	if err != nil {
		t.Fatalf("read config_backup.go: %v", err)
	}
	if got := strings.Count(string(src), "services.ResetAutobanCounters("); got != 1 {
		t.Fatalf("services.ResetAutobanCounters 调用点=%d, want 恰 1（备份导入面唯一生产入口 importConfigBackupCore；新增替换名单面必须走同一入口并更新本钉测）", got)
	}
	commitIdx := strings.Index(string(src), "session.commit(")
	resetIdx := strings.Index(string(src), "services.ResetAutobanCounters(")
	if commitIdx < 0 || resetIdx < commitIdx {
		t.Fatalf("ResetAutobanCounters 调用点必须在 session.commit 之后（commit=%d reset=%d）", commitIdx, resetIdx)
	}
}

func TestRemoveIPFromList_autobanPresetUnbanSmoke(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := ipRemoveRouter(t)
	var presetID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, services.AutobanPresetListName).Scan(&presetID); err != nil {
		t.Fatalf("preset list missing: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`, `[{"value":"203.0.113.77","remark":"自动封禁"}]`, presetID); err != nil {
		t.Fatalf("seed preset entry: %v", err)
	}

	rec := postRemove(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", presetID), map[string]any{"value": "203.0.113.77"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if got := decodeRemove(t, rec).Data.Removed; !got {
		t.Fatal("预置名单条目应可移除（历史修复 例外：删除即解封）")
	}
	var entriesJSON string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, presetID).Scan(&entriesJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(entriesJSON, "203.0.113.77") {
		t.Fatalf("entries=%s, want 已移除 203.0.113.77", entriesJSON)
	}
}
