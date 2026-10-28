package services

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 条数塌缩门：上游返回「每行都是合法 CIDR 但只剩几条」的自洽短名单时，
// 解析率（100%）与绝对上限门都放行——没有条数基线门就会把万余条内置威胁
// 名单整体替换（原名单 IP 静默不再拦）。门拒绝后保留上次快照，源行落 failed
// 供任务监控与运行审计可见；恰好一半的边界收缩仍可合法写入。
func TestThreatEntryShrinkGuard_rejectsParseableCollapsedList(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)

	path := filepath.Join(wafDir, "threat-ustc.iplist")
	priorEntries := make([]string, 100)
	for i := range priorEntries {
		priorEntries[i] = fmt.Sprintf("198.51.100.%d", 2*i+1)
	}
	if err := writeThreatIplistCompiled(path, priorEntries); err != nil {
		t.Fatalf("构造上次成功快照: %v", err)
	}
	priorText, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	priorFast, err := os.ReadFile(path + ".fast")
	if err != nil {
		t.Fatal(err)
	}

	nextEntries := make([]string, 10)
	for i := range nextEntries {
		nextEntries[i] = fmt.Sprintf("203.0.113.%d", 2*i+1)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Join(nextEntries, "\n") + "\n"))
	}))
	t.Cleanup(server.Close)

	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// 基线与磁盘快照均为上次成功的 100 条；新名单 10 条（不是误页也仍是塌缩）。
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=100, raw_hash='' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(context.Background(),
		threatSourceRow{id: id, name: "ustc", url: server.URL}, "manual", "2026-10-22 00:00:00")

	if !failed || changed {
		t.Fatalf("changed=%v failed=%v, want (false,true)（塌缩名单必须按源失败）", changed, failed)
	}
	currentText, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("拒绝后读取文本快照: %v", err)
	}
	currentFast, err := os.ReadFile(path + ".fast")
	if err != nil {
		t.Fatalf("拒绝后读取 .fast 快照: %v", err)
	}
	if !bytes.Equal(currentText, priorText) || !bytes.Equal(currentFast, priorFast) {
		t.Fatal("塌缩名单被拒绝后，上次 .iplist/.fast 快照字节必须逐字保留")
	}
	var status, message string
	if err := db.DB.QueryRow(`SELECT update_status, message FROM security_threat_sources WHERE id=?`, id).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(message, "收缩超过一半") {
		t.Fatalf("status=%q message=%q, want failed 且披露收缩超过一半", status, message)
	}

	// 阈值边界：10 条恰好是基线 20 条的一半；只有「严于一半」才拒绝。
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=20, raw_hash='' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	changed, failed = GetThreatUpdateManager().updateOneSource(context.Background(),
		threatSourceRow{id: id, name: "ustc", url: server.URL}, "manual", "2026-10-22 00:00:00")
	if failed || !changed {
		t.Fatalf("恰好一半应放行: changed=%v failed=%v", changed, failed)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist")); err != nil {
		t.Fatalf("放行后必须写盘: %v", err)
	}
}
