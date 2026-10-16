package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCrawlerBotUpdate_fullCycle 全周期：下载→CIDR 提取→名单快照→IP 段命中。
func TestCrawlerBotUpdate_fullCycle(t *testing.T) {
	_, database := newClusterTestService(t)
	body := `{"ipv4": [{"ipv4": "66.249.66.0/24"}, {"ipv4": "66.249.67.0/24"}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	// 通用 CIDR 提取：合法 CIDR 保留、裸 IP 归一 /32、非 IP 数字串跳过
	got := parseCrawlerCIDRs(body + "\n42.236.12.130\nnot.an.ip.version.1.2.3.4.5\n")
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "66.249.66.0/24") || !strings.Contains(joined, "66.249.67.0/24") {
		t.Fatalf("CIDR 提取缺失: %v", got)
	}
	if !strings.Contains(joined, "42.236.12.130/32") {
		t.Fatalf("裸 IP 未归一 /32: %v", got)
	}

	// 快照 upsert（名单行创建+幂等更新）
	if err := upsertCrawlerIPList("googlebot", got); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var entriesRaw string
	if err := database.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, "crawlerbot:googlebot").Scan(&entriesRaw); err != nil {
		t.Fatal(err)
	}
	var entries []string
	if err := json.Unmarshal([]byte(entriesRaw), &entries); err != nil || len(entries) == 0 {
		t.Fatalf("名单 entries 为空/畸形: %v %q", err, entriesRaw)
	}
	// 幂等：再次写入不报错且 entries 保留
	if err := upsertCrawlerIPList("googlebot", got); err != nil {
		t.Fatalf("幂等 upsert: %v", err)
	}
}

// TestCrawlerBotUpdate_emptySnapshotFailSafe 空集不写（保留上次快照）。
func TestCrawlerBotUpdate_emptySnapshotFailSafe(t *testing.T) {
	_, database := newClusterTestService(t)
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := upsertCrawlerIPList("googlebot", nil); err == nil {
		t.Fatal("空集应报错（fail-safe 保留上次快照）")
	}
	var entriesRaw string
	if err := database.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, "crawlerbot:googlebot").Scan(&entriesRaw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entriesRaw, "66.249.66.0/24") {
		t.Fatalf("空集写入覆盖了上次快照: %q", entriesRaw)
	}
}
