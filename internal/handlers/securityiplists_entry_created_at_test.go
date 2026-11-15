package handlers

// IP 名单条目加入时间钉：created_at 是「加入时间」列与自动封禁挤出排序的
// 数据源——写侧新增条目必须盖章（UTC 墙钟），既有/回传时间戳必须原样保留
// （重新盖章会让挤出顺序与加入时间展示漂移）。覆盖三条新增路径：
//   - AddIPToList 追加/覆盖已到期条目；
//   - CreateIPList 种子条目；
//   - UpdateIPList 整表保存（新值盖章、旧值保留、客户端回传保留）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// assertStampedUTC 断言时间戳可解析为 UTC 墙钟且不早于测试起点（允许
// 秒级截断——盖章与取基准同秒时截断后相等）。
func assertStampedUTC(t *testing.T, stamp string, notBefore time.Time) {
	t.Helper()
	parsed, err := time.Parse("2006-01-02 15:04:05", stamp)
	if err != nil {
		t.Fatalf("created_at=%q 不是 UTC 墙钟（YYYY-MM-DD HH:MM:SS）: %v", stamp, err)
	}
	if parsed.Before(notBefore.Truncate(time.Second)) {
		t.Fatalf("created_at=%q 早于测试起点 %s", stamp, notBefore.Format("2006-01-02 15:04:05"))
	}
}

// Given 自动封禁预置名单空。
// When POST /ips 追加新条目。
// Then 条目 created_at=盖章 UTC 墙钟（加入时间列数据源）。
func TestAddIPToList_newEntryStampsCreatedAt(t *testing.T) {
	router := newAutobanTestEnv(t)
	start := time.Now().UTC()
	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", autobanPresetID(t)), map[string]any{"value": "45.33.32.90"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, autobanPresetID(t))
	if len(entries) != 1 {
		t.Fatalf("entries=%+v, want 1", entries)
	}
	assertStampedUTC(t, entries[0].CreatedAt, start)
}

// Given 预置名单含已到期条目（created_at=旧时间）。
// When POST /ips 同值覆盖（到期条目原位转手动）。
// Then created_at 重新盖章（新加入时间，不沿用到期前旧值）。
func TestAddIPToList_expiredOverrideRestampsCreatedAt(t *testing.T) {
	router := newAutobanTestEnv(t)
	seedAutobanListEntries(t, `[{"value":"45.33.32.91","remark":"自动封禁","created_at":"2020-01-01 00:00:00","expires_at":"2020-01-02 00:00:00"}]`)
	start := time.Now().UTC()
	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", autobanPresetID(t)), map[string]any{"value": "45.33.32.91"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, autobanPresetID(t))
	if len(entries) != 1 {
		t.Fatalf("entries=%+v, want 1", entries)
	}
	assertStampedUTC(t, entries[0].CreatedAt, start)
}

// Given 创建名单带两条种子。
// When POST /security/ip-lists。
// Then 每条种子 created_at=盖章 UTC 墙钟。
func TestCreateIPList_seedEntriesStampCreatedAt(t *testing.T) {
	router := newAutobanTestEnv(t)
	start := time.Now().UTC()
	rec := postJSON(t, router, "/security/ip-lists", map[string]any{
		"name": "加入时间-种子", "category": "自定义",
		"entries": `[{"value":"45.33.32.92","remark":""},{"value":"2001:db8:9::/64","remark":""}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE name='加入时间-种子'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	entries := decodeIPListEntriesForTest(t, raw)
	if len(entries) != 2 {
		t.Fatalf("entries=%+v, want 2", entries)
	}
	for _, e := range entries {
		assertStampedUTC(t, e.CreatedAt, start)
	}
}

// Given 名单存量两条（甲带旧 created_at，乙无）。
// When 整表保存：甲原样回传（带旧时间戳）、乙回传无时间戳、丙新增。
// Then 甲保留旧值（客户端回传不重盖）；乙/丙盖章（无时间戳=新加入）。
func TestUpdateIPList_stampsNewEntriesPreservesExisting(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	id := seedIPListRow(t, "加入时间-整表", `[{"value":"1.2.3.4","remark":"旧","created_at":"2024-05-01 08:00:00"},{"value":"5.6.7.8","remark":"无戳"}]`)
	start := time.Now().UTC()
	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"name":    "加入时间-整表",
		"entries": `[{"value":"1.2.3.4","remark":"旧","created_at":"2024-05-01 08:00:00"},{"value":"5.6.7.8","remark":"无戳"},{"value":"9.9.9.9","remark":"新"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	entries := decodeIPListEntriesForTest(t, raw)
	if len(entries) != 3 {
		t.Fatalf("entries=%+v, want 3", entries)
	}
	byValue := map[string]models.IPListEntry{}
	for _, e := range entries {
		byValue[e.Value] = e
	}
	if got := byValue["1.2.3.4"].CreatedAt; got != "2024-05-01 08:00:00" {
		t.Fatalf("既有回传时间戳必须保留, got %q", got)
	}
	assertStampedUTC(t, byValue["5.6.7.8"].CreatedAt, start)
	assertStampedUTC(t, byValue["9.9.9.9"].CreatedAt, start)
}

// Given 名单存量条目带 created_at。
// When 元数据-only 保存（entries 缺省）。
// Then 条目时间戳原样（不重盖）。
func TestUpdateIPList_metadataOnlyKeepsCreatedAt(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newIPListRouter(t)
	id := seedIPListRow(t, "加入时间-元数据", `[{"value":"1.2.3.4","remark":"","created_at":"2024-05-01 08:00:00"}]`)
	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"name": "加入时间-元数据改"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, `"created_at":"2024-05-01 08:00:00"`) {
		t.Fatalf("元数据保存不得动条目时间戳, entries=%s", raw)
	}
}

func decodeIPListEntriesForTest(t *testing.T, raw string) []models.IPListEntry {
	t.Helper()
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("decode entries %q: %v", raw, err)
	}
	return entries
}
