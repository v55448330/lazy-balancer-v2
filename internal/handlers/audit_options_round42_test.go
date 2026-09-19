package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// SYS42-5(第 42 轮审计):GetAuditLogOptions 的 fetchDistinct 出错时此前仍把
// 空结果写入 60s 缓存——审计库一次瞬态故障(锁/IO)会让筛选下拉在随后 60s 内
// 持续返回空选项。任一 fetchDistinct 出错必须跳过本轮缓存写入,60s 窗口内
// 的下一次查询应重新拉取真实数据。
// SYS42-2:auditOptionsCache 读写并发无锁,补 sync.Mutex(与 helpers.go
// diskUsageCache 同型);竞态形态由锁的存在与读写持锁的代码评审覆盖,本测试
// 钉住「出错不写缓存」的可观察行为。
func TestAuditLogOptions_errorRoundDoesNotPoisonCache(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	t.Cleanup(resetAuditOptionsCacheForTest)
	resetAuditOptionsCacheForTest()

	// Given:健康审计库有一行可去重的操作人
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('recover-user', '登录', '用户认证', '', '1.1.1.1')`); err != nil {
		t.Fatal(err)
	}
	get := func() []string {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs/options", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("options status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				Usernames []struct {
					Value string `json:"value"`
				} `json:"usernames"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, u := range resp.Data.Usernames {
			out = append(out, u.Value)
		}
		return out
	}

	// When:第一轮把 AuditDB 换成缺 audit_log 表的库——三条 fetchDistinct 全部出错
	healthy := db.AuditDB
	broken, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "empty-audit.db"))
	if err != nil {
		t.Fatalf("open broken audit db: %v", err)
	}
	db.AuditDB = broken
	first := get()
	db.AuditDB = healthy
	_ = broken.Close()
	if len(first) != 0 {
		t.Fatalf("broken round must return empty options, got %v", first)
	}

	// Then:60s 缓存窗口内的第二轮必须重新拉取,不得命中出错轮写下的空缓存
	second := get()
	found := false
	for _, v := range second {
		if v == "recover-user" {
			found = true
		}
	}
	if !found {
		t.Fatalf("second options call within 60s window must re-fetch after errored round, got %v", second)
	}
}
