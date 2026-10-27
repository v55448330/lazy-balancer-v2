package services

// 同字节短路（运行配置 == 本次渲染视图）此前不写 LKG：LKG 文件若因带外删除/
// 卷恢复/早期版本未配置而不存在，之后每次 apply 都走短路 → 启动兜底通道
// 永远无文件可回放，DB 渲染一旦被拒就失去自动恢复（运行配置本身健康）。
// 补齐只在**非事务**路径发生：事务内 apply 在 commit 之前执行，未提交视图
// 不得成为 LKG（apply_last_good_commit_defer_test.go 的不变量）。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// newSameConfigAdmin 返回运行配置恒等于候选渲染视图的 admin 替身（短路形态），
// 并记录 /load 次数（短路不应发生真实 /load）。
func newSameConfigAdmin(t *testing.T, candidate map[string]interface{}) (*CaddyService, string, *int) {
	t.Helper()
	newClusterTestService(t)
	running, err := json.Marshal(candidate)
	if err != nil {
		t.Fatalf("marshal candidate: %v", err)
	}
	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			_, _ = w.Write(running)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads++
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	lkgPath := filepath.Join(t.TempDir(), "last_good.json")
	service := NewCaddyService(server.URL)
	service.SetLastGoodPath(lkgPath)
	return service, lkgPath, &loads
}

// Given 运行配置与候选相同（短路）且 LKG 文件缺失
// When 非事务 apply
// Then LKG 被补齐为已确认可用的运行配置字节（启动兜底不再无文件可回放）
func TestApplyConfig_sameConfigRestoresMissingLastGood(t *testing.T) {
	candidate := map[string]interface{}{"apps": map[string]interface{}{"same": true}}
	service, lkgPath, loads := newSameConfigAdmin(t, candidate)
	if _, err := os.Stat(lkgPath); !os.IsNotExist(err) {
		t.Fatalf("前置：LKG 必须不存在, stat err=%v", err)
	}

	if err := service.ApplyConfig(candidate); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if *loads != 0 {
		t.Fatalf("/load 次数=%d, want 0（短路）", *loads)
	}
	got, err := os.ReadFile(lkgPath)
	if err != nil {
		t.Fatalf("短路后 LKG 未补齐（启动兜底将无可回放文件）: %v", err)
	}
	if !caddyConfigJSONEqual(got, mustMarshal(t, candidate)) {
		t.Fatalf("补齐的 LKG=%q, want 运行配置 %v", string(got), candidate)
	}

	// 再跑一次：文件已存在则不得重写（避免每次短路都写盘）。
	fi, err := os.Stat(lkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyConfig(candidate); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	again, err := os.Stat(lkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !again.ModTime().Equal(fi.ModTime()) {
		t.Fatal("LKG 已存在时短路路径不得重写文件")
	}
}

// Given 同一短路形态
// When 事务内 apply（persistLastGood=false）
// Then LKG 仍缺失——未提交视图不得成为「最后已知正确」
func TestApplyConfigFromTx_sameConfigDoesNotCreateLastGood(t *testing.T) {
	candidate := map[string]interface{}{"apps": map[string]interface{}{"same": true}}
	service, lkgPath, _ := newSameConfigAdmin(t, candidate)
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := service.ApplyConfigFromTx(tx, false); err != nil {
		t.Fatalf("tx apply: %v", err)
	}
	if _, err := os.Stat(lkgPath); !os.IsNotExist(err) {
		t.Fatalf("事务内短路不得创建 LKG（未提交）, stat err=%v", err)
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
