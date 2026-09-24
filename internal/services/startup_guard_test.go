package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// F49-15（第 49 轮审计·漂移横幅事故）：启动「0 规则应用」守卫的探测面——
// 运行配置含规则路由时，空库实例不得在启动时把空配置 /load 进该 Caddy。

func TestRunningConfigHasRuleRoutes(t *testing.T) {
	// Given 运行配置含 lb_ 规则路由的 Caddy admin
	withRoutes := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[{"@id":"lb_abc_route"}]}}},"layer4":{"servers":{"srv1":{"routes":[]}}}}}`))
	}))
	defer withRoutes.Close()
	// And 空运行配置（无 lb_ 路由）
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[]}}}}}`))
	}))
	defer empty.Close()

	// When/Then 含路由 → true
	has, err := RunningConfigHasRuleRoutes(withRoutes.URL)
	if err != nil || !has {
		t.Fatalf("with routes: has=%v err=%v, want true", has, err)
	}
	// And 空配置 → false
	has, err = RunningConfigHasRuleRoutes(empty.URL)
	if err != nil || has {
		t.Fatalf("empty: has=%v err=%v, want false", has, err)
	}
	// And admin 不可达 → 错误（调用方按「无正向证据」放行）
	if _, err = RunningConfigHasRuleRoutes("http://127.0.0.1:1"); err == nil {
		t.Fatal("unreachable admin must return error")
	}
}
