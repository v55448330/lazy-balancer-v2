package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/models"
)

func TestCAProviderQueries_returns_credentials(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	credentials := `{"eab_kid":"kid","eab_hmac_key":"secret"}`
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('private','zerossl',?,?,1,1000,1)`, ZeroSSLDirectoryURL, credentials)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}

	// When
	listed, err := NewCAProviderService().ListCAProviders()
	if err != nil {
		t.Fatalf("list CA providers: %v", err)
	}
	loaded, err := loadCAProvider(int(providerID))
	if err != nil {
		t.Fatalf("load CA provider for business use: %v", err)
	}

	// Then: both list and business load return actual credentials
	var listedCredentials string
	for _, provider := range listed {
		if provider.ID == int(providerID) {
			listedCredentials = provider.Credentials
			break
		}
	}
	if !strings.Contains(listedCredentials, "secret") {
		t.Fatalf("listed credentials=%q, want actual HMAC key", listedCredentials)
	}
	if loaded.Credentials != credentials {
		t.Fatalf("business credentials=%q, want actual credentials", loaded.Credentials)
	}
}

func TestCAProviderService_TestCAProviderWithContext_honors_parent_cancellation(t *testing.T) {
	// 自有 DB 隔离（U4b-01）：不得隐式依赖前置测试泄漏的 db.DB 全局。
	newClusterTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewCAProviderService().TestCAProviderWithContext(ctx, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("test provider error=%v, want context canceled", err)
	}
}

func TestCAProviderService_TestCAProviderWithContext_cancels_while_query_waits(t *testing.T) {
	_, database := newClusterTestService(t)
	database.SetMaxOpenConns(1)
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("hold database connection: %v", err)
	}
	defer connection.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- NewCAProviderService().TestCAProviderWithContext(ctx, 1)
	}()
	for database.Stats().WaitCount == 0 {
		runtime.Gosched()
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("test provider error=%v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider query did not stop after context cancellation")
	}
}

func TestCAProviderService_TestCAProviderWithContext_bounds_EAB_auto_provision_with_deadline(t *testing.T) {
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('eab','zerossl',?,'',1,1000,1)`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET acme_email='admin@example.test' WHERE id=1"); err != nil {
		t.Fatalf("seed acme email: %v", err)
	}

	// N+13 H3-S：伪 ZeroSSL EAB 端点延迟响应，晚于注入的 100ms 时限。父 ctx
	// 为 Background（永不取消），服务端不自败——若 EAB 自动获取未被独立超时
	// 包裹（原实现仅 RegisterAccount 有 10s 界），本调用将阻塞至 30s HTTP
	// 客户端兜底；唯一可能的快速取消源即子超时。
	oldTimeout := zerosslEABProvisionTimeout
	zerosslEABProvisionTimeout = 100 * time.Millisecond
	t.Cleanup(func() { zerosslEABProvisionTimeout = oldTimeout })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false,"error":"fixture"}`))
	}))
	defer server.Close()
	oldURL := zerosslEABURL
	zerosslEABURL = server.URL
	t.Cleanup(func() { zerosslEABURL = oldURL })

	done := make(chan error, 1)
	go func() {
		done <- NewCAProviderService().TestCAProviderWithContext(context.Background(), int(providerID))
	}()
	select {
	case err := <-done:
		var testErr *CAProviderTestError
		if !errors.As(err, &testErr) || testErr.Phase != "config" {
			t.Fatalf("test provider error=%v, want CAProviderTestError phase=config", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("test provider error=%v, want context.DeadlineExceeded from the EAB bound", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EAB auto-provision hung — test path is unbounded without its own timeout")
	}
}

func TestCAProviderService_UpdateCAProvider_rejects_disabling_last_enabled(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES ('only','letsencrypt',?,'',1,1000,1)`, LetsEncryptDirectoryURL)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read CA provider ID: %v", err)
	}
	disabled := false

	err = NewCAProviderService().UpdateCAProvider(int(id), models.UpdateCAProviderRequest{Enabled: &disabled})
	if !errors.Is(err, ErrCAProviderLastEnabled) {
		t.Fatalf("disable last provider error=%v, want %v", err, ErrCAProviderLastEnabled)
	}
	var enabled bool
	if err := database.QueryRow("SELECT enabled FROM ca_providers WHERE id=?", id).Scan(&enabled); err != nil {
		t.Fatalf("read CA provider after rollback: %v", err)
	}
	if !enabled {
		t.Fatal("last CA provider was disabled despite rollback")
	}
}
func TestMaskEmail_multibyteLocalPartStaysValidUTF8(t *testing.T) {
	// F49-P5-15（第 49 轮审计）：@ 前缀为多字节 UTF-8（如 CJK 邮箱本地部分）
	// 时，按字节截断前两个「字符」会切在 rune 中间产出非法 UTF-8 残片——
	if got := maskEmail("张小三abc@example.com"); got != "张小***@example.com" {
		t.Fatalf("maskEmail(张小三abc@example.com)=%q, want 张小***@example.com（前两个 rune）", got)
	}
	if got := maskEmail("张三@x.cn"); got != "***@x.cn" {
		t.Fatalf("maskEmail(张三@x.cn)=%q, want ***@x.cn（rune 数 <=3 不保留首字符）", got)
	}
	for _, email := range []string{"张小三abc@example.com", "张三@x.cn", "admin@example.com", "ab@x.cn", "a@b.c", "nosign", "@"} {
		if got := maskEmail(email); !utf8.ValidString(got) {
			t.Fatalf("maskEmail(%q)=%q 不是合法 UTF-8", email, got)
		}
	}
}

// CERT-L1（第 69 轮）：「最后一个启用」守卫的语义矩阵钉测试。守卫已收敛为
// 原子条件 UPDATE（WHERE 子查询），逐形状钉住：放行形态/拦截形态/错误优先级/
// 非禁用写不受守卫影响。
func TestCAProviderService_UpdateCAProvider_lastEnabledGuard_matrix(t *testing.T) {
	// Given：两个启用提供商
	_, database := newClusterTestService(t)
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}
	seed := func(name string, enabled bool) int64 {
		result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES (?,'letsencrypt',?,'',1,1000,?)`, name, LetsEncryptDirectoryURL, enabled)
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("read %s id: %v", name, err)
		}
		return id
	}
	idA := seed("provider-a", true)
	idB := seed("provider-b", true)
	enabledFlag := func(value bool) *bool { return &value }
	providerEnabled := func(id int64) bool {
		var enabled bool
		if err := database.QueryRow("SELECT enabled FROM ca_providers WHERE id=?", id).Scan(&enabled); err != nil {
			t.Fatalf("read enabled state: %v", err)
		}
		return enabled
	}
	svc := NewCAProviderService()

	// When/Then 1：禁用 A（B 仍启用）放行
	if err := svc.UpdateCAProvider(int(idA), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); err != nil {
		t.Fatalf("disable one-of-two should succeed: %v", err)
	}
	if providerEnabled(idA) {
		t.Fatal("provider A should be disabled")
	}

	// When/Then 2：禁用已禁用的 A（wasEnabled=false，守卫不触发）放行
	if err := svc.UpdateCAProvider(int(idA), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); err != nil {
		t.Fatalf("re-disable already-disabled provider should succeed: %v", err)
	}

	// When/Then 3：禁用最后一个启用的 B → ErrCAProviderLastEnabled，B 保持启用
	if err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); !errors.Is(err, ErrCAProviderLastEnabled) {
		t.Fatalf("disable last enabled error=%v, want %v", err, ErrCAProviderLastEnabled)
	}
	if !providerEnabled(idB) {
		t.Fatal("last enabled provider B must stay enabled after guard rejection")
	}

	// When/Then 4：校验错误优先于守卫——禁用最后一个启用且名字非法时返回
	// 名字校验错误（校验在 UPDATE 之前，与旧实现错误顺序一致）
	emptyName := ""
	if err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Name: &emptyName, Enabled: enabledFlag(false)}); !errors.Is(err, ErrCAProviderInvalidName) {
		t.Fatalf("invalid name + disable last error=%v, want %v", err, ErrCAProviderInvalidName)
	}
	if !providerEnabled(idB) {
		t.Fatal("provider B must stay enabled after validation rejection")
	}

	// When/Then 5：非禁用写（不改 enabled）不受守卫影响
	newName := "provider-b-renamed"
	if err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Name: &newName}); err != nil {
		t.Fatalf("name-only update on last enabled should succeed: %v", err)
	}

	// When/Then 6：启用 A 后禁用 B 放行（A 成为新的唯一启用）
	if err := svc.UpdateCAProvider(int(idA), models.UpdateCAProviderRequest{Enabled: enabledFlag(true)}); err != nil {
		t.Fatalf("re-enable A should succeed: %v", err)
	}
	if err := svc.UpdateCAProvider(int(idB), models.UpdateCAProviderRequest{Enabled: enabledFlag(false)}); err != nil {
		t.Fatalf("disable B while A enabled should succeed: %v", err)
	}
	if providerEnabled(idB) || !providerEnabled(idA) {
		t.Fatalf("final state wrong: A enabled=%v, B enabled=%v, want A enabled / B disabled", providerEnabled(idA), providerEnabled(idB))
	}
}

// CERT-L1（第 69 轮）：并发禁用仅剩的两个启用提供商时，启用计数恒不为零——
// 一个禁用成功、另一个必须被守卫拒绝（ErrCAProviderLastEnabled），禁止静默
// 击穿到「零启用」（该状态会让全部 ACME 签发/续签失败）。原子条件 UPDATE
// 形态下该不变量由数据库在写锁内保证，本测试钉住端到端可观察结果。
func TestCAProviderService_UpdateCAProvider_concurrentDisable_neverReachesZeroEnabled(t *testing.T) {
	_, database := newClusterTestService(t)
	svc := NewCAProviderService()
	disabled := false
	for round := range 25 {
		// Given：每轮重置为恰好两个启用提供商
		if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
			t.Fatalf("round %d clear: %v", round, err)
		}
		ids := make([]int64, 0, 2)
		for _, name := range []string{"race-a", "race-b"} {
			result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled) VALUES (?,'letsencrypt',?,'',1,1000,1)`, name, LetsEncryptDirectoryURL)
			if err != nil {
				t.Fatalf("round %d seed %s: %v", round, name, err)
			}
			id, err := result.LastInsertId()
			if err != nil {
				t.Fatalf("round %d read id: %v", round, err)
			}
			ids = append(ids, id)
		}

		// When：并发禁用两者
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, id := range ids {
			wg.Add(1)
			go func(providerID int64) {
				defer wg.Done()
				errs <- svc.UpdateCAProvider(int(providerID), models.UpdateCAProviderRequest{Enabled: &disabled})
			}(id)
		}
		wg.Wait()
		close(errs)

		// Then：错误仅允许 nil 或 ErrCAProviderLastEnabled，且终态恰好一个启用
		for err := range errs {
			if err != nil && !errors.Is(err, ErrCAProviderLastEnabled) {
				t.Fatalf("round %d: unexpected error %v (want nil or ErrCAProviderLastEnabled)", round, err)
			}
		}
		var enabledCount int
		if err := database.QueryRow("SELECT COUNT(*) FROM ca_providers WHERE enabled=1").Scan(&enabledCount); err != nil {
			t.Fatalf("round %d count enabled: %v", round, err)
		}
		if enabledCount != 1 {
			t.Fatalf("round %d: enabled count=%d, want exactly 1（守卫必须拦住第二个禁用）", round, enabledCount)
		}
	}
}
