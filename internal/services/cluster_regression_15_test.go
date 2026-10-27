package services

// 覆盖：
//   - WAF 文件包复用缓存与已序列化响应体（含并发合并），避免每请求全树打包 + base64；
//   - 上报失败/拉取失败的同步间隔与退避边界，任何恢复路径都不反超配置值；
//   - last_seen 无法解析时必须显性告警而非静默判「从未上报」；节点注册的名称归一与来源 IP 锚定；
//   - 登录票据过期/重放/签名无效时仍返回可审计的 claims。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func seedWafBundleSources(t *testing.T) {
	t.Helper()
	// 全局包/响应体缓存必须与夹具同生命周期：合并窗口内的复用判定不比较
	// key，残留条目会让后续用例读到上一夹具的引用与序列化体（-shuffle 或
	// 重排时「引用变化必须重建」失效、复用断言语义错位）。种子即清空，
	// 用例结束后恢复调用前状态。
	oldCache := wafFileBundleCache
	wafFileBundleCache.key = ""
	wafFileBundleCache.bundle = nil
	wafFileBundleCache.response = nil
	wafFileBundleCache.responseValidatedAt = time.Time{}
	t.Cleanup(func() { wafFileBundleCache = oldCache })
	src := t.TempDir()
	rules := filepath.Join(src, "crs", "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "a.conf"), []byte("SecRule X 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "crs", "VERSION"), []byte("v4.14.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLive, oldXdb := crsLiveDir, ip2regionLivePath
	crsLiveDir = filepath.Join(src, "crs")
	ip2regionLivePath = filepath.Join(src, "ip2region.xdb")
	t.Cleanup(func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb })
	if err := os.WriteFile(ip2regionLivePath, []byte("fake-xdb-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildWafFileBundle_reusesCacheForUnchangedRef(t *testing.T) {
	// Given：活动规则文件齐备
	seedWafBundleSources(t)

	// When：连续两次构建（引用未变）
	first := BuildWafFileBundle()
	second := BuildWafFileBundle()

	// Then：第二次必须复用同一次物化结果（不再全树 tar.gz + xdb 读取）
	if first == nil || second == nil {
		t.Fatalf("bundle must not be nil")
	}
	if first != second {
		t.Fatalf("unchanged reference must reuse the cached bundle (got distinct materializations)")
	}
	if len(first.CRSTarGz) == 0 || len(first.Xdb) == 0 {
		t.Fatalf("cached bundle must carry content: %+v", first)
	}

	// When：引用变化（IP2Region 版本标记换版）
	if err := os.WriteFile(ip2regionLivePath+".version", []byte("v2.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	third := BuildWafFileBundle()

	// Then：缓存失效、重建并反映新版本（不能返回陈旧包）
	if third == first {
		t.Fatal("ref change must invalidate the cached bundle")
	}
	if third == nil || third.IP2RegionTag != "v2.0.0" {
		t.Fatalf("rebuilt bundle tag=%v, want v2.0.0", third)
	}
}

func TestBuildWafFileBundleResponse_reusesSerializedBody(t *testing.T) {
	seedWafBundleSources(t)

	first := BuildWafFileBundleResponse()
	second := BuildWafFileBundleResponse()
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("response body must not be empty")
	}
	// 切片底层数组相同 = 复用同一份已序列化字节（无每请求 base64 重编码）。
	if &first[0] != &second[0] {
		t.Fatal("unchanged reference must reuse the serialized response body")
	}
	var response models.APIResponse
	if err := json.Unmarshal(first, &response); err != nil {
		t.Fatalf("cached body must stay valid JSON: %v", err)
	}
	if response.Code != 0 || response.Data == nil {
		t.Fatalf("response envelope=%+v", response)
	}
	// 复用必须是「同一引用」的复用：合并窗口内的判定不比较 key，若全局缓存
	// 未随夹具隔离，上一用例留下的引用（v9.9.9）会让本条以陈旧体积/切片恒绿。
	if strings.Contains(string(first), "v9.9.9") {
		t.Fatalf("serialized body carries another fixture's reference（全局缓存未隔离）")
	}
	if !strings.Contains(string(first), "v4.14.0") {
		t.Fatalf("serialized body missing current fixture CRS version: %s", string(first))
	}
}

func TestBuildWafFileBundleResponse_coalescesStampede(t *testing.T) {
	seedWafBundleSources(t)
	oldWindow := wafFileBundleResponseCoalesceWindow
	wafFileBundleResponseCoalesceWindow = time.Minute
	t.Cleanup(func() { wafFileBundleResponseCoalesceWindow = oldWindow })

	first := BuildWafFileBundleResponse()
	if len(first) == 0 {
		t.Fatal("response body must not be empty")
	}
	// 引用变化但处于合并窗口内：N 个从节点同周期齐拉只做一次全树哈希/打包。
	if err := os.WriteFile(ip2regionLivePath+".version", []byte("v9.9.9"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := BuildWafFileBundleResponse()
	if &first[0] != &second[0] {
		t.Fatal("requests inside the coalesce window must reuse the same generation")
	}

	// 窗口关闭后必须重算并反映新引用（陈旧不得超过窗口）。
	wafFileBundleResponseCoalesceWindow = 0
	third := BuildWafFileBundleResponse()
	if len(third) == 0 {
		t.Fatal("response body after window close must not be empty")
	}
	if &first[0] == &third[0] {
		t.Fatal("window close must invalidate the cached response")
	}
	if !strings.Contains(string(third), "v9.9.9") {
		t.Fatalf("rebuilt response must carry the new reference tag: %s", string(third))
	}
}

func newSyncRunFixture(t *testing.T, syncInterval int, snapshotStatus, reportStatus int) (*SyncService, chan time.Duration) {
	t.Helper()
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			response.WriteHeader(snapshotStatus)
		case "/api/v1/cluster/nodes/report":
			if reportStatus >= http.StatusBadRequest {
				response.WriteHeader(reportStatus)
				_, _ = response.Write([]byte("rejected"))
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"data": map[string]any{}})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(master.Close)
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(caddy.Close)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token', sync_interval=? WHERE id=1", master.URL, syncInterval); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	delays := make(chan time.Duration, 8)
	service.waitRunDelay = func(_ context.Context, d time.Duration) bool {
		delays <- d
		return false
	}
	return service, delays
}

func firstDelay(t *testing.T, delays chan time.Duration) time.Duration {
	t.Helper()
	select {
	case got := <-delays:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("run 循环未在 5s 内进入首个 waitDelay")
		return 0
	}
}

func TestSyncService_reportOnlyFailure_keepsConfiguredInterval(t *testing.T) {
	// Given：拉取健康（304）、仅上报失败、配置间隔 600s
	service, delays := newSyncRunFixture(t, 600, http.StatusNotModified, http.StatusInternalServerError)

	// When
	service.run(context.Background())

	// Then：上报失败不得触发 1s→30s 快速退避（拉取本身健康，加速轮询对上报
	// 无修复作用，只会把用户可见的同步间隔压到 30s 以内并放大已故障主节点负载）
	if got := firstDelay(t, delays); got != 600*time.Second {
		t.Fatalf("delay=%s, want 600s（仅上报失败须维持配置间隔）", got)
	}
}

func TestSyncService_pullFailure_keepsFastBackoffBoundedByInterval(t *testing.T) {
	// Given：拉取失败（500）、配置间隔 600s
	service, delays := newSyncRunFixture(t, 600, http.StatusInternalServerError, http.StatusOK)

	// When
	service.run(context.Background())

	// Then：主链路中断仍走 1s 起快速退避（min(retryDelay, interval)）
	if got := firstDelay(t, delays); got != time.Second {
		t.Fatalf("delay=%s, want 1s（拉取失败首次快速重试）", got)
	}
}

func TestSyncService_pullFailure_neverExceedsShortConfiguredInterval(t *testing.T) {
	// Given：拉取失败、配置间隔 10s（retryDelay 会增长到 30s）
	service, delays := newSyncRunFixture(t, 10, http.StatusInternalServerError, http.StatusOK)

	// When：连续记录六轮等待
	service.waitRunDelay = func(_ context.Context, d time.Duration) bool {
		delays <- d
		return len(delays) < 6
	}
	service.run(context.Background())

	// Then：1s→2s→4s→8s 快速退避，但绝不越过配置间隔（min(retryDelay, interval)）
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for i, expected := range want {
		select {
		case got := <-delays:
			if got != expected {
				t.Fatalf("delay[%d]=%s, want %s（退避不得超过配置间隔）", i, got, expected)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("run 循环未在 5s 内产出第 %d 个 waitDelay", i+1)
		}
	}
}

func TestMasterServingRound_parsesLastSeenViaDriverFormats(t *testing.T) {
	// Given：last_seen 为驱动可解析、但原手写三布局之外的形态（T 分隔、无时区）
	newServingTestEnv(t)
	seen := servingBase.Add(-30 * time.Second).Format("2006-01-02T15:04:05")
	seedServingNode(t, "edge-driver", seen, 3, 60)

	// When
	masterSyncServingRound(context.Background(), servingBase, newServingWatch())

	// Then：同一列在 Nodes()/票据路径由驱动解析——巡检必须同源，不得误报「从未上报」
	for _, line := range servingLines(readClusterSyncLog(t)) {
		if strings.Contains(line, "edge-driver") && strings.Contains(line, "从未上报") {
			t.Fatalf("driver-parsable last_seen must not be reported as never-reported: %q", line)
		}
	}
}

func TestMasterServingRound_unparsableLastSeenSurfacesInsteadOfFalseOffline(t *testing.T) {
	// Given：last_seen 为不可解析文本（直改库/迁移脏数据）
	newServingTestEnv(t)
	seedServingNode(t, "edge-dirty", "not-a-timestamp", 3, 60)

	// When
	masterSyncServingRound(context.Background(), servingBase, newServingWatch())

	// Then：必须显性告警（读取节点行失败），不得静默降级为「从未上报」假离线
	log := readClusterSyncLog(t)
	if !strings.Contains(log, "读取节点行失败") {
		t.Fatalf("unparsable last_seen must surface a row-read warning, log=%q", log)
	}
	for _, line := range servingLines(log) {
		if strings.Contains(line, "edge-dirty") && strings.Contains(line, "从未上报") {
			t.Fatalf("unparsable last_seen must not be reported as never-reported: %q", line)
		}
	}
}

func TestClusterService_RegisterNode_normalizesName(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}

	// Given：控制字符 + 超长名字（schema VARCHAR(100)，SQLite 不强制）
	name := "edge\n" + strings.Repeat("x", 150)
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: name, IPAddress: "10.0.0.9", Port: 8000,
	}, "10.0.0.9", now)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := database.QueryRow("SELECT name FROM nodes WHERE id=?", registration.RegistrationID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(stored, "\n\r\t") {
		t.Fatalf("stored name must not contain control characters: %q", stored)
	}
	if len([]rune(stored)) > models.ClusterNodeNameMaxLen {
		t.Fatalf("stored name runes=%d, want <=%d", len([]rune(stored)), models.ClusterNodeNameMaxLen)
	}
}

func TestClusterService_RegisterNode_rejectsBlankName(t *testing.T) {
	service, _ := newClusterTestService(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "   ", IPAddress: "10.0.0.10", Port: 8000,
	}, "10.0.0.10", now)
	if err == nil {
		t.Fatal("blank node name must be rejected")
	}
}

func TestClusterService_RegisterNode_ignoresForeignAccessURL(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}

	// Given：自述地址指向第三方主机（与注册来源 IP 不一致）
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "edge-a", IPAddress: "10.0.0.11", Port: 8000,
		AccessURL: "https://attacker.example/collect",
	}, "10.0.0.11", now)
	if err != nil {
		t.Fatal(err)
	}
	var accessURL string
	if err := database.QueryRow("SELECT COALESCE(access_url,'') FROM nodes WHERE id=?", registration.RegistrationID).Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "" {
		t.Fatalf("foreign self-reported access_url must not be persisted, got %q", accessURL)
	}
	if !registration.AccessURLIgnored {
		t.Fatal("registration must report the ignored self-declared address")
	}
}

func TestClusterService_RegisterNode_acceptsMatchingAccessURL(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "edge-b", IPAddress: "10.0.0.12", Port: 8000,
		AccessURL: "https://10.0.0.12:8443",
	}, "10.0.0.12", now)
	if err != nil {
		t.Fatal(err)
	}
	var accessURL string
	if err := database.QueryRow("SELECT COALESCE(access_url,'') FROM nodes WHERE id=?", registration.RegistrationID).Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "https://10.0.0.12:8443" {
		t.Fatalf("matching self-reported access_url=%q", accessURL)
	}
	if registration.AccessURLIgnored {
		t.Fatal("matching access_url must not be flagged as ignored")
	}
}

// Given 自述 ip_address 与 access_url 主机自洽，但连接来源地址不同。
// Then 服务层必须以来源地址为信任锚丢弃自述地址——请求体自述值不得充当
// 该判定的一方（曾两者同源，判定恒真）。
func TestClusterService_RegisterNode_usesObservedSourceIPAsAnchor(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "edge-c", IPAddress: "10.0.0.13", Port: 8000,
		AccessURL: "https://10.0.0.13:8443",
	}, "198.51.100.7", now)
	if err != nil {
		t.Fatal(err)
	}
	var accessURL string
	if err := database.QueryRow("SELECT COALESCE(access_url,'') FROM nodes WHERE id=?", registration.RegistrationID).Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "" {
		t.Fatalf("access_url matching only the self-declared ip must be dropped, got %q", accessURL)
	}
	if !registration.AccessURLIgnored {
		t.Fatal("registration must report the ignored self-declared address")
	}
}

func TestMasterServingRound_retriesPendingPinCleanup(t *testing.T) {
	newServingTestEnv(t)
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "cluster-master.pin")
	if err := os.WriteFile(pinPath, []byte("fingerprint"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := NewClusterService(db.DB, dir)
	service.pinCleanupMu.Lock()
	service.pendingPins = map[string]string{pinPath: "https://old-master:8000"}
	service.pinCleanupMu.Unlock()

	// When：主节点巡检一轮（不依赖任何从节点 Pull）
	masterSyncServingRound(context.Background(), servingBase, newServingWatch())

	// Then：残留 pin 被删除、pending 状态清空
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatalf("pending pin must be retried by the master inspection round, stat err=%v", err)
	}
	service.pinCleanupMu.Lock()
	pending := len(service.pendingPins)
	service.pinCleanupMu.Unlock()
	if pending != 0 {
		t.Fatalf("pending pin 条数=%d, want 0", pending)
	}
}

func TestClusterLoginTicket_expired_returnsClaimsForAudit(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	claims, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now.Add(91*time.Second))
	if !errors.Is(err, ErrLoginTicketExpired) {
		t.Fatalf("expired ticket error=%v", err)
	}
	if claims.Username != "alice" || claims.UserID != 3 {
		t.Fatalf("signature-verified expired ticket must return claims for attribution, got %+v", claims)
	}
}

func TestClusterLoginTicket_replay_returnsClaimsForAudit(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	if _, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	claims, _, _, err := service.ValidateLoginTicket(context.Background(), ticket, now)
	if !errors.Is(err, ErrLoginTicketReplay) {
		t.Fatalf("replayed ticket error=%v", err)
	}
	if claims.Username != "alice" {
		t.Fatalf("signature-verified replayed ticket must return claims for attribution, got %+v", claims)
	}
}

func TestClusterLoginTicket_invalidSignature_returnsEmptyClaims(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service, ticket := issueClusterLoginTicket(t, now)
	parts := strings.Split(ticket, ".")
	if parts[1][0] == 'A' {
		parts[1] = "B" + parts[1][1:]
	} else {
		parts[1] = "A" + parts[1][1:]
	}
	claims, _, _, err := service.ValidateLoginTicket(context.Background(), strings.Join(parts, "."), now)
	if err == nil {
		t.Fatal("invalid signature must be rejected")
	}
	if claims.Username != "" {
		t.Fatalf("unverified ticket must not attribute an actor, got %+v", claims)
	}
}

func TestClusterStatus_transportInsecureFlag(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url='http://master.example:8000', cluster_token='tok' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.TransportInsecure {
		t.Fatal("plaintext master_url must set transport_insecure for steady-state UI warning")
	}

	if _, err := database.Exec("UPDATE global_config SET master_url='https://master.example:8000' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	status, err = service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.TransportInsecure {
		t.Fatal("https master_url must not set transport_insecure")
	}
}
