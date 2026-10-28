package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// issueControlTicket 在主节点语义库上签发服务控制票据，并把库切换为从节点语义
// （与 cluster_ticket_test.go 的 issueClusterLoginTicket 同模式）。
func issueControlTicket(t *testing.T, now time.Time, action string) (*ClusterService, string) {
	t.Helper()
	service, database := newClusterTestService(t)
	clusterToken := "lb_cluster_control-secret"
	key := sha256.Sum256([]byte(clusterToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (11,'slave','10.0.0.11',8000,'online',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueServiceControlTicket(context.Background(), 11, action, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	if issued.NodeName != "slave" {
		t.Fatalf("node name=%q, want slave", issued.NodeName)
	}
	if issued.URL != "http://10.0.0.11:8000" {
		t.Fatalf("url=%q, want fallback protocol://ip:port", issued.URL)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=11 WHERE id=1", clusterToken); err != nil {
		t.Fatal(err)
	}
	return service, issued.Ticket
}

func TestServiceControlTicketRoundtrip(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStopCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); err != nil {
		t.Fatalf("validate ticket: %v", err)
	}
}

func TestServiceControlTicketRejectsExpired(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionRestartApp)
	// 签发 TTL 90s（含时钟偏移容差），越过该窗口必须拒绝
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionRestartApp, now.Add(91*time.Second)); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("expired error=%v", err)
	}
}

func TestServiceControlTicketRejectsInvalidSignature(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStartCaddy)
	parts := strings.Split(ticket, ".")
	if parts[1][0] == 'A' {
		parts[1] = "B" + parts[1][1:]
	} else {
		parts[1] = "A" + parts[1][1:]
	}
	if err := service.ValidateServiceControlTicket(context.Background(), strings.Join(parts, "."), models.ClusterServiceActionStartCaddy, now); !errors.Is(err, ErrServiceControlSignature) {
		t.Fatalf("signature error=%v", err)
	}
}

func TestServiceControlTicketRejectsReplay(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStopCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrServiceControlReplay) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestServiceControlTicketRejectsReplayAfterServiceRebuild(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionRestartCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionRestartCaddy, now); err != nil {
		t.Fatalf("first validation: %v", err)
	}
	rebuilt := NewClusterService(service.db, "")
	if err := rebuilt.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionRestartCaddy, now); !errors.Is(err, ErrServiceControlReplay) {
		t.Fatalf("replay after rebuild error=%v", err)
	}
}

func TestServiceControlTicketRejectsActionMismatch(t *testing.T) {
	// 票据与动作绑定：签发给 start_caddy 的票据不得用于 stop_caddy（防动作替换）
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, ticket := issueControlTicket(t, now, models.ClusterServiceActionStartCaddy)
	if err := service.ValidateServiceControlTicket(context.Background(), ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("action mismatch error=%v", err)
	}
}

func TestServiceControlTicketRejectsForeignNode(t *testing.T) {
	// registration_id 不匹配（票据发给别的节点）必须拒绝
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	clusterToken := "lb_cluster_control-foreign"
	key := sha256.Sum256([]byte(clusterToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (12,'slave','10.0.0.12',8000,'online',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueServiceControlTicket(context.Background(), 12, models.ClusterServiceActionStopCaddy, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	// 本节点登记的是 11 号，票据声称 12 号
	if _, err := database.Exec("UPDATE global_config SET is_master=0,cluster_token=?,registration_id=11 WHERE id=1", clusterToken); err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateServiceControlTicket(context.Background(), issued.Ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("foreign node error=%v", err)
	}
}

func TestServiceControlTicketRejectedOnMaster(t *testing.T) {
	// 主节点持有票据（本节点 is_master=1）必须拒绝——服务控制只对从节点生效
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	key := sha256.Sum256([]byte("lb_cluster_control-master-side"))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (13,'slave','10.0.0.13',8000,'online',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueServiceControlTicket(context.Background(), 13, models.ClusterServiceActionStopCaddy, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	if err := service.ValidateServiceControlTicket(context.Background(), issued.Ticket, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrInvalidServiceControlTicket) {
		t.Fatalf("master-side error=%v", err)
	}
}

func TestIssueServiceControlTicketRejectsInvalidAction(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, _ := newClusterTestService(t)
	if _, err := service.IssueServiceControlTicket(context.Background(), 1, "rm_rf_slash", now); !errors.Is(err, ErrInvalidServiceAction) {
		t.Fatalf("invalid action error=%v", err)
	}
}

func TestIssueServiceControlTicketRequiresApprovedNodeWithToken(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	// 待审批节点
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,is_approved) VALUES (14,'pending','10.0.0.14',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueServiceControlTicket(context.Background(), 14, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("pending node error=%v", err)
	}
	// 不存在的节点
	if _, err := service.IssueServiceControlTicket(context.Background(), 999, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node error=%v", err)
	}
	// 已审批但令牌哈希为空（未交付令牌）——不可控节点，但节点本身存在：
	// 与「不存在/未审批」区分（409 族哨兵），否则排障会去查节点是否被删。
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,is_approved,cluster_token_hash) VALUES (15,'hashless','10.0.0.15',1,'')`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueServiceControlTicket(context.Background(), 15, models.ClusterServiceActionStopCaddy, now); !errors.Is(err, ErrNodeTokenPending) {
		t.Fatalf("hashless node error=%v, want ErrNodeTokenPending", err)
	}
}

func TestIssueServiceControlTicketPrefersAccessURL(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	service, database := newClusterTestService(t)
	key := sha256.Sum256([]byte("cluster-token"))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,protocol,access_url,status,is_approved,cluster_token_hash) VALUES (16,'slave','172.18.0.2',8000,'http','https://node.example:8443','offline',1,?)`, hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	// 离线节点也可下发 restart_app（挂死节点的恢复路径），access_url 优先
	issued, err := service.IssueServiceControlTicket(context.Background(), 16, models.ClusterServiceActionRestartApp, now)
	if err != nil {
		t.Fatalf("issue ticket: %v", err)
	}
	if issued.URL != "https://node.example:8443" {
		t.Fatalf("url=%q, want access_url", issued.URL)
	}
}

// 同主机 https 升级重定向的主机名比较不区分大小写：Location 与请求主机仅
// 大小写不同时仍应重放（否则管理地址带大写字母时升级重放永不触发）。
func TestDoWithSameHostTLSUpgradeRedirect_hostnameComparisonIgnoresCase(t *testing.T) {
	var hits atomic.Int32
	var replayedURL string
	client := &http.Client{
		// 契约要求：调用方禁止标准库自动跟随（否则 301 被改写并先行消费）。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if hits.Add(1) == 1 {
				return &http.Response{
					StatusCode: http.StatusMovedPermanently,
					Status:     "301 Moved Permanently",
					Header:     http.Header{"Location": []string{"https://MASTER.Example:443/ticket"}},
					Body:       http.NoBody,
					Request:    req,
				}, nil
			}
			replayedURL = req.URL.String()
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader(`{"code":0}`)),
				Request:    req,
			}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "http://master.example:8080/ticket", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
	if err != nil {
		t.Fatalf("upgrade redirect returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200 after same-host upgrade replay", resp.StatusCode)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("transport saw %d requests, want 2 (upgrade replay)", got)
	}
	if replayedURL != "https://MASTER.Example:443/ticket" {
		t.Fatalf("replayed URL=%q, want Location 目标", replayedURL)
	}
}

// 跨主机的 https 升级重定向一律不跟随：请求携带 X-Cluster-Token / 票据，
// Location 指向别的主机名时重放等于把凭据交给第三方。主机名比较被放宽成
// 恒真（或误删）即失守，因此这里直接钉 helper 本身（notifyMasterDetach 只是
// 间接调用方）。含「原主机名为前缀的伪造域名」形态，防后缀/前缀比较。
func TestDoWithSameHostTLSUpgradeRedirect_doesNotFollowCrossHostHTTPSRedirect(t *testing.T) {
	for _, location := range []string{
		"https://evil.example/ticket",
		"https://master.example.evil.example/ticket",
	} {
		t.Run(location, func(t *testing.T) {
			var hits atomic.Int32
			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					hits.Add(1)
					if hits.Load() > 1 {
						return &http.Response{
							StatusCode: http.StatusOK,
							Status:     "200 OK",
							Header:     http.Header{},
							Body:       http.NoBody,
							Request:    req,
						}, nil
					}
					return &http.Response{
						StatusCode: http.StatusMovedPermanently,
						Status:     "301 Moved Permanently",
						Header:     http.Header{"Location": []string{location}},
						Body:       http.NoBody,
						Request:    req,
					}, nil
				}),
			}
			req, err := http.NewRequest(http.MethodPost, "http://master.example:8080/ticket", strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Cluster-Token", "cluster-secret")

			resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
			if err != nil {
				t.Fatalf("cross-host redirect returned error: %v", err)
			}
			defer resp.Body.Close()
			// Then 原 301 原样返回（调用方据此走「重定向指引」），且没有第二次请求。
			if resp.StatusCode != http.StatusMovedPermanently {
				t.Fatalf("status=%d, want original 301（不得跟随跨主机重定向）", resp.StatusCode)
			}
			if got := hits.Load(); got != 1 {
				t.Fatalf("transport saw %d requests, want 1（凭据不得离开原主机）", got)
			}
		})
	}
}

// 无 GetBody 的带体请求在同主机 https 升级重定向下返回合成 301
// 空体，且目标端不再收到请求。
func TestDoWithSameHostTLSUpgradeRedirect_unreplayableBodySynthetic301(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "https://"+r.Host+"/upgraded")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer server.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	// 模拟不可重放请求：Body 存在但 GetBody 为 nil。
	req.GetBody = nil
	resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
	if err != nil {
		t.Fatalf("synthetic redirect returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status=%d, want 301", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read synthetic body: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("synthetic 301 body=%q, want empty", body)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("target received %d requests, want 1 (no replay for unreplayable body)", got)
	}
}

// 降级竞态：handler 角色门通过后节点簿记已降级——带角色条件的读取命中 0 行时
// 必须复核角色返回 ErrNotMasterNode（403 语义），不得落成 ErrNodeNotFound(404)
// （否则降级窗口里的调用被误报为「节点不存在」，运营方排查方向被引偏）。
func TestIssueServiceControlTicket_demotionRaceReturnsNotMaster(t *testing.T) {
	service, database := newClusterTestService(t)
	key := sha256.Sum256([]byte("lb_cluster_control-demote-race"))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash) VALUES (12,'slave-race','10.0.0.12',8000,'online',1,?)`,
		hex.EncodeToString(key[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	_, err := service.IssueServiceControlTicket(context.Background(), 12, models.ClusterServiceActionStopCaddy, time.Now())
	if !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("降级窗口签发票据 error=%v, want ErrNotMasterNode(403 语义)", err)
	}
	if errors.Is(err, ErrNodeNotFound) {
		t.Fatal("降级竞态不得误报为节点不存在(404)")
	}
}

// Location 只带主机（无 path）时必须继承原请求路径：反代/自定义 301 常见形态
// `Location: https://host`，重放打到根路径会让从端返回 404/HTML，主端落进
// JSON 解析错误并报「解析从节点响应失败」——既有可行动 3xx 指引分支被静默绕过。
func TestDoWithSameHostTLSUpgradeRedirect_inheritsRequestPathWhenLocationOmitsPath(t *testing.T) {
	var hits atomic.Int32
	var replayedURI string
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if hits.Add(1) == 1 {
				return &http.Response{
					StatusCode: http.StatusMovedPermanently,
					Status:     "301 Moved Permanently",
					Header:     http.Header{"Location": []string{"https://master.example"}},
					Body:       http.NoBody,
					Request:    req,
				}, nil
			}
			replayedURI = req.URL.RequestURI()
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "http://master.example:8080/api/v1/cluster/report?x=1", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Cluster-Token", "cluster-secret")

	resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
	if err != nil {
		t.Fatalf("upgrade redirect returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200 after same-host upgrade replay", resp.StatusCode)
	}
	if hits.Load() != 2 {
		t.Fatalf("transport saw %d requests, want 2", hits.Load())
	}
	if replayedURI != "/api/v1/cluster/report?x=1" {
		t.Fatalf("replayed request URI=%q, want 原请求路径（空 path 的 Location 必须继承 req.URL.Path）", replayedURI)
	}
}

// Location 携带 userinfo 时重放不得以 URL Basic 认证外发：`target.User` 必须
// 清零（同主机凭证不外泄，且不得让反代注入的凭据污染集群调用）。
func TestDoWithSameHostTLSUpgradeRedirect_dropsLocationUserinfo(t *testing.T) {
	var hits atomic.Int32
	var replayedUser *url.Userinfo
	var replayedAuth string
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if hits.Add(1) == 1 {
				return &http.Response{
					StatusCode: http.StatusMovedPermanently,
					Status:     "301 Moved Permanently",
					Header:     http.Header{"Location": []string{"https://attacker:secret@master.example/ticket"}},
					Body:       http.NoBody,
					Request:    req,
				}, nil
			}
			replayedUser = req.URL.User
			replayedAuth = req.Header.Get("Authorization")
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
	}
	req, err := http.NewRequest(http.MethodPost, "http://master.example:8080/ticket", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
	if err != nil {
		t.Fatalf("upgrade redirect returned error: %v", err)
	}
	defer resp.Body.Close()
	if hits.Load() != 2 {
		t.Fatalf("transport saw %d requests, want 2", hits.Load())
	}
	if replayedUser != nil {
		t.Fatalf("replayed URL 携带 userinfo=%v, want nil", replayedUser)
	}
	if replayedAuth != "" {
		t.Fatalf("replayed Authorization=%q, want 空（不得从 Location userinfo 派生 Basic 认证）", replayedAuth)
	}
}
