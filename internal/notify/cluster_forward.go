package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lazy-balancer-v2/internal/atomicfile"
	"lazy-balancer-v2/internal/db"
)

// ── 集群事件转发（用户裁定 2026-11-22：主节点集中汇聚模式）──
// 从节点检测自身角色（is_master=0）后，Publish 不入本地队列，而是把
// （节点名+事件）即时推送到主节点 /cluster/events/report（集群令牌认证，
// 与 nodes/report 同通道）；主节点校验后带 Node 字段入本地事件总线，
// 订阅匹配与投递全部在主节点完成（通道零同步/机器人零冲突/集群全量视角）。
// 故障路径：主节点不可达/5xx 时写本地 spool，短间隔轮询重传（不丢）。

// ClusterEventReport 从节点→主节点的事件上报载荷。
type ClusterEventReport struct {
	Node    string            `json:"node"`     // 上报节点名（nodes.name，主端回显校验）
	Events  []ClusterEventOne `json:"events"`   // 本批事件（正常路径单条，spool 重传可批量）
	Spooled bool              `json:"spooled"`  // true=spool 重传批次（主端仅记日志）
	BatchID string            `json:"batch_id"` // spool 批次标识（幂等去重键）
}

// ClusterEventOne 单条上报事件（Event 的可序列化投影）。
type ClusterEventOne struct {
	Type   string            `json:"type"`
	Level  string            `json:"level,omitempty"` // 空=目录默认
	Title  string            `json:"title,omitempty"` // 空=目录标题
	Body   string            `json:"body,omitempty"`  // 空=目录模板渲染
	Node   string            `json:"node,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

// clusterForwarder spool 目录缓存（角色探测经注入查询直读，无缓存——
// 从节点事件量级低（分钟级），每事件一次轻量 SELECT 可接受，缓存反而引入
// 角色翻转窗口的转发误判）。
type clusterForwarder struct {
	spoolDir string
}

var clusterFwd = &clusterForwarder{}

// clusterForwardSpoolDirName spool 子目录（data 目录下）。
const clusterForwardSpoolDirName = "notify-forward-spool"

// clusterForwardRoleDetector 角色探测（global_config 直读；notify 包已依赖 db，
// 无循环依赖）。nodeName 取本机主机名（主端回显时以 nodes.name 认证身份为准）。
var clusterForwardRoleDetector = func() (isMaster bool, masterURL, token, nodeName string, err error) {
	if db.DB == nil {
		return true, "", "", "", nil // 库未装配=按主节点处理（零转发）
	}
	var isMasterInt int
	if err := db.DB.QueryRow(`SELECT COALESCE(is_master,1), COALESCE(master_url,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&isMasterInt, &masterURL, &token); err != nil {
		return true, "", "", "", err // 探测失败=保守按主节点（不转发）
	}
	return isMasterInt != 0, masterURL, token, LocalNodeName(), nil
}

// shouldForwardClusterEvent 从节点判定（带缓存）+ 事件级过滤：
// 仅转发目录内事件（带外键不入上报面）。
func shouldForwardClusterEvent(evt Event) bool {
	if _, ok := catalogByID(evt.Type); !ok {
		return false // 目录外事件不上报（与本地投递同门）
	}
	isMaster, _, _, _, err := clusterForwardRoleDetector()
	if err != nil || isMaster {
		return false // 探测失败=保守按主节点（不转发，本地正常处理）
	}
	return true
}

// forwardEventToMaster 即时推送主路径（事件驱动，非轮询）。
// 失败返回 error 由调用方决定 spool。
func forwardEventToMaster(evt Event) error {
	isMaster, masterURL, token, nodeName, _ := clusterForwardRoleDetector()
	if isMaster || masterURL == "" || token == "" {
		return fmt.Errorf("转发条件不成立（master=%v url=%q）", isMaster, masterURL)
	}
	report := ClusterEventReport{
		Node:   nodeName,
		Events: []ClusterEventOne{eventToReportOne(evt, nodeName)},
	}
	return postClusterEventReport(masterURL, token, report)
}

// eventToReportOne Event→上报投影（Fields 原样携带，正文兜底 Body）。
func eventToReportOne(evt Event, nodeName string) ClusterEventOne {
	one := ClusterEventOne{
		Type:   evt.Type,
		Level:  string(evt.Level),
		Title:  evt.Title,
		Body:   evt.Body,
		Fields: evt.Fields,
	}
	if evt.Node != "" {
		one.Node = evt.Node
	} else {
		one.Node = nodeName
	}
	return one
}

// postClusterEventReport 上报 POST（3s 超时，与 detach 通知同口径；
// http→https 同主机重定向重放一次，集群同步同契约）。
func postClusterEventReport(masterURL, token string, report ClusterEventReport) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(masterURL, "/") + "/api/v1/cluster/events/report"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-Token", token)
	client := &http.Client{Timeout: 3 * time.Second}
	if ClusterForwardTransportFactory != nil {
		if tr := ClusterForwardTransportFactory(masterURL); tr != nil {
			client.Transport = tr
			defer func() {
				if t, ok := tr.(*http.Transport); ok {
					t.CloseIdleConnections()
				}
			}()
		}
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("主节点上报被拒: %d", resp.StatusCode)
	}
	return nil
}

// ── spool：故障兜底（2s 轮询重传，正常路径零轮询）──

const clusterForwardSpoolMaxFiles = 1000 // 上限防御（超限丢最老，事件通知非审计面）

// ClusterForwardTransportFactory 上报 HTTP 传输工厂（services 装配——与快照
// 同步同一 TOFU pin 体系，自签主节点证书按指纹校验；nil=默认传输，适用于
// 公网可信证书或 HTTP）。返回 nil 表示该地址不需要特殊 TLS 配置。
var ClusterForwardTransportFactory func(masterURL string) http.RoundTripper

// spoolClusterEvent 主节点不可达时落盘（文件名=纳秒时序，批次单事件）。
func spoolClusterEvent(evt Event) {
	dir := clusterForwardSpoolDir()
	if dir == "" {
		return
	}
	report := ClusterEventReport{
		Node:    clusterForwardNodeName(),
		Events:  []ClusterEventOne{eventToReportOne(evt, "")},
		Spooled: true,
		BatchID: fmt.Sprintf("spool-%d", time.Now().UnixNano()),
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return
	}
	path := filepath.Join(dir, fmt.Sprintf("pending-%d.json", time.Now().UnixNano()))
	// 原子写（直写落盘快照门禁：临时文件+rename，重传侧永不读到半截 JSON）
	_ = atomicfile.WriteAtomic(path, raw, 0o600)
	trimClusterForwardSpool(dir)
}

// clusterForwardNodeName spool 侧节点名（角色查询失败时回退主机名）。
func clusterForwardNodeName() string {
	_, _, _, name, err := clusterForwardRoleDetector()
	if err != nil || name == "" {
		return LocalNodeName()
	}
	return name
}

// clusterForwardSpoolDir spool 目录（data 目录派生；未初始化返回空=不落盘）。
func clusterForwardSpoolDir() string {
	if clusterFwd.spoolDir != "" {
		return clusterFwd.spoolDir
	}
	base := db.DataDir()
	if base == "" {
		return ""
	}
	dir := filepath.Join(base, clusterForwardSpoolDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	clusterFwd.spoolDir = dir
	return dir
}

// trimClusterForwardSpool 上限裁剪（最老先丢）。
func trimClusterForwardSpool(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= clusterForwardSpoolMaxFiles {
		return
	}
	// ReadDir 已按文件名序（时序命名=最老在前）
	for _, e := range entries[:len(entries)-clusterForwardSpoolMaxFiles] {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}

// ClusterForwardSpoolRetryInterval spool 重传节拍（任务体 RunTicker 用）。
const ClusterForwardSpoolRetryInterval = 2 * time.Second

// DrainClusterForwardSpool 单轮重传（逐文件，成功即删；串行避免乱序）。
// 由 notification-delivery daemon（从节点分支）的 RunTicker 驱动——不自建轮询。
func DrainClusterForwardSpool(ctx context.Context) {
	dir := clusterForwardSpoolDir()
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var report ClusterEventReport
		if err := json.Unmarshal(raw, &report); err != nil {
			_ = os.Remove(path) // 畸形文件不重传（事件通知非审计面，丢弃+留痕）
			log.Printf("WARN: 集群事件 spool 文件损坏已丢弃: %s", e.Name())
			continue
		}
		_, masterURL, token, nodeName, derr := clusterForwardRoleDetector()
		if derr != nil || masterURL == "" || token == "" {
			return // 角色未就绪/已升主——下轮再看（升主后 spool 清理见角色翻转钩子）
		}
		if report.Node == "" {
			report.Node = nodeName
		}
		if err := postClusterEventReport(masterURL, token, report); err != nil {
			return // 主节点仍不可达——保留下轮重试
		}
		_ = os.Remove(path)
	}
}

// ── 日报统计上报（从节点→主节点，每日槽点一次）──

// ClusterNodeStats 从节点昨日统计块（主节点「各节点摘要」数据源）。
type ClusterNodeStats struct {
	Date        string `json:"date"`
	Requests    int64  `json:"requests"`
	Allowed     int64  `json:"allowed"`
	Logged      int64  `json:"logged"`
	Blocked     int64  `json:"blocked"`
	DistinctIPs int64  `json:"distinct_ips"`
	TopRule     string `json:"top_rule"`
	TopIPs      string `json:"top_ips"`
	CCTriggered int64  `json:"cc_triggered"`
	Autobans    int64  `json:"autobans"`
}

// CollectNodeStats 采集本节点指定日期（昨日）的统计块（从节点上报用）。
func CollectNodeStats(ctx context.Context, now time.Time) (ClusterNodeStats, error) {
	d, err := CollectDailyData(ctx, now)
	if err != nil {
		return ClusterNodeStats{}, err
	}
	return ClusterNodeStats{
		Date: d.Date, Requests: d.Requests, Allowed: d.Allowed, Logged: d.Logged,
		Blocked: d.Blocked, DistinctIPs: d.DistinctIPs, TopRule: d.TopRule,
		TopIPs: d.TopIPs, CCTriggered: d.CCTriggered, Autobans: d.Autobans,
	}, nil
}

// ReportNodeStatsToMaster 从节点上报昨日统计块（槽点单次，非轮询；
// 失败仅留痕——次日重报覆盖，日报侧缺失标「未上报」）。
func ReportNodeStatsToMaster(ctx context.Context, stats ClusterNodeStats) error {
	_, masterURL, token, _, err := clusterForwardRoleDetector()
	if err != nil {
		return err
	}
	if masterURL == "" || token == "" {
		return fmt.Errorf("集群上报地址/令牌缺失")
	}
	payload, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(masterURL, "/") + "/api/v1/cluster/node-stats/report"
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-Token", token)
	client := &http.Client{Timeout: 5 * time.Second}
	if ClusterForwardTransportFactory != nil {
		if tr := ClusterForwardTransportFactory(masterURL); tr != nil {
			client.Transport = tr
			defer func() {
				if t, ok := tr.(*http.Transport); ok {
					t.CloseIdleConnections()
				}
			}()
		}
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("主节点统计上报被拒: %d", resp.StatusCode)
	}
	return nil
}

// NodeDailyStatRow 主节点存储行（读回渲染用）。
type NodeDailyStatRow struct {
	Node  string
	Stats ClusterNodeStats
}
