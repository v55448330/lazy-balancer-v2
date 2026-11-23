package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/atomicfile"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/netutil"
)

// ── 集群事件转发（用户裁定 2026-11-22：主节点集中汇聚模式）──
// 从节点检测自身角色（is_master=0）后，Publish 不入本地队列，而是把
// （节点名+事件）即时推送到主节点 /cluster/events/report（集群令牌认证，
// 与 nodes/report 同通道）；主节点校验后带 Node 字段入本地事件总线，
// 订阅匹配与投递全部在主节点完成（通道零同步/机器人零冲突/集群全量视角）。
// 故障路径：主节点不可达/5xx 时写本地 spool，短间隔轮询重传（不丢）。

// ClusterEventReport 从节点→主节点的事件上报载荷。
type ClusterEventReport struct {
	Node    string            `json:"node"`             // 上报节点名（nodes.name，主端回显校验）
	Events  []ClusterEventOne `json:"events"`           // 本批事件（正常路径单条，spool 重传可批量）
	Spooled bool              `json:"spooled"`          // true=spool 重传批次（主端仅记日志）
	BatchID string            `json:"batch_id"`         // spool 批次标识（幂等去重键）
	Origin  string            `json:"origin,omitempty"` // 事件起源节点名（回到起源节点即丢弃——互指防回荡）
	Hop     int               `json:"hop,omitempty"`    // 已经历的转发跳数（>=1 的接收方不得再转发）
}

// ClusterEventOne 单条上报事件（Event 的可序列化投影）。
type ClusterEventOne struct {
	Type   string            `json:"type"`
	Level  string            `json:"level,omitempty"` // 空=目录默认
	Title  string            `json:"title,omitempty"` // 空=目录标题
	Body   string            `json:"body,omitempty"`  // 空=目录模板渲染
	Node   string            `json:"node,omitempty"`
	Time   string            `json:"time,omitempty"` // 原始发生时刻（RFC3339Nano；主端优先采用落行）
	Fields map[string]string `json:"fields,omitempty"`
}

// clusterForwarder spool 目录缓存（角色探测经注入查询直读，无缓存——
// 从节点事件量级低（分钟级），每事件一次轻量 SELECT 可接受，缓存反而引入
// 角色翻转窗口的转发误判）。spoolDir 读改写经 mu 保护（spool 写入
// goroutine、spool 重传循环与角色翻转清理点会并发访问）。
type clusterForwarder struct {
	mu       sync.Mutex
	spoolDir string
}

var clusterFwd = &clusterForwarder{}

// clusterForwardSpoolDirName spool 子目录（data 目录下）。
const clusterForwardSpoolDirName = "notify-forward-spool"

// clusterForwardRoleDetector 角色探测（global_config 直读；notify 包已依赖 db，
// 无循环依赖）。nodeName 取本机主机名（主端回显时以 nodes.name 认证身份为准）。
// 经 mu 读写：转发 worker goroutine 与调用方/测试装配并发访问。
var (
	clusterForwardRoleMu       sync.RWMutex
	clusterForwardRoleDetector = func() (isMaster bool, masterURL, token, nodeName string, err error) {
		if db.DB == nil {
			return true, "", "", "", nil // 库未装配=按主节点处理（零转发）
		}
		var isMasterInt int
		if err := db.DB.QueryRow(`SELECT COALESCE(is_master,1), COALESCE(master_url,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&isMasterInt, &masterURL, &token); err != nil {
			return true, "", "", "", err // 探测失败=保守按主节点（不转发）
		}
		return isMasterInt != 0, masterURL, token, LocalNodeName(), nil
	}
)

// clusterForwardRole 取当前角色探测结果（锁内取函数快照，锁外执行）。
func clusterForwardRole() (isMaster bool, masterURL, token, nodeName string, err error) {
	clusterForwardRoleMu.RLock()
	fn := clusterForwardRoleDetector
	clusterForwardRoleMu.RUnlock()
	return fn()
}

// clusterForwardRoleDetectorSnapshot 当前探测函数（testseam：用例复原用）。
func clusterForwardRoleDetectorSnapshot() func() (bool, string, string, string, error) {
	clusterForwardRoleMu.RLock()
	defer clusterForwardRoleMu.RUnlock()
	return clusterForwardRoleDetector
}

// setClusterForwardRoleDetectorForTest 替换角色探测（testseam：用例注入假角色）。
func setClusterForwardRoleDetectorForTest(fn func() (bool, string, string, string, error)) {
	clusterForwardRoleMu.Lock()
	clusterForwardRoleDetector = fn
	clusterForwardRoleMu.Unlock()
}

// shouldForwardClusterEvent 从节点判定（每次直读角色，无缓存——见
// clusterForwarder 注释）+ 事件级过滤：仅转发目录内事件（带外键不入上报面）。
// shouldForwardClusterEvent 返回是否转发 + 角色快照（快照随 job 传给 worker，
// 每事件只探测一次）。
func shouldForwardClusterEvent(evt Event) (bool, clusterForwardRoleInfo) {
	if _, ok := catalogByID(evt.Type); !ok {
		return false, clusterForwardRoleInfo{} // 目录外事件不上报（与本地投递同门）
	}
	isMaster, masterURL, token, nodeName, err := clusterForwardRole()
	if err != nil || isMaster {
		return false, clusterForwardRoleInfo{} // 探测失败=保守按主节点（不转发，本地正常处理）
	}
	return true, clusterForwardRoleInfo{masterURL: masterURL, token: token, nodeName: nodeName}
}

// ── 转发队列：异步、有界、单 worker ──
// 从节点 Publish 绝不阻塞事件源（安全事件摄取/登录路径不得被主节点网络超时
// 卡住）：事件入有界队列，单 worker 串行转发（保序）；队列满直接落 spool
// （既不丢事件，也不阻塞调用方）。
const clusterForwardQueueSize = 256 // 有界队列（溢出落盘，非丢弃）

// clusterForwardRoleInfo 角色探测快照（入队时取一次，worker 复用——此前
// shouldForward 与 forwardEventToMaster 各探测一次，每事件 2 次 SELECT）。
type clusterForwardRoleInfo struct {
	masterURL string
	token     string
	nodeName  string
}

// clusterForwardJob 队列条目。done 仅测试排空同步用（生产恒 nil）：worker
// 串行处理，关闭 done 即代表此前入队的事件都已落定。role=入队时的角色快照。
type clusterForwardJob struct {
	evt  Event
	role clusterForwardRoleInfo
	done chan struct{}
}

var (
	clusterForwardOnce sync.Once
	clusterForwardMu   sync.RWMutex
	clusterForwardCh   chan clusterForwardJob
)

// clusterForwardQueue 返回转发队列（首次调用即起单 worker）。
func clusterForwardQueue() chan clusterForwardJob {
	clusterForwardOnce.Do(func() {
		ch := make(chan clusterForwardJob, clusterForwardQueueSize)
		clusterForwardMu.Lock()
		clusterForwardCh = ch
		clusterForwardMu.Unlock()
		go clusterForwardLoop(ch)
	})
	clusterForwardMu.RLock()
	defer clusterForwardMu.RUnlock()
	return clusterForwardCh
}

// clusterForwardLoop 单 worker：串行转发，失败即落 spool（进程关停时由
// Stop 把队列剩余事件一并落盘，下次启动重传）。
func clusterForwardLoop(ch chan clusterForwardJob) {
	for job := range ch {
		if job.done != nil {
			close(job.done)
			continue
		}
		if err := forwardEventToMasterWithRole(job.evt, job.role); err != nil {
			if permanentClusterReportRejection(err) {
				// 永久拒绝（4xx 非限流）：重试只会永远打回，逐次落 spool 再删
				// 是纯噪声——直接丢弃并留痕（事件通知非审计面）。
				log.Printf("WARN: 集群事件上报被永久拒绝（%v），事件 %s 丢弃", err, job.evt.Type)
				continue
			}
			enqueueClusterForwardSpool(job.evt)
		}
	}
}

// drainClusterForwardQueueOnStop 关停兜底：把队列内剩余待转发事件全部落 spool
// （worker 正在处理的单条由它自己收尾）。未起 worker 时零动作。
func drainClusterForwardQueueOnStop() {
	clusterForwardMu.RLock()
	ch := clusterForwardCh
	clusterForwardMu.RUnlock()
	if ch == nil {
		return
	}
	for {
		select {
		case job := <-ch:
			if job.done != nil {
				close(job.done)
				continue
			}
			spoolClusterEvent(job.evt)
		default:
			drainClusterForwardSpoolOnStop()
			return
		}
	}
}

// drainClusterForwardSpoolOnStop 关停时把异步落盘队列剩余事件同步落盘（停机
// 路径允许阻塞；正常路径调用方恒不触盘）。未起队列时零动作。
func drainClusterForwardSpoolOnStop() {
	clusterForwardSpoolMu.RLock()
	ch := clusterForwardSpoolCh
	write := clusterForwardSpoolWriter
	clusterForwardSpoolMu.RUnlock()
	if ch == nil {
		return
	}
	for {
		select {
		case evt := <-ch:
			write(evt)
		default:
			return
		}
	}
}

// enqueueClusterForward 入队（满则落盘）。Origin/Hop 在入队时定稿，spool 重传
// 与即时转发携带同一防回荡标记。
func enqueueClusterForward(evt Event, role clusterForwardRoleInfo) {
	if evt.Origin == "" {
		evt.Origin = LocalNodeName()
	}
	if evt.Hop == 0 {
		evt.Hop = 1
	}
	if evt.BatchID == "" {
		evt.BatchID = clusterForwardBatchID(evt)
	}
	ch := clusterForwardQueue()
	select {
	case ch <- clusterForwardJob{evt: evt, role: role}:
	default:
		// 队列满：交给异步有界落盘队列（调用方绝不触盘/fsync/spool 扫描）。
		enqueueClusterForwardSpool(evt)
	}
}

// forwardEventToMaster 即时推送主路径（由转发 worker 调用，非事件源 goroutine）。
// 失败返回 error 由 worker 落 spool。
func forwardEventToMaster(evt Event) error {
	isMaster, masterURL, token, nodeName, _ := clusterForwardRole()
	if isMaster || masterURL == "" || token == "" {
		return fmt.Errorf("转发条件不成立（master=%v url=%q）", isMaster, masterURL)
	}
	return forwardEventToMasterWithRole(evt, clusterForwardRoleInfo{masterURL: masterURL, token: token, nodeName: nodeName})
}

// forwardEventToMasterWithRole 用入队时角色快照转发（队列 worker 路径：不再
// 二次探测；快照为空时回退实时探测——spool 重传/测试直调形态）。
func forwardEventToMasterWithRole(evt Event, role clusterForwardRoleInfo) error {
	masterURL, token, nodeName := role.masterURL, role.token, role.nodeName
	if masterURL == "" || token == "" {
		isMaster, mu, tk, nn, _ := clusterForwardRole()
		if isMaster || mu == "" || tk == "" {
			return fmt.Errorf("转发条件不成立（master=%v url=%q）", isMaster, mu)
		}
		masterURL, token, nodeName = mu, tk, nn
	}
	origin, hop := evt.Origin, evt.Hop
	if origin == "" {
		origin = nodeName
	}
	if hop == 0 {
		hop = 1
	}
	batchID := evt.BatchID
	if batchID == "" {
		batchID = clusterForwardBatchID(evt)
	}
	report := ClusterEventReport{
		Node:    nodeName,
		Events:  []ClusterEventOne{eventToReportOne(evt, nodeName)},
		BatchID: batchID,
		Origin:  origin,
		Hop:     hop,
	}
	return postClusterEventReport(masterURL, token, report)
}

// eventToReportOne Event→上报投影（Fields 原样携带，正文兜底 Body，原始发生
// 时刻以 RFC3339Nano 携带——主端优先采用它落投递行，避免 spool 重放把
// created_at 改成重放时刻）。
func eventToReportOne(evt Event, nodeName string) ClusterEventOne {
	one := ClusterEventOne{
		Type:   evt.Type,
		Level:  string(evt.Level),
		Title:  evt.Title,
		Body:   evt.Body,
		Fields: evt.Fields,
	}
	if !evt.Time.IsZero() {
		one.Time = evt.Time.UTC().Format(time.RFC3339Nano)
	}
	if evt.Node != "" {
		one.Node = evt.Node
	} else {
		one.Node = nodeName
	}
	return one
}

// clusterForwardBatchID 事件客户端幂等键（内容寻址）：同一事件的 live 上报与
// spool 重传得到同键，主节点按 batch_id 去重可抗「已处理但响应丢失」的重复
// 投递（去重窗口本身在主节点进程内，见 handlers.HandleClusterEventReport）。
func clusterForwardBatchID(evt Event) string {
	h := sha256.New()
	fields := make([]string, 0, len(evt.Fields))
	for k := range evt.Fields {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	parts := []string{evt.Type, string(evt.Level), strconv.FormatInt(evt.Time.UnixNano(), 10), evt.Node, evt.Title, evt.Body}
	for _, k := range fields {
		parts = append(parts, k, evt.Fields[k])
	}
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return "ev-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// ── 上报 HTTP 客户端：按 masterURL 复用 + 3xx 判失败 + 同主机 https 升级重放 ──

var (
	clusterForwardFactoryMu sync.RWMutex
	clusterForwardFactory   func(masterURL string) http.RoundTripper
	clusterForwardClients   sync.Map // masterURL -> *http.Client
)

// SetClusterForwardTransportFactory 装配上报 HTTP 传输工厂（进程启动一次；
// 生产=services 的 TOFU pin 传输）。工厂变更即失效客户端缓存——晚装配窗口
// 不得让默认传输被永久缓存。
func SetClusterForwardTransportFactory(fn func(masterURL string) http.RoundTripper) {
	clusterForwardFactoryMu.Lock()
	clusterForwardFactory = fn
	clusterForwardFactoryMu.Unlock()
	resetClusterForwardClientCache()
}

func clusterForwardTransport(masterURL string) http.RoundTripper {
	clusterForwardFactoryMu.RLock()
	fn := clusterForwardFactory
	clusterForwardFactoryMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(masterURL)
}

// resetClusterForwardClientCache 失效全部缓存客户端（工厂变更/测试隔离）。
func resetClusterForwardClientCache() {
	clusterForwardClients.Range(func(key, _ any) bool {
		clusterForwardClients.Delete(key)
		return true
	})
}

// clusterForwardClient 按主节点地址复用的 HTTP 客户端：每条上报新建 Transport
// 会让事件级 TLS 握手零复用。请求级超时由 ctx 单源控制（client.Timeout=0）。
// CheckRedirect=ErrUseLastResponse：3xx 由 doClusterForwardRequest 处理（标准库
// 先行跟随会把 POST 改写成 GET）。并发首建可能多建一个客户端，LoadOrStore
// 保证只有一个生效。
func clusterForwardClient(masterURL string) *http.Client {
	if v, ok := clusterForwardClients.Load(masterURL); ok {
		return v.(*http.Client)
	}
	client := &http.Client{
		Transport:     clusterForwardTransport(masterURL),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	actual, _ := clusterForwardClients.LoadOrStore(masterURL, client)
	return actual.(*http.Client)
}

// doClusterForwardRequest 发一次上报请求：同主机 http→https 升级重定向按原
// 方法重放一次（凭证不出原主机，与 services.DoWithSameHostTLSUpgradeRedirect
// 同契约）。3xx 一律不是成功态——调用方按 >=300 判失败并落 spool 重试。
func doClusterForwardRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if !netutil.IsTLSUpgradeRedirect(resp.StatusCode) {
		return resp, nil
	}
	location := resp.Header.Get("Location")
	target, perr := url.Parse(location)
	// 仅同主机名（端口可变）+ https + 可重放请求才重放；其余原样返回（3xx
	// 由调用方判失败）。主机名比较不区分大小写（与 services 同契约）。
	if location == "" || perr != nil || target.Scheme != "https" ||
		!strings.EqualFold(target.Hostname(), req.URL.Hostname()) || req.GetBody == nil {
		return resp, nil
	}
	resp.Body.Close()
	retry := req.Clone(req.Context())
	// Location 只带主机时继承原 path/query（反代/管理面 HTTPS 升级的常见形态）。
	if target.Path == "" {
		target.Path = req.URL.Path
		target.RawPath = req.URL.RawPath
	}
	if target.RawQuery == "" {
		target.RawQuery = req.URL.RawQuery
	}
	target.User = nil // Location 注入的 userinfo 不得外发
	retry.URL = target
	body, berr := req.GetBody()
	if berr != nil {
		return nil, fmt.Errorf("重放 https 升级请求: %w", berr)
	}
	retry.Body = body
	return client.Do(retry)
}

// checkClusterReportStatus 上报响应判成功：仅 2xx 成功（3xx 不再被当成功——
// 主节点启用 HTTPS 后 302 静默丢事件并删 spool）。
func checkClusterReportStatus(what string, code int) error {
	if code >= http.StatusOK && code < http.StatusMultipleChoices {
		return nil
	}
	return &clusterReportStatusError{what: what, code: code}
}

// postClusterEventReport 上报 POST（3s 超时，与 detach 通知同口径）。
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
	resp, err := doClusterForwardRequest(clusterForwardClient(masterURL), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkClusterReportStatus("主节点上报", resp.StatusCode)
}

// ── spool：故障兜底（2s 轮询重传，正常路径零轮询）──

const clusterForwardSpoolMaxFiles = 1000 // 上限防御（超限丢最老，事件通知非审计面）

// clusterForwardSpoolQueueSize 落盘队列容量：队列满时 Publish 走此异步有界
// 通道，而不是在事件源 goroutine 上同步 fsync 两次+扫描 spool（违反「恒
// 非阻塞」注释；安全事件摄取/登录路径不得被磁盘抖动卡住）。溢出才丢弃计数。
const clusterForwardSpoolQueueSize = 256

var (
	clusterForwardSpoolOnce    sync.Once
	clusterForwardSpoolMu      sync.RWMutex
	clusterForwardSpoolCh      chan Event
	clusterForwardSpoolWriter  = spoolClusterEvent // testseam：用例替换为阻塞写验证非阻塞
	clusterForwardSpoolDropped atomic.Int64
)

func clusterForwardSpoolQueue() chan Event {
	clusterForwardSpoolOnce.Do(func() {
		ch := make(chan Event, clusterForwardSpoolQueueSize)
		clusterForwardSpoolMu.Lock()
		clusterForwardSpoolCh = ch
		clusterForwardSpoolMu.Unlock()
		go clusterForwardSpoolLoop(ch)
	})
	clusterForwardSpoolMu.RLock()
	defer clusterForwardSpoolMu.RUnlock()
	return clusterForwardSpoolCh
}

func clusterForwardSpoolLoop(ch chan Event) {
	for evt := range ch {
		clusterForwardSpoolMu.RLock()
		write := clusterForwardSpoolWriter
		clusterForwardSpoolMu.RUnlock()
		write(evt)
	}
}

// enqueueClusterForwardSpool 非阻塞落盘入队（调用方恒不触盘）：队列满即丢弃
// 并计数留痕——事件通知非审计面，宁可丢也不阻塞安全事件摄取。
func enqueueClusterForwardSpool(evt Event) {
	ch := clusterForwardSpoolQueue()
	select {
	case ch <- evt:
	default:
		clusterForwardSpoolDropped.Add(1)
		log.Printf("WARN: 集群事件落盘队列已满（容量 %d），事件 %s 丢弃（累计 %d）",
			clusterForwardSpoolQueueSize, evt.Type, clusterForwardSpoolDropped.Load())
	}
}

// spoolClusterEvent 主节点不可达时落盘（文件名=纳秒时序，批次单事件）。
func spoolClusterEvent(evt Event) {
	dir := clusterForwardSpoolDir()
	if dir == "" {
		return
	}
	// 主节点上报地址/令牌未配置（含已升主/从未入集群）：落盘后没有任何重传
	// 面能消费，等于只涨磁盘。直接丢弃并留痕。
	// 探测本身失败（rerr≠nil，如 DB 瞬时故障）不属此列：保持落盘，等探测恢复
	// 后由 spool 重传——误判丢弃等于数据永久丢失。
	isMaster, masterURL, token, nodeName, rerr := clusterForwardRole()
	if rerr == nil && (isMaster || masterURL == "" || token == "") {
		log.Printf("WARN: 集群事件 spool 跳过（主节点上报地址/令牌未配置，master=%v，事件 %s 丢弃）", isMaster, evt.Type)
		return
	}
	if nodeName == "" {
		nodeName = LocalNodeName()
	}
	origin, hop := evt.Origin, evt.Hop
	if origin == "" {
		origin = nodeName
	}
	if hop == 0 {
		hop = 1
	}
	batchID := evt.BatchID
	if batchID == "" {
		batchID = clusterForwardBatchID(evt)
	}
	report := ClusterEventReport{
		Node:    nodeName,
		Events:  []ClusterEventOne{eventToReportOne(evt, "")},
		Spooled: true,
		BatchID: batchID,
		Origin:  origin,
		Hop:     hop,
	}
	raw, err := json.Marshal(report)
	if err != nil {
		log.Printf("WARN: 集群事件 spool 序列化失败（事件 %s 丢弃）: %v", evt.Type, err)
		return
	}
	path := filepath.Join(dir, fmt.Sprintf("pending-%d.json", time.Now().UnixNano()))
	// 原子写（直写落盘快照门禁：临时文件+rename，重传侧永不读到半截 JSON）。
	// 失败必须留痕：写失败等于主节点不可达期间的重试面静默消失。
	if err := atomicfile.WriteAtomic(path, raw, 0o600); err != nil {
		log.Printf("WARN: 集群事件 spool 落盘失败（事件 %s 丢弃）: %v", evt.Type, err)
		return
	}
	trimClusterForwardSpool(dir)
}

// clusterReportStatusError 上报响应非 2xx（详情同旧文案，便于日志比对）。
type clusterReportStatusError struct {
	what string
	code int
}

func (e *clusterReportStatusError) Error() string {
	return fmt.Sprintf("%s被拒: %d", e.what, e.code)
}

// permanent 永久拒绝判定：4xx 中除超时(408)/限流(429) 外重试必败。
func (e *clusterReportStatusError) permanent() bool {
	return e.code >= 400 && e.code < 500 && e.code != http.StatusRequestTimeout && e.code != http.StatusTooManyRequests
}

// permanentClusterReportRejection 上报错误是否属「永久拒绝」（无需重试）。
func permanentClusterReportRejection(err error) bool {
	var se *clusterReportStatusError
	if !errors.As(err, &se) {
		return false
	}
	return se.permanent()
}

// clusterForwardSpoolDir spool 目录（data 目录派生；未初始化返回空=不落盘）。
// 首次解析结果缓存；读改写受 mu 保护（spool 写入/重传/角色翻转清理并发）。
func clusterForwardSpoolDir() string {
	clusterFwd.mu.Lock()
	defer clusterFwd.mu.Unlock()
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

// clusterForwardSpoolDirSnapshot 当前缓存值（测试隔离用）。
func clusterForwardSpoolDirSnapshot() string {
	clusterFwd.mu.Lock()
	defer clusterFwd.mu.Unlock()
	return clusterFwd.spoolDir
}

// setClusterForwardSpoolDirForTest 覆写 spool 目录缓存（testseam：spool 目录
// 生产恒由 data 目录派生，测试需绕开 db.DataDir 依赖）。
func setClusterForwardSpoolDirForTest(dir string) {
	clusterFwd.mu.Lock()
	defer clusterFwd.mu.Unlock()
	clusterFwd.spoolDir = dir
}

// DiscardClusterForwardSpool 丢弃全部待转发 spool（升主/角色对账升主时调用）：
// 这些事件原本要交给旧主节点，升主后收件面已失效——继续重传只会打到自身或
// 旧地址（事件通知非审计面，丢弃并留痕）。
func DiscardClusterForwardSpool(reason string) {
	dir := clusterForwardSpoolDir()
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			removed++
		}
	}
	if removed > 0 {
		log.Printf("INFO: 角色切换（%s）：丢弃 %d 个待转发事件 spool（旧主节点收件面已失效）", reason, removed)
	}
}

// trimClusterForwardSpool 上限裁剪（最老先丢）。
func trimClusterForwardSpool(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	// 只统计成品 .json：原子写的 .tmp 半成品正在被 rename，误删会让写侧
	// rename 失败（事件静默丢失）；非 spool 文件同理不参与裁剪计数。
	finished := make([]os.DirEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			finished = append(finished, e)
		}
	}
	if len(finished) <= clusterForwardSpoolMaxFiles {
		return
	}
	// ReadDir 已按文件名序（时序命名=最老在前）
	for _, e := range finished[:len(finished)-clusterForwardSpoolMaxFiles] {
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
		_, masterURL, token, nodeName, derr := clusterForwardRole()
		if derr != nil || masterURL == "" || token == "" {
			return // 角色未就绪/已升主——下轮再看（升主时由 DiscardClusterForwardSpool 清理）
		}
		if report.Node == "" {
			report.Node = nodeName
		}
		if err := postClusterEventReport(masterURL, token, report); err != nil {
			if permanentClusterReportRejection(err) {
				// 永久拒绝（4xx 非限流）：保留文件等于无限重试同一份必败载荷。
				_ = os.Remove(path)
				log.Printf("WARN: 集群事件 spool 上报被永久拒绝（%v），已丢弃: %s", err, e.Name())
				continue
			}
			log.Printf("INFO: 集群事件 spool 重传暂缓（主节点仍不可达，下轮重试）: %v", err)
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
	_, masterURL, token, _, err := clusterForwardRole()
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
	resp, err := doClusterForwardRequest(clusterForwardClient(masterURL), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkClusterReportStatus("主节点统计上报", resp.StatusCode)
}
