package notify

// 发布总线：Publish 仅入缓冲通道（满则丢弃+计数，绝不阻塞事件源）；
// dispatcher 单消费者把事件按订阅矩阵落 notification_deliveries(pending)。
// 投递 Daemon（taskengine notification-delivery）扫描 pending 按通道发送。
// 从节点转发同样是异步的（有界队列+单 worker，见 cluster_forward.go）：
// 网络外呼永不在事件源 goroutine 上执行。

import (
	"log"

	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

var (
	queue        chan Event
	started      atomic.Bool
	droppedCount atomic.Int64
	stopCh       chan struct{}
	stopOnce     sync.Once
	loopDone     chan struct{} // 分发循环退出信号（Stop 后等待排空面；Start 置新）
)

// Start 启动分发循环（进程生命周期一次；重复调用为 no-op）。
func Start() {
	if !started.CompareAndSwap(false, true) {
		return
	}
	queue = make(chan Event, 1024)
	stopCh = make(chan struct{})
	loopDone = make(chan struct{})
	go dispatchLoop()
}

// Stop 停止分发循环（进程关停兜底；在途事件随进程回收——事实已在库）。
// 集群转发队列不同：事件未落库，关停时把队列剩余条目全部落 spool，下次启动
// 重传（不静默丢）。
// 幂等且可早于 Start 调用：stopCh 未装配（启动失败早退路径）时只做队列落盘。
func Stop() {
	stopOnce.Do(func() {
		if stopCh != nil {
			close(stopCh)
		}
		drainClusterForwardQueueOnStop()
	})
}

// Bootstrap 进程启动挂接（cmd/server 启动链 DB 装配后调用一次）：启动分发
// 循环并做一次 pending 重投兜底（超龄判 dead、近期 pending 留队交投递
// Daemon 重扫）。库未装配时 requeue 为 no-op；此前的 Publish 按无队列丢弃。
func Bootstrap() {
	// 凭据静态加密存量迁移（先于连接器读取凭据）：遗留明文敏感键原地重加密，
	// 幂等。失败留痕不阻断启动（读路径兼容遗留明文，写路径恒加密）。
	if err := MigrateSecretSettings(); err != nil {
		log.Printf("WARN: notify 凭据静态加密迁移失败: %v", err)
	}
	Start()
	requeueStalePending()
}

// DroppedCount 已丢弃事件计数（监控/测试用）。
// testseam: 导出只读计数供用例观测「是否发布」（队列未装配时 Publish 计入此处）。
func DroppedCount() int64 { return droppedCount.Load() }

// Publish 发布事件（目录外事件拒绝——订阅矩阵与模板均以目录为唯一事实源）。
// 集群从节点（用户裁定 2026-11-22 主节点集中汇聚）：不入本地队列，交给转发
// 队列异步推送主节点（有界队列+单 worker，队列满或推送失败即落 spool 兜底）；
// 订阅匹配/投递全部在主节点完成。本函数恒非阻塞。
func Publish(evt Event) {
	if _, ok := catalogByID(evt.Type); !ok {
		log.Printf("WARN: notify.Publish 事件 %q 不在目录中，已丢弃", evt.Type)
		return
	}
	noteAuthEvent(evt.Type) // 日报认证日计数（集群合计：主+全从——从节点事件经转发入主节点总线同样累加）
	if evt.Time.IsZero() {
		evt.Time = time.Now()
	}
	if forward, role := shouldForwardClusterEvent(evt); forward {
		// 防回荡（两从节点互指 master_url 时若无标记会无限转圈）：已转过一次
		// 的事件（Hop>=1）与起源为本机的事件在本节点不再外发。
		if evt.Hop >= 1 || (evt.Origin != "" && evt.Origin == LocalNodeName()) {
			log.Printf("INFO: notify 集群转发终止事件 %s（hop=%d origin=%q 已到达转发终点），本地丢弃", evt.Type, evt.Hop, evt.Origin)
			return
		}
		enqueueClusterForward(evt, role) // 异步：绝不阻塞事件源
		return
	}
	// 主节点/单机本地事件补节点标识（2026-11-22 用户裁定：通知里只有从节点
	// 事件带节点信息，主节点事件 Node 恒空不可辨识）——非转发路径才会走到
	// 这里，转发事件由主端以认证节点名落 Node。
	if evt.Node == "" {
		evt.Node = MasterNodeLabel()
	}
	select {
	case queue <- evt:
	default:
		droppedCount.Add(1)
		log.Printf("WARN: notify 队列已满（容量 1024），事件 %s 丢弃（累计 %d）", evt.Type, droppedCount.Load())
	}
}

func dispatchLoop() {
	defer close(loopDone)
	for {
		select {
		case <-stopCh:
			return
		case evt := <-queue:
			dispatch(evt)
		}
	}
}

// dispatch 单事件分发：按目录模板兜底渲染 → 找订阅者 → 落 pending 投递行。
func dispatch(evt Event) {
	entry, ok := catalogByID(evt.Type)
	if !ok {
		return
	}
	if evt.Level == "" {
		evt.Level = entry.Level
	}
	if evt.Title == "" {
		evt.Title = renderTitle(entry, evt)
	}
	if evt.Body == "" {
		evt.Body = renderBody(entry, evt)
	}
	if db.DB == nil {
		// 库未装配（启动早期失败路径/测试剥离）时事件无处落库：丢弃并留痕，
		// 绝不让分发 goroutine 在 nil 句柄上 panic 拖垮进程。
		log.Printf("WARN: notify 库未装配，事件 %s 丢弃", evt.Type)
		return
	}
	userIDs, err := subscribersFor(evt.Type, evt.Level)
	if err != nil {
		log.Printf("WARN: notify 查询订阅者失败（事件 %s 本轮未投递）: %v", evt.Type, err)
		return
	}
	selections := subscriptionChannelSelectionsFor(evt.Type, userIDs)
	for _, uid := range userIDs {
		insertDeliveryPending(uid, evt)
		// MCP 实时推送与通道投递同源过滤：显式空选接收通道（channel_ids='[]'，
		// 用户裁定「全不选=不订阅」）的用户不再收推送——旧实现无条件推送，
		// 用户关掉全部通道后仍被 MCP 会话打扰。
		//
		// 过滤模型限制（P3 记录，非缺陷）：MCP 不是通道行，选择面里只有「显式
		// 空选」这一态可判定。以下形态仍会推送，属模型边界：
		//   ① 订阅行的 channel_ids 为空串/未设置 = 「未选择=全部通道」，MCP 视同
		//      在列（MCP 会话本身不落 notification_channels，无法逐通道核对）；
		//   ② 账号下所有通道都被停用（行仍在但 enabled=0）——投递 Daemon 侧会
		//      按启用通道裁掉全部投递，但本处只看选择面，MCP 推送仍到达；
		//   ③ 事件级最小级别/模板过滤不作用于推送管道（推送载荷即目录原始
		//      标题/正文），模板定制只影响通道投递。
		// 需要「完全不收」时用显式空选（②口径的根治）或关闭 MCP 实时推送开关
		// （notify.mcp_enabled，mcpserver 侧整体短路）。
		if selections[uid].explicitEmpty {
			continue
		}
		firePushHooks(uid, Message{EventType: evt.Type, Level: string(evt.Level), Title: evt.Title, Body: evt.Body})
	}
}

// insertDeliveryPending 落一条 pending 投递行（每用户一行；投递 Daemon 按用户
// 的启用通道展开为多通道投递并更新状态）。
func insertDeliveryPending(userID int64, evt Event) {
	_, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, created_at, node)
		VALUES (?,?,?,?,?, 'pending', 0, ?, ?)`,
		userID, evt.Type, string(evt.Level), evt.Title, evt.Body,
		evt.Time.UTC().Format("2006-01-02 15:04:05"), evt.Node)
	if err != nil {
		log.Printf("WARN: notify 投递行落库失败（user=%d event=%s）: %v", userID, evt.Type, err)
	}
}
