package notify

// 发布总线：Publish 仅入缓冲通道（满则丢弃+计数，绝不阻塞事件源）；
// dispatcher 单消费者把事件按订阅矩阵落 notification_deliveries(pending)。
// 投递 Daemon（taskengine notification-delivery）扫描 pending 按通道发送。

import (
	"log"
	"strconv"
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
)

// Start 启动分发循环（进程生命周期一次；重复调用为 no-op）。
func Start() {
	if !started.CompareAndSwap(false, true) {
		return
	}
	queue = make(chan Event, 1024)
	stopCh = make(chan struct{})
	go dispatchLoop()
}

// Stop 停止分发循环（进程关停兜底；在途事件随进程回收——事实已在库）。
func Stop() { stopOnce.Do(func() { close(stopCh) }) }

// DroppedCount 已丢弃事件计数（监控/测试用）。
func DroppedCount() int64 { return droppedCount.Load() }

// Publish 发布事件（目录外事件拒绝——订阅矩阵与模板均以目录为唯一事实源）。
func Publish(evt Event) {
	if _, ok := catalogByID(evt.Type); !ok {
		log.Printf("WARN: notify.Publish 事件 %q 不在目录中，已丢弃", evt.Type)
		return
	}
	if evt.Time.IsZero() {
		evt.Time = time.Now()
	}
	select {
	case queue <- evt:
	default:
		droppedCount.Add(1)
		log.Printf("WARN: notify 队列已满（容量 1024），事件 %s 丢弃（累计 %d）", evt.Type, droppedCount.Load())
	}
}

func dispatchLoop() {
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
	userIDs, err := subscribersFor(evt.Type, evt.Level)
	if err != nil {
		log.Printf("WARN: notify 查询订阅者失败（事件 %s 本轮未投递）: %v", evt.Type, err)
		return
	}
	for _, uid := range userIDs {
		insertDeliveryPending(uid, evt)
	}
}

// insertDeliveryPending 落一条 pending 投递行（每用户一行；投递 Daemon 按用户
// 的启用通道展开为多通道投递并更新状态）。
func insertDeliveryPending(userID int64, evt Event) {
	_, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (?,?,?,?,?, 'pending', 0, ?)`,
		userID, evt.Type, string(evt.Level), evt.Title, evt.Body,
		evt.Time.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		log.Printf("WARN: notify 投递行落库失败（user=%d event=%s）: %v", userID, evt.Type, err)
	}
}

// strconvPlaceholder 防 unused import；模板参数格式化由 renderTitle/renderBody 使用。
var _ = strconv.Itoa
