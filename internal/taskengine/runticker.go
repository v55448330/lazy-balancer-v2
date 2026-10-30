package taskengine

import (
	"context"
	"log"
	"time"
)

// RunTicker 是唯一许可的高频常驻执行形态（task-engine 标准 v2.2 §0.2）：
// 「立即首跑（bootstrap）→ 固定节拍 → 唤醒立即补跑（合并抖动）」的单体循环，
// ctx 取消即停。子资源（队列/租户/提供商）的泵由宿主 daemon 的 fn 遍历驱动
// （如 Manager.DispatchOnce），不得在业务域自建 go loop()/ticker（§0.4）。
//
// interval<=0 兜底为 1s 并记一次 warn（配置缺失显性留痕，不静默空转也不热循环）；
// fn panic 经 recover 隔离并记 ERROR——常驻 daemon 不得因单轮执行体 panic 退出
// （与引擎调度循环 panic 隔离同口径，见 engine.go 调度闭包 recover）。
// wake 非 nil 时作为额外触发源：唤醒信号是「提示」（§0.3），通道缓冲 1 +
// 非阻塞投递由调用方保证合并——本函数每次至多消费一个待处理唤醒，堆积信号
// 不产生连跑。
func RunTicker(ctx context.Context, interval time.Duration, wake <-chan struct{}, fn func(context.Context)) {
	if interval <= 0 {
		log.Printf("WARNING: taskengine: RunTicker interval=%s <= 0，兜底为 1s（调用方节拍配置缺失，须显性留痕）", interval)
		interval = time.Second
	}
	// bootstrap：先立即执行一次，再进入节拍循环（启动即消费积压/恢复现场，
	// 不等首个 interval 到期）。
	runTickerOnce(ctx, fn)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runTickerOnce(ctx, fn)
		case <-wake:
			runTickerOnce(ctx, fn)
		}
	}
}

// runTickerOnce 单轮执行体：panic 隔离后节拍循环继续（daemon 不退出）。
func runTickerOnce(ctx context.Context, fn func(context.Context)) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: taskengine: RunTicker 执行函数 panic（隔离继续节拍，daemon 不退出）: %v", r)
		}
	}()
	fn(ctx)
}
