package services

// 主节点集群服务面巡检（2026-10-03 用户裁定：主节点 cluster-sync 纳入任务
// 引擎统一生命周期——真实工作体取代 masterSyncServingStatus 状态镜像）。
//
// 职责：每 60s 一轮巡检 nodes 表（last_seen/reported_version）与
// global_config.cluster_version：
//   - 从节点离线判定：report 超时 > 2×sync_interval（下限 120s）；
//   - 版本滞后判定：从节点 reported_version < 主 cluster_version 持续 > 5 分钟。
//
// 日志零噪音口径（与 cluster-sync 从节点同步轮同文件 tasks/cluster-sync.log，
// 两角色各节点本地落盘）：
//   - 异常（离线/持续滞后）：状态变化时 WARN 一次，不逐轮重复；
//   - 小时级心跳（60 轮×60s）：全绿记「服务面正常：从节点 N 在线，最新版本 X」；
//     无从节点记「服务面正常：无从节点注册」；异常在挂时心跳静默（异常已
//     WARN 留痕，小时级重复=噪音）；
//   - 巡检轮错误（DB 不可读等）：WARN 不中断，下一轮继续。

import (
	"context"
	"database/sql"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 巡检节律（var——测试压缩时钟用；生产恒 60s×60 轮=小时级心跳）。
var (
	masterSyncInspectInterval  = 60 * time.Second
	masterSyncHeartbeatRounds  = 60
	masterSyncLagPersistFloor  = 5 * time.Minute // 版本滞后告警的最短持续时长
	masterSyncOfflineThreshold = 2 * time.Minute // 离线判定超时下限（2×sync_interval 与之取大）
)

// masterServingWatch 巡检跨轮状态：告警去重 + 滞后起点 + 心跳轮计数。
type masterServingWatch struct {
	offlineAlerted map[int64]bool
	lagAlerted     map[int64]bool
	lagSince       map[int64]time.Time
	quietRounds    int
}

// masterSyncServingLifecycleRun 主分支 Run 体：巡检循环挂引擎代 ctx——
// 停止/换代（StopLoop/角色翻转）取消 ctx 即真实退出，与从分支同生命周期。
func masterSyncServingLifecycleRun(rc taskengine.RunContext) error {
	ctx, cancel := context.WithCancel(rc.Ctx)
	defer cancel()
	// 启动可见性：零噪音口径下全绿只在小时级心跳落一条，刚启动/刚切角色
	// 时日志面板会长时间只有 [start]。这里每次换代只写一次巡检参数，
	// 不逐轮写（内部周期不属于任务调度节奏）。
	TaskLogf("cluster-sync", "serving", "主节点巡检启动：每 %d 秒一轮，全绿时每 %d 轮心跳一次",
		int(masterSyncInspectInterval.Seconds()), masterSyncHeartbeatRounds)
	done := make(chan struct{})
	go func() {
		defer close(done)
		masterSyncServingLoop(ctx)
	}()
	<-rc.Ctx.Done()
	// 收尾兜底：巡检轮内的 DB 调用均带 ctx，取消即返回；最多等 3s 防
	// 极端卡顿悬挂引擎换代（超时弃等——goroutine 随 ctx 泄漏面收敛为 0）。
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	return nil
}

func masterSyncServingLoop(ctx context.Context) {
	w := &masterServingWatch{
		offlineAlerted: map[int64]bool{},
		lagAlerted:     map[int64]bool{},
		lagSince:       map[int64]time.Time{},
	}
	masterSyncServingRound(ctx, time.Now(), w) // 启动即首轮
	//scope-exempt: daemon-run-body-loop —— §0.2 形态② daemon Run 体自管理阻塞循环（主节点服务面巡检，ctx 取消即退）
	ticker := time.NewTicker(masterSyncInspectInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			masterSyncServingRound(ctx, time.Now(), w)
		}
	}
}

type masterServingNode struct {
	id       int64
	name     string
	lastSeen sql.NullTime
	version  int
}

// masterSyncServingRound 执行一轮巡检（facts 读取→异常判定→零噪音落日志）。
// now 注入（测试压缩时钟）；w 由循环跨轮持有。
func masterSyncServingRound(ctx context.Context, now time.Time, w *masterServingWatch) {
	// 2026-10-04 测试污染修复：ctx 已取消（引擎停机/测试清理）时跳过整轮——
	// 防止取消后仍完成当前轮写共享日志（taskLogDir 已被下一测试/新引擎重置）。
	if ctx.Err() != nil {
		return
	}
	// 快照全局句柄：测试/停机清理可能在 nil 检查与查询之间把 db.DB 置空，
	// 直接读全局会让巡检 goroutine 在 database/sql 的 nil *DB 上 SIGSEGV。
	database := db.DB
	if database == nil {
		return
	}
	// 提升后 pin 清理失败的重试挂巡检周期。此前唯一重试点是
	// Snapshot()（从节点 Pull）入口——刚提升、无从节点的主节点永不重试，
	// 旧主节点 pin 文件与「清理失败」审计长期残留（进程重启连内存态也丢）。
	for _, service := range clusterServicesFor(database) {
		service.retryPendingPinCleanup()
	}
	var clusterVersion, syncInterval int
	// 离线阈值跟随全局同步间隔——sync_interval 与
	// cluster_sync 同口径读 global_config（COALESCE 60 兜底）；nodes.sync_interval
	// 是写侧（RegisterNode/ReportNode）从不写的死列（schema 默认 60），读它会把
	// 阈值钉死在 120s 下限，真实 interval>120s 时逐轮误报离线。
	if err := database.QueryRowContext(ctx,
		`SELECT COALESCE(cluster_version,0), COALESCE(sync_interval,60) FROM global_config WHERE id=1`).Scan(&clusterVersion, &syncInterval); err != nil {
		TaskLogfWarn("cluster-sync", "serving", "巡检失败：读取集群版本与同步间隔失败（下一轮重试）：%v", err)
		return
	}
	rows, err := database.QueryContext(ctx,
		`SELECT id, COALESCE(name,''), last_seen, COALESCE(reported_version,0)
		 FROM nodes WHERE is_approved=1 AND mode='slave'`)
	if err != nil {
		TaskLogfWarn("cluster-sync", "serving", "巡检失败：读取节点表失败（下一轮重试）：%v", err)
		return
	}
	var nodes []masterServingNode
	for rows.Next() {
		var n masterServingNode
		// last_seen 直接扫描为 sql.NullTime——与 Nodes()/票据路径
		// 同源（驱动按 DATETIME 声明解析），不再维护第二套手写布局表。不可解析
		// 的脏值不得静默降级为「从未上报」假离线：整轮显性告警并跳过（下一轮
		// 重试），与 rows.Err 同口径。
		if err := rows.Scan(&n.id, &n.name, &n.lastSeen, &n.version); err != nil {
			rows.Close()
			TaskLogfWarn("cluster-sync", "serving", "巡检失败：读取节点行失败（last_seen 无法解析或列型不符，下一轮重试）：%v", err)
			return
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		TaskLogfWarn("cluster-sync", "serving", "巡检失败：读取节点行失败（下一轮重试）：%v", err)
		return
	}
	rows.Close()

	seen := make(map[int64]bool, len(nodes))
	online, offlineCount, lagging := 0, 0, 0
	// 每节点阈值与 ComputeNodeStatus/updateOverview 同口径——
	// max(2×全局 sync_interval, 下限 120s)+脏值 clamp 归一到 nodeOfflineThreshold，
	// 同一轮全节点同值（全局列）。
	threshold := nodeOfflineThreshold(syncInterval)
	for _, n := range nodes {
		seen[n.id] = true
		lastSeen := n.lastSeen.Time
		if !n.lastSeen.Valid || now.Sub(lastSeen) > threshold {
			offlineCount++
			// 离线即清滞后窗与已告警位：滞后「持续 5 分钟」只对在线且滞后的
			// 连续区间成立——不清窗会把离线期计入滞后时长（文案失真），且
			// 已告警位残留会让恢复后仍滞后的节点永不再告警。
			delete(w.lagSince, n.id)
			delete(w.lagAlerted, n.id)
			if !w.offlineAlerted[n.id] {
				w.offlineAlerted[n.id] = true
				if !n.lastSeen.Valid {
					TaskLogfWarn("cluster-sync", "serving", "从节点 %s 离线：从未上报（超时阈值 %d 秒）", n.name, int(threshold.Seconds()))
				} else {
					TaskLogfWarn("cluster-sync", "serving", "从节点 %s 离线：最后上报 %s（超时阈值 %d 秒）",
						n.name, lastSeen.In(CurrentLocation()).Format("2006-01-02 15:04:05"), int(threshold.Seconds()))
				}
			}
			continue
		}
		online++
		delete(w.offlineAlerted, n.id) // 恢复上报——清告警态（恢复本身零日志，心跳体现）
		if n.version < clusterVersion {
			lagging++
			if since, ok := w.lagSince[n.id]; !ok {
				w.lagSince[n.id] = now
			} else if now.Sub(since) >= masterSyncLagPersistFloor && !w.lagAlerted[n.id] {
				w.lagAlerted[n.id] = true
				TaskLogfWarn("cluster-sync", "serving", "从节点 %s 版本滞后：已应用 %d / 集群 %d（持续超过 %d 分钟）",
					n.name, n.version, clusterVersion, int(masterSyncLagPersistFloor.Minutes()))
			}
		} else {
			delete(w.lagSince, n.id)
			delete(w.lagAlerted, n.id)
		}
	}
	// 节点被删除：清理其告警状态（防 map 缓涨）。离线分支已即时清滞后态，
	// offlineAlerted 命中的节点不可能同时残留 lagSince/lagAlerted；lagSince
	// 自身的未命中清理仍需保留（在线滞后期间被删除的节点未经过离线分支）。
	for id := range w.offlineAlerted {
		if !seen[id] {
			delete(w.offlineAlerted, id)
		}
	}
	for id := range w.lagSince {
		if !seen[id] {
			delete(w.lagSince, id)
			delete(w.lagAlerted, id)
		}
	}

	// 小时级心跳：全绿才记（异常在挂→静默，异常已 WARN 留痕）。
	// 异常轮必须清零窗口——原实现只按轮数自增/满 60 清零，窗口内
	// 出现离线/滞后后，恢复仅数轮就可能在「仅数轮全绿」时输出「服务面正常」
	// 心跳（与 configwatchdog 的漂移清零窗口口径分叉）。
	if offlineCount > 0 || lagging > 0 {
		w.quietRounds = 0
		return
	}
	w.quietRounds++
	if w.quietRounds < masterSyncHeartbeatRounds {
		return
	}
	w.quietRounds = 0
	// 异常轮已在上方提前返回，此处 offlineCount/lagging 恒为 0——
	// 原 switch 的第二个 case 是恒真死分支，按无条件输出收敛。
	if len(nodes) == 0 {
		TaskLogf("cluster-sync", "serving", "服务面正常：无从节点注册")
		return
	}
	TaskLogf("cluster-sync", "serving", "服务面正常：从节点 %d 在线，最新版本 %d", online, clusterVersion)
}

// （原手工 parseNodeLastSeen 三布局解析已删除——last_seen 统一由
// 驱动按 DATETIME 声明解析（sql.NullTime），与 Nodes()/票据路径同源。）
