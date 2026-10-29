// Package services —— 爬虫地址库定时更新任务（v2.3.8 用户裁定：厂商 IP
// 名单必须自动保鲜，独立源表/排程/日志/管理面，不并入威胁情报库）。
//
// 机制：security_crawler_sources 源表（Google/OpenAI/Bing/360 官方 JSON/表）
// 独立排程（默认每天 04:00）+ 手动触发下载 → 通用 CIDR 提取（JSON/HTML 通用解析）→
// security_ip_lists 系统名单（name=CrawlerIPListName(engine)，system=1）原子快照
// 写入；失败保留上次快照（fail-safe，绝不以更新失败破坏既有豁免）。
// 验证器（caddygeoip.VerifyCrawler）按引擎 VerifyMethod 二选一：iprange 引擎
// （当前仅 so360spider）读运行快照名单做 IP 段验证，其余引擎走 PTR 双跳——
// 不存在两法并行的豁免路径。名单投影与既有安全_ip_lists 同表复用；非 iprange
// 引擎的名单仅用于展示/存档，不参与验证判定。
package services

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"time"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// crawlerBaselineLoader / crawlerIPListMigrate 是测试缝（生产恒指向真实
// 实现）：单轮基线缓存与迁移提升的调用计数观测点。
var (
	crawlerBaselineLoader = loadCrawlerIPListsFromDB
	crawlerIPListMigrate  = migrateCrawlerIPListNames
)

// crawlerBaselineSet 单次 RunUpdate 共享的名单基线快照：收缩门读取
// 「DB 名单行条数」基线。单轮内基线稳定（upsert 只写本源行，其他源基线不受影响），
// 整轮共享一份；
// 读取失败记忆化同一错误（与逐次读取的失败口径一致——基线读失败按源失败
// 处理，方向安全）。
type crawlerBaselineSet struct {
	all map[string][]string
	err error
}

func loadCrawlerBaselineSet() crawlerBaselineSet {
	if db.DB == nil {
		return crawlerBaselineSet{}
	}
	all, err := crawlerBaselineLoader()
	return crawlerBaselineSet{all: all, err: err}
}

// baseline 与 crawlerSnapshotBaseline 同口径（DB 行优先、无行回退内置首版、
// 皆无 → known=false），消费预读快照而非现读。
func (s crawlerBaselineSet) baseline(engineID string) (int, bool, error) {
	if s.err != nil {
		return 0, false, s.err
	}
	builtin, known := 0, false
	if entries, ok := crawlerBuiltinSnapshot[engineID]; ok {
		builtin, known = len(entries), true
	}
	if current, ok := s.all[engineID]; ok {
		return len(current), true, nil
	}
	return builtin, known, nil
}

// CrawlerTaskID 是爬虫地址库更新任务 ID（taskengine 注册、handler 状态/
// 触发/日志、任务监控共用；字面量只允许存在于本常量与任务注册处）。
const CrawlerTaskID = "crawlerbot-update"

// CrawlerUpdateManager 爬虫地址库更新入口（与威胁库同为 Manager 形态；
// 当前无运行态字段，单例仅统一生命周期与调用契约）。
type CrawlerUpdateManager struct{}

// validateCrawlerEntriesSanity 爬虫名单合理性门。
// 引擎声明了官方段（geoipnames 单一事实源）时，一切格式（含 JSON——结构化
// 字段白名单由 parseCrawlerCIDRsForFormat 承担，本门承担段集一致性）：
//  1. 子集门：每条解析结果必须 ⊆ 某官方段（off.Bits()<=prefix.Bits() 且
//     包含首地址）——前为「交集」判定，0.0.0.0/0、10.0.0.0/8 等
//     覆盖官方段的超网会被放行，写入即对启用爬虫豁免的策略整体 fail-open；
//  2. 覆盖门：每个官方段至少被保留条目覆盖 1/8 地址空间（自此为
//     地址空间覆盖率口径，不再是「任一更具体条目命中」；阈值依据见函数内
//     360 官方页实测）——截断页/仅一条官方段内 IP 的错误页、以及「每段一个
//     单 IP」的占位形状都不得整体替换豁免名单（与 crawler_seed_parity_test.go
//     复用同一覆盖率判定，注释所称「同口径」即同一函数）。
//
// 引擎未声明官方段时无可对照口径，原样放行（收缩门 crawlerSnapshotShrinkGuard
// 与绝对条数上限仍兜底条数塌缩/异常膨胀）。
func validateCrawlerEntriesSanity(engineID string, entries []string) ([]string, error) {
	if len(entries) == 0 {
		return nil, errors.New("解析无产出（疑似错误页/限流页），保留上次快照")
	}
	declared := crawlerEngineDeclaredRanges(engineID)
	if len(declared) == 0 {
		return entries, nil // 引擎未声明官方段：无可对照的合理性口径
	}
	official := make([]netip.Prefix, 0, len(declared))
	for _, raw := range declared {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			official = append(official, prefix)
		}
	}
	if len(official) == 0 {
		return entries, nil
	}
	// 子集门：只保留落在某官方段内的条目；页面里的示例/无关 IP 与覆盖官方段
	// 的超网都不得进入豁免名单。
	filtered := make([]string, 0, len(entries))
	filteredPrefixes := make([]netip.Prefix, 0, len(entries))
	dropped := make([]string, 0)
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			continue
		}
		contained := false
		for _, off := range official {
			if off.Bits() <= prefix.Bits() && off.Contains(prefix.Addr()) {
				filtered = append(filtered, entry)
				filteredPrefixes = append(filteredPrefixes, prefix)
				contained = true
				break
			}
		}
		if !contained {
			dropped = append(dropped, entry)
		}
	}
	// 段外条目必须留痕：厂商新增/调整 IP 段而代码 IPRanges 未同步时，这些条目
	// 会被静默丢弃——合法爬虫失去豁免，管理员只能看到条目数变小，无从判断
	// 「是错误页还是段集未同步」。本门只在更新任务（日级、逐源）里执行，日志
	// 量有界，不额外节流。
	if len(dropped) > 0 {
		sample := dropped
		if len(sample) > 5 {
			sample = sample[:5]
		}
		Logf("warn", "爬虫源 %s 解析出 %d 条不在已声明官方段内的条目（保留 %d 条，样本 %v）：厂商新增段需同步 geoipnames.CrawlerEngines.IPRanges，否则该段不会被豁免", engineID, len(dropped), len(filtered), sample)
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("解析结果（%d 条）未落在 %s 声明的官方 IP 段内（疑似错误页/版本串污染），保留上次快照", len(entries), engineID)
	}
	// 覆盖门：按地址空间覆盖率判定——每个官方段至少被保留条目
	// 覆盖 1/8 地址空间（等价于「至少一条窄于官方段 3 位的前缀证据」）。旧实现
	// 「任一更具体条目命中即算覆盖」：一条 /32 就能让官方 /24 算「已覆盖」，
	// 页面给出每段一个单 IP（5×/32）即可整体替换 5 个官方段的豁免名单（收缩门
	// 5*2<5 不命中）。地址空间口径下 /32 对 /24 仅 1/256、对 /21 仅 1/2048。
	//
	// 阈值为何是 1/8 而不是官方段的一半（实测证据，2026-10-20）：
	// 360 官方页（so.com/help/spider_ip.html）在 42.236.8.0/21 内只公布
	// 42.236.10.* / 42.236.12.* 两个 /24（= 该摘要段的 1/4），而引擎 IPRanges
	// 的 /21 是「42.236.10-15.x 归纳」的摘要段。以 50% 为门会把**真实官方页**
	// 永久判为截断（源每轮失败、名单永不更新）；1/8 既容纳官方页的发布粒度，
	// 也把「单 IP/极小段占位」挡在门外（单 IP 远低于 1/8）。
	for _, off := range official {
		if !crawlerPrefixCoverageSufficient(off, filteredPrefixes) {
			return nil, fmt.Errorf("解析结果（%d 条）对 %s 官方段 %s 的地址覆盖不足 1/8（疑似截断页/部分名单/单 IP 占位），保留上次快照", len(filtered), engineID, off)
		}
	}
	return filtered, nil
}

// crawlerPrefixCoverageSufficient 判断 retained（已经过子集门，可能来自其它
// 官方段）对官方段 off 的地址空间并集覆盖率是否 ≥1/8。
// 用 netip 位运算取各条目区间 [start, start+2^)，与 off 求交后
// 排序合并求并集大小：并集口径允许「多条 /24 合并成 /22」这类合法形态，
// 单 IP/极小段无法凑出 1/8 地址空间。条目量级为单源名单（百级），big.Int
// 开销可忽略且只在更新任务（日级）里执行。
func crawlerPrefixCoverageSufficient(off netip.Prefix, retained []netip.Prefix) bool {
	addrBits := off.Addr().BitLen()
	total := new(big.Int).Lsh(big.NewInt(1), uint(addrBits-off.Bits()))
	type span struct{ start, end *big.Int }
	spans := make([]span, 0, len(retained))
	for _, prefix := range retained {
		if prefix.Addr().BitLen() != addrBits {
			continue // 地址族不同，不可能 ⊆ 本官方段
		}
		if off.Bits() > prefix.Bits() || !off.Contains(prefix.Masked().Addr()) {
			continue // 非本段子集（属于其它官方段）
		}
		addr16 := prefix.Masked().Addr().As16()
		start := new(big.Int).SetBytes(addr16[:])
		size := new(big.Int).Lsh(big.NewInt(1), uint(addrBits-prefix.Bits()))
		spans = append(spans, span{start: start, end: new(big.Int).Add(start, size)})
	}
	if len(spans) == 0 {
		return false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start.Cmp(spans[j].start) < 0 })
	covered := new(big.Int)
	curStart, curEnd := spans[0].start, spans[0].end
	for _, s := range spans[1:] {
		if s.start.Cmp(curEnd) <= 0 { // 相邻或重叠 → 合并
			if s.end.Cmp(curEnd) > 0 {
				curEnd = s.end
			}
			continue
		}
		covered.Add(covered, new(big.Int).Sub(curEnd, curStart))
		curStart, curEnd = s.start, s.end
	}
	covered.Add(covered, new(big.Int).Sub(curEnd, curStart))
	// covered*8 >= total（阈值含等号：恰好 1/8 算覆盖）
	return covered.Lsh(covered, 3).Cmp(total) >= 0
}

// crawlerSnapshotBaseline 单次现读包装（测试/独立调用方直调路径）：当前
// 快照条数与「有可对照口径」标志——DB 行优先（运行期唯一真相），无行回退
// 内置首版（首轮更新也受门），两者皆无 → known=false（无可对照口径，条数门
// 放行）；基线读取失败按失败处理（保留上次快照，方向安全）。策略口径单源
// 在 crawlerBaselineSet.baseline，本函数只是「现读一份基线集再取」。
func crawlerSnapshotBaseline(engineID string) (count int, known bool, err error) {
	set := loadCrawlerBaselineSet()
	return set.baseline(engineID)
}

// crawlerSnapshotShrinkGuard 条数收缩门：新名单条数较当前快照
// 收缩超过一半时拒绝写入、保留上次快照——子集/覆盖门之外的兜底（引擎未
// 声明官方段时它是唯一闸门）。基线=DB 名单行当前条数，无行回退内置首版
// （首轮更新也受门），两者皆无则放行（无可对照口径）。基线读取失败按
// 失败处理（保留上次快照，方向安全）。
// set 非 nil=单次 RunUpdate 共享的预读基线（单轮缓存）；nil=现读
// （测试/独立调用方直调）。
func crawlerSnapshotShrinkGuard(engineID string, newCount int, set *crawlerBaselineSet) error {
	var baseline int
	var known bool
	var err error
	if set != nil {
		baseline, known, err = set.baseline(engineID)
	} else {
		baseline, known, err = crawlerSnapshotBaseline(engineID)
	}
	if err != nil {
		return fmt.Errorf("读取爬虫名单基线失败: %w", err)
	}
	if !known {
		return nil
	}
	if baseline >= 2 && newCount*2 < baseline {
		return fmt.Errorf("解析条数 %d 较当前快照 %d 收缩超过一半（疑似错误页/劫持），保留上次快照；如确认上游名单合法重构，需人工清理基线后重试", newCount, baseline)
	}
	return nil
}

// CrawlerIPListEntryCap 爬虫系统名单条目绝对上限。与产品口径
// handlers/securityiplists.go 的 ipListMaxEntries=2000 同义（services 不能
// import handlers，故此处单源声明并注明同义；两值漂移会让任务写入越过管理面
// 上限，与 AutobanListEntryCap 同型的跨包契约）。
const CrawlerIPListEntryCap = 2000

// crawlerSnapshotGrowthGuard 条数扩张门：源响应上限
// 16MB，通用 CIDR 提取后可产出数十万条，膨胀会放大 DB 行、
// crawler-ip-lists.json、插件每 10min 重载的前缀表与渲染期内存。
// 仅保留绝对上限 CrawlerIPListEntryCap；相对当前快照的合法扩张不拒绝。
// 拒绝时保留上次快照；调用方按源失败留痕（任务日志 ERROR + 源状态 failed +
// 运行审计「更新失败」），不在此重复记录。
func crawlerSnapshotGrowthGuard(newCount int) error {
	if newCount > CrawlerIPListEntryCap {
		return fmt.Errorf("解析条数 %d 超过系统名单上限 %d 条，拒绝写入（保留上次快照）", newCount, CrawlerIPListEntryCap)
	}
	return nil
}

// crawlerEngineDeclaredRanges 返回引擎声明的官方 IP 段（geoipnames 单一源）。
func crawlerEngineDeclaredRanges(engineID string) []string {
	for _, engine := range geoipnames.CrawlerEngines() {
		if engine.ID == engineID {
			return engine.IPRanges
		}
	}
	return nil
}

var crawlerUpdateManager = &CrawlerUpdateManager{}

func GetCrawlerUpdateManager() *CrawlerUpdateManager { return crawlerUpdateManager }

// RunUpdate 单轮全量更新（手动/自动同体）：逐源下载+解析+快照。
// 任一源失败记录失败态但**不回滚其它源**（与威胁库同语义：失败保留上次快照）。
// 任务时间源=task_runs.started_at（经 RunID，配置时区墙钟→UTC 存储）：
// 源 started_at/last_checked 与任务监控为同一时刻；业务流水统一写任务日志。
func (m *CrawlerUpdateManager) RunUpdate(ctx context.Context, rc taskengine.RunContext) (runErr error) {
	operator := rc.Operator
	if operator == "" {
		operator = "system"
	}
	outcome := "success"
	// emptyRound 标记「启用源均未到期，无更新」：审计动作仍为「更新」（与威胁
	// 族同口径），detail 显式声明空轮；「跳过」动作专留给降级中止。此前该轮
	// 把 outcome 置 skipped 充当审计词，导致同一语义在两族分叉到不同动作，且
	// 「跳过」同时承载降级的安全含义。
	emptyRound := false
	// 用户取消自动轮=显式放弃本槽（与失败同源）：把全部到期/空源槽推进到
	// 下一排程槽。引擎侧取消时已消费本槽，而未处理的到期源仍留在被消费的
	// 槽值上（引擎排程槽=启用源最早 next_update）——不推进则爬虫地址库自动
	// 更新永久静默停摆（含「取消落在开跑前、零源行写入」形态）。
	// demote/导入排空/进程停止的取消不推进（引擎侧同样不消费槽，恢复后补跑）。
	defer func() {
		if outcome == "cancelled" && userCancelledRun(ctx) {
			if err := advanceSourceSlotsAfterUserCancel("security_crawler_sources", rc.Trigger, nil, crawlerNextSlotStrict); err != nil {
				runErr = errors.Join(runErr, err)
			}
		}
	}()
	defer func() {
		detail := fmt.Sprintf("更新%s（触发：%s）", map[string]string{
			"success": "成功", "failed": "失败", "cancelled": "已取消", "skipped": "跳过",
		}[outcome], rc.Trigger)
		if emptyRound && outcome == "success" {
			detail = fmt.Sprintf("无到期源，本轮无更新（触发：%s）", rc.Trigger)
		}
		switch outcome {
		case "failed":
			RecordAuditLog(operator, "更新失败", "爬虫地址库", detail, "")
		case "cancelled":
			RecordAuditLog(operator, "取消", "爬虫地址库", detail, "")
		case "skipped":
			// 动作标签必须与终态同义：此前 skipped 落 default 记「更新」而
			// 详情写「跳过」，审计中心动作/详情自相矛盾。
			RecordAuditLog(operator, "跳过", "爬虫地址库", detail, "")
		default:
			RecordAuditLog(operator, "更新", "爬虫地址库", detail, "")
		}
	}()
	// changedCount/projectionConverged 供「正常收尾收敛」与「中止轮后置收敛」
	// 共用：循环内提前 return（取消/降级/角色不可判定）会绕过收尾的唯一收敛
	// 块，而前序源已写库的名单内容仍被 ACL/信任面引用——必须补一次收敛；
	// 正常收尾已收敛时置位，defer 据此保证整轮只收敛一次。
	var changedCount int
	projectionConverged := false
	defer func() {
		if changedCount > 0 && !projectionConverged {
			convergeCrawlerProjectionAfterAbortedRun()
		}
	}()
	if db.DB == nil {
		outcome = "failed"
		return errors.New("主库未初始化")
	}
	if isMaster, roleErr := RoleOf(context.Background(), db.DB); roleErr != nil {
		// 角色读取失败（DB 瞬断/脏行）≠从节点——按失败返回（task_runs/任务
		// 监控可见），不得静默跳过（二态复核把 DB 故障当从节点）。
		outcome = "failed"
		TaskLogfWarn("crawlerbot-update", "failed", "角色读取失败，无法判定本节点是否主节点，已中止爬虫地址更新: %v", roleErr)
		return fmt.Errorf("角色读取失败: %w", roleErr)
	} else if !isMaster {
		outcome = "skipped"
		TaskLogfWarn("crawlerbot-update", "skipped", "当前节点为从节点，终止爬虫地址更新")
		return taskengine.ErrTaskSkipped
	}
	if err := ctx.Err(); err != nil {
		outcome = "cancelled"
		return err
	}
	if err := ensureCrawlerSources(); err != nil {
		outcome = "failed"
		return err
	}
	sources, err := crawlerDueSources(rc.Trigger)
	if err != nil {
		outcome = "failed"
		return err
	}
	if len(sources) == 0 {
		// 与威胁族口径一致：无到期源按成功轮处理（task_runs 不记 skip），
		// 任务日志只留一条 INFO 业务摘要——此前写 skipped 级行与 task_runs
		// success 分叉；审计动作同族（「更新」+ detail 声明空轮），「跳过」不再
		// 混用（见 emptyRound 注释）。
		emptyRound = true
		TaskLogf("crawlerbot-update", "checking", "没有启用或到期的爬虫源，本轮无更新")
		return nil
	}
	TaskLogf("crawlerbot-update", "checking", "开始更新爬虫地址库（%d 个启用源）", len(sources))
	// 单轮迁移提升+基线缓存：名单名迁移幂等（逐源 upsert 各自重跑=每源
	// N 次 UPDATE），收缩/扩张门的名单基线逐门全量读（=每源 2 次全表读
	// +JSON 解析）——单轮内基线稳定（upsert 只写本源行，不影响其他源的
	// 基线），整轮共享一份预读。upsert 保留自迁移兜底（独立调用方契约不变）。
	if err := crawlerIPListMigrate(); err != nil {
		outcome = "failed"
		return fmt.Errorf("名单名迁移失败: %w", err)
	}
	baselines := loadCrawlerBaselineSet()
	runStarted := taskRunStartedAt(&rc)
	var firstErr error
	successCount, failedCount, totalEntries := 0, 0, 0
	for _, src := range sources {
		if isMaster, known := updateRunRole(); !known {
			// 角色读取失败≠降级——按失败返回（任务可见），不误报「从节点」。
			outcome = "failed"
			TaskLogfWarn("crawlerbot-update", "failed", "角色读取失败，无法判定本节点是否主节点，终止爬虫地址更新（已完成源保留）")
			return errors.New("角色读取失败，无法判定本节点是否主节点")
		} else if !isMaster {
			outcome = "skipped"
			TaskLogfWarn("crawlerbot-update", "skipped", "节点已降级为从节点，终止爬虫地址更新（已完成源保留）")
			return taskengine.ErrTaskSkipped
		}
		if err := ctx.Err(); err != nil {
			outcome = "cancelled"
			return err
		}
		if err := markCrawlerSourceRunning(src.Name, rc.Trigger, runStarted); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 标记运行失败: %w", src.Name, err)
			}
			failedCount++
			WriteCrawlerUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 标记运行失败: %v", src.Name, err))
			continue
		}
		TaskLogf("crawlerbot-update", "downloading", "下载 %s（%s）", src.Name, src.URL)
		var body string
		err = runWithInTaskRetry(ctx, func() error {
			var fetchErr error
			body, fetchErr = crawlerFetchBody(ctx, src)
			return fetchErr
		}, func(attempt int, wait time.Duration, rerr error) {
			TaskLogfWarn("crawlerbot-update", "retry", "源 %s 下载失败: %v；等待 %s 重试，第 %d 次，共 3 次", src.Name, rerr, wait, attempt)
		})
		if err != nil {
			if ctx.Err() != nil {
				if master, known := updateRunRole(); !known {
					// 取消归因不可判定（角色读取失败）——按失败返回（任务可见），
					// 不得并入「降级」或「手动取消」。
					outcome = "failed"
					TaskLogfWarn("crawlerbot-update", "failed", "角色读取失败，无法判定中止原因（降级/手动取消不可判定），终止爬虫地址更新")
					return errors.New("角色读取失败，无法判定中止原因")
				} else if !master {
					outcome = "skipped"
					TaskLogfWarn("crawlerbot-update", "skipped", "节点已降级为从节点，终止爬虫地址更新（已完成源保留）")
					return taskengine.ErrTaskSkipped
				}
				outcome = "cancelled"
				markCrawlerSourceCancelled(src.Name)
				TaskLogfWarn("crawlerbot-update", "cancelled", "源 %s 更新已手动取消（保留上次快照）", src.Name)
				return ctx.Err()
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 下载失败: %w", src.Name, err)
			}
			failedCount++
			markCrawlerSourceFailed(src.Name, rc.Trigger, "下载失败（保留上次快照）")
			WriteCrawlerUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", src.Name, err))
			continue
		}
		// 按源声明格式解析（json 源的非 JSON 响应=错误页 → 失败并
		// 保留上次快照；词法边界已排除版本号/日期等 IP 同形 token）。
		entries, perr := parseCrawlerCIDRsForFormat(body, src.Format)
		if perr == nil {
			// +：合理性门——
			// 子集（每条 ⊆ 官方段，取代旧交集判定）+ 覆盖（官方段全覆盖），
			// 一切格式同口径；错误页/超网/截断名单保留上次快照。
			entries, perr = validateCrawlerEntriesSanity(src.Name, entries)
		}
		if perr == nil {
			// 条数收缩门——较当前快照（DB/内置首版）收缩过半拒绝写入。
			perr = crawlerSnapshotShrinkGuard(src.Name, len(entries), &baselines)
		}
		if perr == nil {
			// 条数扩张门——仅绝对 2000 条上限，合法相对扩张不拒绝。
			perr = crawlerSnapshotGrowthGuard(len(entries))
		}
		if perr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 解析失败: %w", src.Name, perr)
			}
			failedCount++
			markCrawlerSourceFailed(src.Name, rc.Trigger, "解析或校验失败（保留上次快照）")
			WriteCrawlerUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", src.Name, perr))
			continue
		}
		// 成功写路径前复核（与威胁族同一写门 updateRunWriteGate）：下载/解析
		// 完成到 upsert 写库之间的降级窗口——循环顶部复核只覆盖源间边界，
		// 首源/唯一源的写库此前不经过任何复核。
		if gerr := updateRunWriteGate(ctx); gerr != nil {
			if errors.Is(gerr, errRunRoleUndecidable) {
				outcome = "failed"
				TaskLogfWarn("crawlerbot-update", "failed", "角色读取失败，无法判定本节点是否主节点，源 %s 结果未写库，终止爬虫地址更新", src.Name)
				return gerr
			}
			if errors.Is(gerr, taskengine.ErrTaskSkipped) {
				outcome = "skipped"
				TaskLogfWarn("crawlerbot-update", "skipped", "节点已降级为从节点，源 %s 结果未写库（从节点零写，由集群同步收敛）", src.Name)
				return gerr
			}
			outcome = "cancelled"
			markCrawlerSourceCancelled(src.Name)
			TaskLogfWarn("crawlerbot-update", "cancelled", "源 %s 更新已手动取消（结果未写库，保留上次快照）", src.Name)
			return gerr
		}
		changed, err := upsertCrawlerIPListChangedInner(src.Name, entries)
		if err != nil {
			// 部分提交收敛 部分提交收敛：DB 已更新而快照写失败时 upsert 返回
			// changed=true + err——DB 与投影/插件快照已分叉，仍须计入收敛面，
			// 由下方 changedCount>0 分支触发投影收敛对齐 DB（插件快照由下一轮
			// 源重试的 crawlerSnapshotMatchesEngine 校验自愈）。
			if changed {
				changedCount++
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 写名单失败: %w", src.Name, err)
			}
			failedCount++
			// 部分提交形态：DB 已落定而运行快照写失败时不得显示「保留上次
			// 快照」（与事实相反，面板排障会被误导）。
			failMsg := "名单写入失败（保留上次快照）"
			if changed {
				failMsg = "名单写入失败（数据库已更新，运行快照未写入）"
			}
			markCrawlerSourceFailed(src.Name, rc.Trigger, failMsg)
			WriteCrawlerUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", src.Name, err))
			continue
		}
		if changed {
			changedCount++
		}
		if merr := markCrawlerSourceSuccess(src.Name, rc.Trigger, len(entries)); merr != nil {
			if errors.Is(merr, errScheduleSlotNotAdvanced) {
				// 源行已 success、名单已写；只是排程槽未推进。不得补写 failed
				// 源态（与事实相反）——本轮按失败返回让引擎退避重投同一槽。
				WriteCrawlerUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 已更新但排程不可读，本轮排程槽未推进: %v", src.Name, merr))
				failedCount++
				if firstErr == nil {
					firstErr = fmt.Errorf("源 %s 排程槽未推进: %w", src.Name, merr)
				}
				continue
			}
			// 名单内容已写，但源状态机未闭环（源行停留 running/旧槽）：
			// 任务终态必须与源状态一致地记为失败，不得 success 掩盖。
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 写成功态失败: %w", src.Name, merr)
			}
			failedCount++
			WriteCrawlerUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 写成功态失败: %v", src.Name, merr))
			// 尽力补写 failed 终态：否则源行停留 running，自动更新随后被关闭
			// 时该行长期显示「运行中」。补写可能同样失败（通常就是 DB 写
			// 故障），失败不影响任务终态与计数。
			if ferr := markCrawlerSourceFailed(src.Name, rc.Trigger, "名单已写入但源状态写失败（下轮刷新状态）"); ferr != nil {
				WriteCrawlerUpdateLog("ERROR", "failed", fmt.Sprintf("源 %s 补写失败态失败: %v", src.Name, ferr))
			}
			continue
		}
		successCount++
		totalEntries += len(entries)
		TaskLogf("crawlerbot-update", "success", "源 %s 更新成功（%d 条，版本 %s）", src.Name, len(entries), time.Now().UTC().Format("2006.01.02"))
	}
	if failedCount > 0 {
		outcome = "failed"
		TaskLogfWarn("crawlerbot-update", "failed", "爬虫地址更新完成：成功 %d、失败 %d", successCount, failedCount)
	} else {
		TaskLogf("crawlerbot-update", "success", "爬虫地址更新完成：%d 个源成功，共 %d 条", successCount, totalEntries)
	}
	// 名单内容变化后的收敛——复用威胁库的单源热路径（投影重写
	// 零 /load；未证实收敛回退强制重载）。无变化/全失败不触碰 Caddy。
	if changedCount > 0 {
		// 收敛写路径前复核（与 upsert 前门同构）：投影重写/回退重载是主节点
		// 写面动作，降级/不可判定窗口不得执行（引用方由主节点后续轮收敛）。
		if gerr := updateRunWriteGate(ctx); gerr != nil {
			if errors.Is(gerr, errRunRoleUndecidable) {
				outcome = "failed"
				TaskLogfWarn("crawlerbot-update", "failed", "角色读取失败，无法判定本节点是否主节点，跳过名单投影收敛（引用方由后续轮次收敛）")
				return gerr
			}
			if errors.Is(gerr, taskengine.ErrTaskSkipped) {
				outcome = "skipped"
				TaskLogfWarn("crawlerbot-update", "skipped", "节点已降级为从节点，跳过名单投影收敛（从节点零写，引用方由主节点收敛）")
				return gerr
			}
			outcome = "cancelled"
			return gerr
		}
		projectionConverged = true
		convergeIPListProjectionAfterMutation("crawlerbot-update")
	}
	return firstErr
}

// crawlerAbortConvergeTimeout 是中止轮后置投影收敛的角色复核预算：用户取消
// 不得吞掉这次收敛，但复核窗口必须有界（DB 瞬断时不能无限拖住取消返回）。
const crawlerAbortConvergeTimeout = 30 * time.Second

// convergeCrawlerProjectionAfterAbortedRun 是中止轮（取消/降级/角色不可判定）
// 的后置投影收敛：循环内提前 return 会绕过收尾的唯一收敛块，而前序源已成功
// 写库的名单内容（changedCount>0）仍被 ACL/信任面引用——不收敛会让实际拦截
// 停在旧版，且同名内容不再变化时后续轮次不会重试。
// 复核口径不放松：主从/取消判定用脱离用户取消的有界上下文重跑一次，只有
// 主节点且角色可判定时才执行收敛；降级与角色不可判定一律零写（引用方由
// 主节点后续轮次收敛）。
func convergeCrawlerProjectionAfterAbortedRun() {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), crawlerAbortConvergeTimeout)
	defer cancel()
	switch gerr := updateRunWriteGate(cleanupCtx); {
	case gerr == nil:
		convergeIPListProjectionAfterMutation(CrawlerTaskID)
	case errors.Is(gerr, errRunRoleUndecidable):
		TaskLogfWarn(CrawlerTaskID, "failed", "中止轮：角色读取失败，无法判定本节点是否主节点，跳过名单投影收敛（引用方由后续轮次收敛）")
	case errors.Is(gerr, taskengine.ErrTaskSkipped):
		TaskLogfWarn(CrawlerTaskID, "skipped", "中止轮：节点已降级为从节点，跳过名单投影收敛（从节点零写，引用方由主节点收敛）")
	default:
		TaskLogfWarn(CrawlerTaskID, "unchanged", "中止轮：名单投影收敛复核未通过，跳过收敛（引用方由后续轮次收敛）: %v", gerr)
	}
}

// convergeIPListProjectionAfterMutation 内置名单（system=1，可被 ACL/信任面
// 引用）内容变化后的生效路径
//   - 投影刷新器已注册 → RefreshIPListProjections（毫秒级、零 /load，
//     @ipListFast 匹配器 ≤1s stat 热感知）；
//   - 未证实收敛（发射面变化/运行配置不可读/刷新被拒）或回调未注册 →
//     回退全量 /load（宁可一次重载，不欠引用方渲染收敛）。
func convergeIPListProjectionAfterMutation(task string) {
	if threatProjectionRefresher == nil {
		TaskLogfWarn(task, "unchanged", "投影刷新器未注册，跳过名单投影热路径（引用方由下次配置变更收敛）")
		return
	}
	hot, err := threatProjectionRefresher()
	if err == nil && hot == ProjectionConverged {
		TaskLogf(task, "hot", "名单内容变化经投影热路径收敛（零 Caddy 重载）")
		return
	}
	TaskLogf(task, "reloading", "投影热路径未证实收敛，回退重载 Caddy 配置")
	if threatReloader == nil {
		TaskLogfWarn(task, "reloading", "重载回调未注册，引用方渲染由下次配置变更收敛")
		return
	}
	// 真实 /load 与同族（threat_update/autoban/crs/ip2region）同口径
	// 留系统重载审计——此前爬虫路径只写应用日志，审计中心无记录。
	rerr := threatReloader()
	recordSystemReloadAudit("crawlerbot_update", rerr)
	if rerr != nil {
		Logf("error", "爬虫地址库: 名单变化后重载失败: %v", rerr)
		TaskLogfWarn(task, "reloading", "重载 Caddy 配置失败: %v", rerr)
	}
}

// markCrawlerSourceRunning 源开始态：任务开始时刻统一以 UTC 写 started_at/
// last_checked，前端按配置时区展示，避免墙钟被二次 +8h。
func markCrawlerSourceRunning(name, trigger, started string) error {
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='running', message='', trigger=?, started_at=?, last_checked=?, updated_at=datetime('now') WHERE name=?`,
		trigger, started, started, name)
	return err
}

// crawlerSlotAdvanceSQL 爬虫源族失败落的推进门：仅 auto 触发且现存槽空/过期
// 才推进——手动失败不动预约（引擎按退避重投同一槽，业务抢先推进会把该自动槽
// 静默吃掉）。成功落见 crawlerSlotSuccessSQL（auto/manual 同权）。
const crawlerSlotAdvanceSQL = `next_update=IIF(` + slotAdvanceGateSQL + `, ?, next_update)`

// crawlerSlotSuccessSQL 爬虫源族成功落的推进门：auto/manual 同权（仅空/过期
// 槽），失败落仍走 crawlerSlotAdvanceSQL（仅 auto）。
const crawlerSlotSuccessSQL = `next_update=IIF(` + slotSuccessGateSQL + `, ?, next_update)`

// crawlerSlotSuccessAssign 爬虫源族成功落的赋值片段与参数（成功门 trigger
// 两次 + 槽值）。排程不可读时返回 no-op 片段与错误：状态照常落库、预约保持
// 旧值，调用方必须把本轮按失败返回给任务引擎（成功轮不推进槽却回 success
// 会被引擎消费本槽——该族自动更新静默停摆，见 errScheduleSlotNotAdvanced）。
func crawlerSlotSuccessAssign(trigger string) (string, []any, error) {
	slotSQL, slotArgs, err := slotAssign(crawlerSlotSuccessSQL, trigger, 2, func() (string, error) {
		return crawlerNextSlotStrict(time.Now().UTC())
	})
	if err != nil {
		return noopSlotAssignSQL, nil, fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	return slotSQL, slotArgs, nil
}

// crawlerSlotAdvanceAssign 爬虫源族失败落的赋值片段与参数（仅 auto 推进）。
func crawlerSlotAdvanceAssign(trigger string) (string, []any) {
	slotSQL, slotArgs, err := slotAssign(crawlerSlotAdvanceSQL, trigger, 1, func() (string, error) {
		return crawlerNextSlotStrict(time.Now().UTC())
	})
	if err != nil {
		return noopSlotAssignSQL, nil
	}
	return slotSQL, slotArgs
}

// markCrawlerSourceSuccess 源成功态：entry_count 更新 + version=成功日期 +
// consecutive_failures 清零 + next_update 按排程槽推进门更新。返回落库错误
// （与威胁族 markSourceSuccess 同口径）：吞错会让任务终态 success 而源行停留
// running、next_update 不推进——任务日志与源状态机互相矛盾。
func markCrawlerSourceSuccess(name, trigger string, entryCount int) error {
	slotSQL, slotArgs, slotErr := crawlerSlotSuccessAssign(trigger)
	args := append(append([]any{entryCount, time.Now().UTC().Format("2006.01.02")}, slotArgs...), name)
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET entry_count=?, version=?, update_status='success', message='', consecutive_failures=0, `+slotSQL+`, finished_at=datetime('now') WHERE name=?`,
		args...)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写成功态失败: %v", name, err)
		return err
	}
	// 状态列已落库但排程槽未推进（排程不可读）：按错误上抛，让调用方把本轮
	// 记为失败（引擎退避重投 1s/5s/30s；连续 4 轮仍未推进由引擎停调）——源
	// 状态 success + 过期槽会让引擎按「成功未推进」消费本槽，该族自动更新
	// 静默停摆。
	if slotErr != nil {
		Logf("error", "crawlerbot-update: 源 %s 排程不可读，本轮排程槽未推进（引擎将退避重投）: %v", name, slotErr)
	}
	return slotErr
}

// markCrawlerSourceCancelled 用户取消终态：保留上次快照、版本与失败计数，
// 源行自身不推进排程槽——用户取消自动轮时由 RunUpdate 的收口统一推进全部
// 到期源槽（advanceSourceSlotsAfterUserCancel），demote/导入排空/进程停止的
// 取消则两者都不推进。返回落库错误（取消轮本身已记终态，调用方仅留痕）。
func markCrawlerSourceCancelled(name string) error {
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='cancelled', message='已手动取消（保留上次快照）', finished_at=datetime('now') WHERE name=?`, name)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写取消态失败: %v", name, err)
	}
	return err
}

// markCrawlerSourceFailed 源失败态：consecutive_failures+1、next_update 按
// 同一推进门更新（退避机制已撤除；失败保留上次快照，内容表 entries 不动）。
// message 由调用方给出真实失败类别——面板按该文案排障，常量文案会把「名单
// 已更新而快照写失败」误述成「保留上次快照」。
// 返回落库错误（同 markCrawlerSourceSuccess）。
func markCrawlerSourceFailed(name, trigger, message string) error {
	slotSQL, slotArgs := crawlerSlotAdvanceAssign(trigger)
	args := append(append([]any{message}, slotArgs...), name)
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='failed', message=?, consecutive_failures=consecutive_failures+1, `+slotSQL+`, finished_at=datetime('now') WHERE name=?`, args...)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写失败态失败: %v", name, err)
	}
	return err
}
