package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 规则库定时调度（v2.3.x）：CRS/IP2Region/威胁情报库三个更新任务的排程从固定
// 24h 间隔改为「星期多选 + 时间」可配置——DB 存逗号串星期（1=周一…7=周日，
// 默认全选=每天）与 HH:MM（默认 04:00），槽位按基础设置时区（CurrentLocation）
// 的本地日历计算、UTC 落库。到期判定走 next_update<=now。
// 2026-09-25 用户裁定（排程语义重构）：①任务必须真正按设置的日期+时间触发
// ——next_update 恒为排程槽（真实触发时间），失败退避不再改写它（原 1h/指数
// 退避覆写机制撤除）；②失败重试在当前任务内完成（见下方 updateMaxAttempts），
// 日志记「第 x 次，共 x 次」；重试耗尽后任务落定 failed，下一运行=下一排程槽。

const (
	// 治理默认单源在 db（fresh DDL DEFAULT / 迁移补列同源，钉测见
	// db_truth_defaults_test）；services 读失败兜底直接引用，不另写字面量。
	defaultScheduleDays = db.DefaultScheduleDays
	defaultScheduleTime = db.DefaultScheduleTime
)

// 排程槽推进门共享 SQL 片段：现存槽空/过期才推进（未来槽不回拨）。此前同一
// 谓词在 CRS/IP2Region/威胁/爬虫四族多处内联重复（同型漏同步两起），此处收敛
// 为单一事实源；参数序恒为「触发来源（auto 门 1 个 / 成功门 2 个）、下一槽值（?）」。
// 分族前缀：版本表族（CRS/IP2Region）在谓词前叠加 auto_update=1 门；
// 威胁/爬虫源族无 auto_update 列（启用门走 WHERE update_enabled=1 重排，见
// scheduleThreatSources），不加该前缀。advanceVersionSlotIfDue 的
// IIF(auto_update=1, ?, next_update) 是另一形态（触发门由调用方
// advanceSlotIfAuto 前置，此处只判 auto_update），刻意不并入。
//
// 触发门分两态（引擎侧 success/failed/cancelled 的消费语义不同）：
//   - 失败/取消：仅 auto 推进——手动轮失败时引擎按退避重投同一槽，业务若抢先
//     推进会把该自动槽静默吃掉。
//   - 成功：auto 推进空/过期槽；manual 只推进**已过期**槽。引擎成功轮（含
//     手动轮）会消费过期槽，业务侧不推进则水位与业务槽单边分叉：tick 的
//     「槽 > 已消费水位」门永不成立，四族自动更新永久静默停摆（人工反复
//     「立即更新」只会反复加固）。空槽不在 manual 范围：零值槽不会进入引擎的
//     消费分支（无停摆面），且「手动成功不得替空槽建立预约」是既有裁定——
//     预约只由排程保存/启用/启动武装路径建立。
const (
	// slotExpiredSQL 现存槽非空且已过期。比较两侧都过 datetime()：裸
	// TEXT 字典序会把 RFC3339 形态（'T'=0x54 > ' '=0x20）的过期槽判成未来，
	// 与 parseUTCSlot 的双布局容错口径分叉（旧备份/快照带入的 RFC3339 槽）。
	// 非空但不可解析 → datetime() 为 NULL → 比较为 NULL（按未来处理，不推进）。
	slotExpiredSQL = `COALESCE(next_update,'')<>'' AND datetime(next_update)<=datetime('now')`
	// slotEmptyOrExpiredSQL 现存槽空或已过期。
	slotEmptyOrExpiredSQL = `(COALESCE(next_update,'')='' OR datetime(next_update)<=datetime('now'))`
	// slotAdvanceGateSQL 失败/取消路径的推进门：仅 auto 触发。
	slotAdvanceGateSQL = `?='auto' AND ` + slotEmptyOrExpiredSQL
	// slotSuccessGateSQL 成功路径的推进门：auto 空/过期 + manual 仅过期。
	slotSuccessGateSQL = `(?='auto' AND ` + slotEmptyOrExpiredSQL + `) OR (?='manual' AND ` + slotExpiredSQL + `)`
	// versionTableSlotSuccessSQL 版本表族（security_crs_version/
	// security_ip2region_version）成功落的 next_update 赋值片段。
	versionTableSlotSuccessSQL = `next_update=IIF(auto_update=1 AND (` + slotSuccessGateSQL + `), ?, next_update)`
	// threatSlotSuccessSQL 威胁源族（security_threat_sources）成功落的
	// next_update 赋值片段。
	threatSlotSuccessSQL = `next_update=IIF(` + slotSuccessGateSQL + `, ?, next_update)`
	// threatSlotAdvanceSQL 威胁源族失败落（仅 auto 推进）。
	threatSlotAdvanceSQL = `next_update=IIF(` + slotAdvanceGateSQL + `, ?, next_update)`
	// versionTableSlotAdvanceSQL 版本表族失败/取消落（仅 auto_update 开推进）。
	versionTableSlotAdvanceSQL = `next_update=IIF(auto_update=1, ?, next_update)`
	// noopSlotAssignSQL 是「排程不可读」时写路径的 next_update 赋值片段：
	// 保持原值。写路径的读侧口径不是 fail-soft 的默认排程——一次瞬时读失败
	// 若按默认「每天 04:00」算槽并落库，会把用户的「星期几 + HH:MM」覆盖成
	// 未选择的日子（下一次越档执行后才自愈）。拿不到口径就不写预约，状态列
	// 照常落库。
	noopSlotAssignSQL = `next_update=next_update`
)

// errScheduleSlotNotAdvanced 标记「本轮排程槽未推进」——写路径严格读排程
// 失败（库未初始化/排程列不可读），或状态行写入失败（槽随之没落地）。
//
// 成功路径必须把该结果按失败返回给任务引擎，不得以 success 收尾：引擎的
// 「成功落定+槽仍到期」分支会把本槽记入 schedDoneSlot（同一槽只执行一次的
// 水位），此后 tick 的「槽 > 已消费水位」门永久拒绝该槽——业务槽停在过去、
// 也没有「下一次成功/失败落库」可以自愈，该族自动更新就此静默停摆。失败轮
// 走引擎的退避重投（1s/5s/30s）；连续 4 轮仍未推进即由引擎停调
// （ScheduleStopReasonFailStreak），读恢复后需在业务页重新保存一次或重启
// 进程重新武装——不是静默停摆，但也不是无人工自愈。
var errScheduleSlotNotAdvanced = fmt.Errorf("本轮排程槽未推进（排程不可读或状态行写入失败）: %w", taskengine.ErrScheduleSlotNotAdvanced)

// userCancelledRun 本轮是否由用户显式取消（任务监控「取消」/前端取消入口）。
// 引擎在用户取消路径给运行 ctx 标记 ErrUserCancelled 取消原因；demote 中止/
// 导入排空/进程停止走普通取消（context.Canceled）——三者保留「恢复后到期轮
// 补跑」语义，只有用户取消需要把排程槽当作显式放弃推进到下一槽（与失败
// 同源），否则引擎已消费本槽而业务槽恒过期 → 自动更新永久静默停摆。
func userCancelledRun(ctx context.Context) bool {
	return ctx != nil && errors.Is(context.Cause(ctx), taskengine.ErrUserCancelled)
}

// advanceSourceSlotsAfterUserCancel 源表族（威胁情报/爬虫地址）用户取消
// 自动轮后的槽推进：单源取消只覆盖在途那一行，循环中止后其余到期源的槽
// 仍是旧值——而引擎的排程槽=启用源最早 next_update，任一源留在被消费的槽值
// 上即可永久压住整个任务。故按同一推进门处理全部到期/空槽行（未来槽不回拨），
// 语义=「本槽放弃，预约下一槽」。
//
// names 是该族运行域（威胁族传注册表源名，爬虫族传 nil=全部启用行）：槽域
// 必须 ⊆ 运行域，否则取消路径会把注册表外的惰性槽重新写回，与启动期清理、
// 读侧寻槽、保存排程的收窄互相抵消。slotOf 取严格读形态——排程不可读时本轮
// 不推进（失败已由严格读单源留痕），不得用默认排程覆盖用户的预约。
func advanceSourceSlotsAfterUserCancel(table, trigger string, names []string, slotOf func(time.Time) (string, error)) error {
	if trigger != "auto" {
		// 手动轮不改变预约（引擎侧同样不消费手动轮的槽）。
		return nil
	}
	// 引擎运行体内（后台）写路径：与读侧同源走原子句柄。
	database := db.GetDB()
	if database == nil {
		return fmt.Errorf("%w: 数据库未初始化", errScheduleSlotNotAdvanced)
	}
	slot, err := slotOf(time.Now().UTC())
	if err != nil {
		return fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	nameClause, nameArgs := sourceNameSetClause("name", names, false)
	if _, err := database.Exec(`UPDATE `+table+` SET next_update=IIF(`+slotAdvanceGateSQL+`, ?, next_update) WHERE update_enabled=1`+nameClause,
		append([]any{trigger, slot}, nameArgs...)...); err != nil {
		return fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	return nil
}

// setVersionTableAutoUpdate 版本表族（CRS/IP2Region）自动更新开关的单源写侧：
// 行缺失先按 seed 播种（INSERT OR IGNORE），再写标志与排程槽，最后联动任务
// 调度。两族此前三句 SQL 逐字同构（含「失败退避撤除」裁定），任一处改动都
// 需双点同步；label 仅用于保留各族既有错误文案，taskID 联动调度。
//
// 排程槽生命周期（2026-10-11 用户裁定）：仅 auto 且现存槽空/过期才由运行侧
// 推进；此处开关动作立即重排程——开启写下一槽、关闭无条件清空（2026-09-25
// 用户裁定：失败退避机制撤除）。
func setVersionTableAutoUpdate(table, label, seed, taskID string, enabled bool) error {
	// 两步写事务化（与同文件 setVersionTableSchedule 同构）：INSERT 成功而
	// UPDATE 失败会留「行已建、排程未生效、next_update 为空」的中间态——开关
	// 显示已开、任务永不触发，且失败只经一次 handler 错误响应留痕，之后无人
	// 复查。
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("开启 %s 自动更新事务: %w", label, err)
	}
	defer func() { _ = tx.Rollback() }() // 已 Commit 后为 no-op
	if _, err := tx.Exec(
		"INSERT OR IGNORE INTO "+table+" (id, version, auto_update) VALUES (1, ?, ?)",
		seed, enabled,
	); err != nil {
		return fmt.Errorf("初始化 %s 版本记录: %w", label, err)
	}
	nextUpdate := ""
	if enabled {
		// 事务内读排程两列（事务外读看不到刚建的行）——与 versionTableNextSlot
		// 同一槽计算单源。
		days, hhmm, serr := versionTableScheduleTx(tx, table)
		if serr != nil {
			return fmt.Errorf("读取 %s 排程: %w", label, serr)
		}
		nextUpdate = NextScheduledSlot(time.Now().UTC(), days, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
	}
	if _, err := tx.Exec("UPDATE "+table+" SET auto_update=?, next_update=CASE WHEN ? THEN ? ELSE '' END WHERE id=1", enabled, enabled, nextUpdate); err != nil {
		return fmt.Errorf("更新 %s 自动更新开关: %w", label, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交 %s 自动更新事务: %w", label, err)
	}
	// 调度应用走与业务驱动整轮对齐共用的互斥（避免「库新/loop 旧」交错）；
	// 应用值在锁内按库实态读取，本参数仅作读失败回退。
	applyBusinessTaskLoop(taskID, enabled)
	return nil
}

// ensureVersionTableRow 版本表族种子行单源：仅行缺失时按 seed 播种
// （auto_update 默认 ON，logPrefix 保留各族既有日志前缀）。
func ensureVersionTableRow(table, seed, logPrefix string) {
	if _, err := db.DB.Exec(
		"INSERT OR IGNORE INTO "+table+" (id, version, auto_update) VALUES (1, ?, TRUE)",
		seed,
	); err != nil {
		Logf("error", "%s: failed to ensure version row: %v", logPrefix, err)
	}
}

// parseUTCSlot 解析 DB 存的 UTC 排程串为 time.Time（crsTimeLayout 与
// RFC3339 双形态——与 localDisplayUTC 同口径）。
func parseUTCSlot(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{crsTimeLayout, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ParseUTCTimeDual 双布局 UTC 时间解析的包外入口（单源=parseUTCSlot：
// crsTimeLayout 平面串 + RFC3339 双形态）。cert_jobs 等 UTC 时间列的消费方
// （handlers cert-job 历史等）一律走本入口，禁止另写单布局 time.Parse——
// 驱动/列表达式形态变化时单布局解析会静默归零（时间列空 + duration=0）。
func ParseUTCTimeDual(s string) (time.Time, bool) {
	t := parseUTCSlot(s)
	return t, !t.IsZero()
}

// RearmScheduleSlotsAfterTimezoneChange 时区变更后按新时区重算四个已武装
// 排程族的**未来**槽（CRS/IP2Region 版本表单行 + 威胁/爬虫源表逐启用行）。
// 排程槽按配置时区本地日历计算、UTC 落库——时区切换后旧槽仍按旧偏移触发
// （「下次执行」展示与实际触发同错）。已过期槽不动（到期补跑语义保留，
// 重排会吞掉等待中的补跑轮）；空槽不动（首槽武装归 armSecurityLibraryFirstSlots）。
// 调用前必须已完成 ConfigureLocation（CurrentLocation 已是新时区）。
// 自动备份族无落库槽（NextSlotFn 按设置实时计算），天然随新时区生效。
func RearmScheduleSlotsAfterTimezoneChange() {
	// 后台/时区重排路径统一走原子句柄（本包口径见 logrotate/tz）：同步侧
	// db.DB 与后台 db.GetDB() 分裂时，重排会写一个库、调度器读另一个库。
	database := db.GetDB()
	if database == nil {
		return
	}
	now := time.Now().UTC()
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		var nextUpdate string
		if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM ` + table + ` WHERE id=1`).Scan(&nextUpdate); err != nil {
			Logf("warn", "时区变更重排：读取 %s 排程失败: %v", table, err)
			continue
		}
		// auto_update 关闭时也重排：该列是「下次更新」展示槽的唯一来源
		// （GetCRSInfo/GetIP2RegionInfo 直读），与 setVersionTableSchedule
		// 「关闭时也重排 next_update，调度器仍受开关门控」同口径——否则切换
		// 时区后前端换算出的展示时刻仍按旧偏移。
		if nextUpdate == "" {
			continue
		}
		if slot := parseUTCSlot(nextUpdate); slot.IsZero() || !slot.After(now) {
			continue // 过期槽保留（补跑）；非法串由首槽武装/保存路径自愈
		}
		slot, serr := versionTableNextSlotStrict(table, now)
		if serr != nil {
			// 排程不可读：不写（留痕已由严格读单源），旧槽保留——
			// 用默认排程写回会把用户的星期/HH:MM 覆盖成未选择的日子。
			continue
		}
		if _, err := database.Exec(`UPDATE `+table+` SET next_update=? WHERE id=1`, slot); err != nil {
			Logf("warn", "时区变更重排：%s 写入 next_update 失败: %v", table, err)
		}
	}
	// 威胁/爬虫源表：逐启用行重排（行键不同——威胁按 id、爬虫按 name）。
	// 两族均带注册表名过滤（与读侧寻槽、首槽武装同源）：注册表外启用行的槽
	// 不属于运行域，重排只会把被清理的惰性槽又写回去。
	// 槽函数取严格形态（与版本表族同口径）：排程不可读时整表跳过——fail-soft
	// 变体会把用户的「星期几 + HH:MM」写成默认 04:00 的未来槽（一次性越档
	// 执行），读失败已由严格读单源留痕。
	for _, st := range []struct {
		table  string
		keyCol string
		slotFn func(time.Time) (string, error)
		names  []string
	}{
		{"security_threat_sources", "id", threatNextSlotStrict, threatSourceRegistryNames()},
		{"security_crawler_sources", "name", crawlerNextSlotStrict, crawlerSourceRegistryNames()},
	} {
		slot, slotErr := st.slotFn(now)
		if slotErr != nil {
			// 排程不可读：本表本轮不重排（旧槽保留，下一轮重排/保存排程自愈）。
			continue
		}
		nameClause, nameArgs := sourceNameSetClause("name", st.names, false)
		rows, err := database.Query(`SELECT `+st.keyCol+`, COALESCE(next_update,'') FROM `+st.table+`
			WHERE update_enabled=1 AND COALESCE(next_update,'')<>''`+nameClause, nameArgs...)
		if err != nil {
			Logf("warn", "时区变更重排：读取 %s 排程失败: %v", st.table, err)
			continue
		}
		type rearm struct {
			key  string
			slot string
		}
		var rearms []rearm
		for rows.Next() {
			var key, nextUpdate string
			if err := rows.Scan(&key, &nextUpdate); err != nil {
				Logf("warn", "时区变更重排：%s 行扫描失败（跳过该行）: %v", st.table, err)
				continue
			}
			if cur := parseUTCSlot(nextUpdate); cur.IsZero() || !cur.After(now) {
				continue // 过期槽保留（补跑语义）
			}
			rearms = append(rearms, rearm{key: key, slot: slot})
		}
		if err := rows.Err(); err != nil {
			Logf("warn", "时区变更重排：%s 迭代失败（部分行未重排）: %v", st.table, err)
		}
		rows.Close()
		for _, ra := range rearms {
			if _, err := database.Exec(`UPDATE `+st.table+` SET next_update=? WHERE `+st.keyCol+`=?`, ra.slot, ra.key); err != nil {
				Logf("warn", "时区变更重排：%s(%s=%s) 写入 next_update 失败: %v", st.table, st.keyCol, ra.key, err)
			}
		}
	}
}

// NormalizeScheduleDays 归一写侧输入：过滤非法值、去重、升序；结果为空表示
// 输入无有效星期（调用方按校验失败拒绝）。
func NormalizeScheduleDays(days []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(days))
	for _, d := range days {
		if d < 1 || d > 7 || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// ParseScheduleDays 解析 DB 逗号串星期集（非法值过滤、去重、升序）。
func ParseScheduleDays(s string) []int {
	var raw []int
	for _, part := range strings.Split(s, ",") {
		if d, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			raw = append(raw, d)
		}
	}
	return NormalizeScheduleDays(raw)
}

// FormatScheduleDays 序列化星期集为逗号串（与 ParseScheduleDays 互逆）。
func FormatScheduleDays(days []int) string {
	norm := NormalizeScheduleDays(days)
	parts := make([]string, 0, len(norm))
	for _, d := range norm {
		parts = append(parts, strconv.Itoa(d))
	}
	return strings.Join(parts, ",")
}

// ValidScheduleHHMM 校验 "HH:MM"（24 小时制，补零两位）——端点 400 判定用。
func ValidScheduleHHMM(hhmm string) bool {
	_, _, ok := parseAutoBackupHHMM(hhmm)
	return ok
}

// NextScheduledSlot 计算 now 之后的下一个排程槽：候选=loc 本地日历的 hh:mm，
// 当日在星期集内且候选>now 则取当日，否则向后扫描至多 8 天取首个命中。
// days 空/全非法 → 兜底全周；hhmm 非法 → 兜底治理默认时间（db.
// DefaultScheduleTime，与 DDL/迁移同源）。返回值带 loc 时区，落库端取 .UTC()。
func NextScheduledSlot(now time.Time, days []int, hhmm string, loc *time.Location) time.Time {
	hour, minute, ok := parseAutoBackupHHMM(hhmm)
	if !ok {
		// 兜底值必须与治理默认同源：本函数是导出纯函数，handler/测试可直接
		// 调用，写死 04:00 会在默认时间变更后形成隐形分叉。默认值本身不可
		// 解析时才退到显式兜底（保持永不失败的纯函数契约）。
		hour, minute = 4, 0
		if h, m, ok := parseAutoBackupHHMM(defaultScheduleTime); ok {
			hour, minute = h, m
		}
	}
	set := map[int]bool{}
	for _, d := range NormalizeScheduleDays(days) {
		set[d] = true
	}
	if len(set) == 0 {
		for d := 1; d <= 7; d++ {
			set[d] = true
		}
	}
	local := now.In(loc)
	base := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	for i := 0; i < 8; i++ {
		day := base.AddDate(0, 0, i)
		iso := int(day.Weekday())
		if iso == 0 {
			iso = 7
		}
		if !set[iso] {
			continue
		}
		// 墙面分量重组：跨 DST 时槽位仍落在本地 hh:mm（AddDate 直接加时长会漂移）
		slot := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, 0, 0, loc)
		if slot.After(now) {
			return slot
		}
	}
	// 兜底全周时 8 天扫描必有命中；零值=防御不可达
	return time.Time{}
}

// validateScheduleInput 写侧统一校验（服务层纵深防御；端点先做同口径 400 判定）。
func validateScheduleInput(days []int, hhmm string) ([]int, error) {
	norm := NormalizeScheduleDays(days)
	if len(norm) == 0 {
		return nil, fmt.Errorf("至少选择一天")
	}
	if !ValidScheduleHHMM(hhmm) {
		return nil, fmt.Errorf("时间格式无效（HH:MM）")
	}
	return norm, nil
}

// normalizeScheduleRow 读取端归一：空/非法值回落默认（与 newColumns 默认对齐）。
func normalizeScheduleRow(daysRaw, hhmm string) ([]int, string) {
	days := ParseScheduleDays(daysRaw)
	if len(days) == 0 {
		days = ParseScheduleDays(defaultScheduleDays)
	}
	if !ValidScheduleHHMM(hhmm) {
		hhmm = defaultScheduleTime
	}
	return days, hhmm
}

// scheduleRowQuerier 是排程读取的句柄面：展示/调度判定读原子句柄
// （*sql.DB），写事务内必须先建行再算槽、只能读事务视图（*sql.Tx）。
type scheduleRowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// versionTableScheduleQuery / globalTaskScheduleQuery 是排程两列查询的单源
// （表名与列前缀均由包内固定传入，不接受外部输入）。
func versionTableScheduleQuery(table string) string {
	return `SELECT COALESCE(schedule_days,''), COALESCE(schedule_time,'') FROM ` + table + ` WHERE id=1`
}

func globalTaskScheduleQuery(prefix string) string {
	return `SELECT COALESCE(` + prefix + `_schedule_days,''), COALESCE(` + prefix + `_schedule_time,'') FROM global_config WHERE id=1`
}

// scheduleRow 读取排程两列并归一，不做默认兜底、不留痕——兜底与留痕的差异
// 是读侧（fail-soft）与写路径（fail-visible）的语义差别，由 scheduleRead
// 的调用方决定，读取本身只有一个实现。
func scheduleRow(querier scheduleRowQuerier, query string) ([]int, string, error) {
	var daysRaw, hhmm string
	if err := querier.QueryRow(query).Scan(&daysRaw, &hhmm); err != nil {
		return nil, "", err
	}
	days, normHHMM := normalizeScheduleRow(daysRaw, hhmm)
	return days, normHHMM, nil
}

// scheduleRead 是排程读取的单源：读两列 + 归一 + 读失败/恢复留痕。
// key 区分配置项（schedule-read-<表|前缀>），首报 warn、恢复 info——
// 事务外与事务内两个变体只差句柄。
func scheduleRead(querier scheduleRowQuerier, key, query string) ([]int, string, error) {
	days, hhmm, err := scheduleRow(querier, query)
	if err != nil {
		logScheduleReadFailure(key, err)
		return nil, "", err
	}
	logScheduleReadRecovered(key)
	return days, hhmm, nil
}

// versionTableSchedule 读版本表（CRS/IP2Region）排程两列。
func versionTableSchedule(table string) ([]int, string) {
	// 引擎 tick 读侧（EnabledFn/NextSlotFn）消费原子句柄：与 tz/logrotate 同源。
	database := db.GetDB()
	if database == nil {
		return normalizeScheduleRow(defaultScheduleDays, defaultScheduleTime)
	}
	days, hhmm, err := scheduleRead(database, "schedule-read-"+table, versionTableScheduleQuery(table))
	if err != nil {
		return normalizeScheduleRow(defaultScheduleDays, defaultScheduleTime)
	}
	return days, hhmm
}

// errScheduleUnavailable 排程不可读（库句柄未初始化）——写路径按「口径未知」
// 处理：不推进槽，保留旧预约。
var errScheduleUnavailable = errors.New("排程不可读（数据库未初始化）")

// versionTableScheduleStrict 写路径的排程读取：失败返回 error，不做默认排程
// 兜底。读侧 fail-soft（versionTableSchedule）服务展示与调度判定——其默认值
// 若被写路径复用，一次瞬时读失败就会把用户的「星期几 + HH:MM」覆盖成默认
// 「每天 04:00」的下一槽（未选择的日子真的执行一次后才自愈）。写路径拿不到
// 口径就不写。
func versionTableScheduleStrict(table string) ([]int, string, error) {
	database := db.GetDB()
	if database == nil {
		return nil, "", errScheduleUnavailable
	}
	return scheduleRead(database, "schedule-read-"+table, versionTableScheduleQuery(table))
}

// logScheduleReadFailure 排程/配置读取失败的状态转换留痕（文案必须是通用
// 「读取配置失败（key）」，因为 LogConfigReadFailure 把本 helper 复用到审计页
// 时区、请求体上限、日志统计阈值等非排程配置项——此前文案写死「读取任务
// 排程失败」，审计页时区值非法时排障者被引向调度器）。// 此前三处读取错误
// 全部静默——库不可读/表缺失时威胁库、爬虫地址库、CRS、
// IP2Region 自动更新「静默停摆」（auto_update 读成 false + 槽位空），排障
// 零信号。按首报留痕（同 tz/logrotate 的 logStateTransition 口径），恢复时
// 补一条 info，避免 30s/60s 轮询刷日志。
func logScheduleReadFailure(key string, err error) {
	if lvl := logStateTransition(key, true); lvl != "" {
		Logf(lvl, "读取配置失败（%s），按默认值继续: %v", key, err)
	}
}

func logScheduleReadRecovered(key string) {
	if lvl := logStateTransition(key, false); lvl != "" {
		Logf(lvl, "读取配置已恢复（%s）", key)
	}
}

// LogConfigReadFailure / LogConfigReadRecovered 排程/配置读失败留痕的包外
// 入口（与 logScheduleReadFailure 同一状态机单源）——handlers
// 侧配置直读（如日志统计阈值读取）复用；文案以 key 区分配置项，禁止另造
// 静默或每轮刷屏的平行实现。
func LogConfigReadFailure(key string, err error) { logScheduleReadFailure(key, err) }
func LogConfigReadRecovered(key string)          { logScheduleReadRecovered(key) }

// ResetLogStateTransitionForTest 清空某 key 的状态转换记忆（同一 key 的状态
// 跨用例共享，不复位会让「首次失败留痕」断言读到前一用例的残留态）。
func ResetLogStateTransitionForTest(key string) {
	metricsStateMu.Lock()
	delete(metricsStateFailed, key)
	for i, k := range metricsStateOrder {
		if k == key {
			metricsStateOrder = append(metricsStateOrder[:i], metricsStateOrder[i+1:]...)
			break
		}
	}
	metricsStateMu.Unlock()
}

// versionTableNextUpdate 读版本表当前排程槽（空串=未排程）——同批，
// 引擎 NextSlotFn 的 DB 直读数据源（不经管理器实例）。
func versionTableNextUpdate(table string) string {
	// nil 库守卫——NextSlotFn fail-closed（零值槽）；句柄走原子读取。
	database := db.GetDB()
	if database == nil {
		return ""
	}
	var s string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM ` + table + ` WHERE id=1`).Scan(&s); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			logScheduleReadFailure("schedule-next-update-"+table, err)
		}
		return ""
	}
	logScheduleReadRecovered("schedule-next-update-" + table)
	return s
}

// nextSlotFrom 是槽计算的单源（排程两列 + 基准时刻 → UTC 落库串）：读侧
// fail-soft 与写路径严格读共用，两处不得各写一份 NextScheduledSlot 调用。
func nextSlotFrom(days []int, hhmm string, now time.Time) string {
	return NextScheduledSlot(now, days, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
}

// versionTableNextSlot 版本表「重排时写什么」的读侧答案（UTC 落库串）；
// 排程不可读时按默认排程兜底——仅供展示/调度判定，写路径必须用严格变体。
func versionTableNextSlot(table string, now time.Time) string {
	days, hhmm := versionTableSchedule(table)
	return nextSlotFrom(days, hhmm, now)
}

// versionTableNextSlotStrict 写路径的槽计算：排程不可读返回 error，调用方
// 据此放弃本次槽推进（保留旧预约）。
func versionTableNextSlotStrict(table string, now time.Time) (string, error) {
	days, hhmm, err := versionTableScheduleStrict(table)
	if err != nil {
		return "", err
	}
	return nextSlotFrom(days, hhmm, now), nil
}

// slotAssign 是「按严格排程槽拼 next_update 赋值片段」的单源：先算槽（失败即
// 返回 no-op 片段，预约保持旧值），再按门的形态拼参数——成功门里 trigger 判据
// 出现两次（auto/manual 同权），失败/取消推进门只判一次。六个同族函数
// （版本表/威胁源/爬虫源 × 成功/推进）此前各自拼 []any，参数个数写错不会被
// 编译器发现，只会在运行时把槽值绑到 trigger 位置。
//
// 错误原样返回（不包 errScheduleSlotNotAdvanced）：调用方按族决定是「上抛让
// 本轮记失败」还是「静默保留旧预约」。
func slotAssign(gateSQL, trigger string, triggerArgs int, slotFn func() (string, error)) (string, []any, error) {
	slot, err := slotFn()
	if err != nil {
		return noopSlotAssignSQL, nil, err
	}
	switch triggerArgs {
	case 2:
		return gateSQL, []any{trigger, trigger, slot}, nil
	case 1:
		return gateSQL, []any{trigger, slot}, nil
	default:
		// 门里不带 trigger 判据（如版本表推进门只判 auto_update）。
		return gateSQL, []any{slot}, nil
	}
}

// versionTableSlotSuccessAssign 版本表族成功落的 next_update 赋值片段与参数
// （成功门 trigger 两次 + 槽值）。排程不可读时返回 no-op 片段与错误：状态/
// 版本列照常落库，预约保持旧值，调用方必须把本轮按失败返回给任务引擎
// （见 errScheduleSlotNotAdvanced——成功轮不推进槽却回 success 会被引擎消费
// 本槽，该族自动更新从此静默停摆）。
func versionTableSlotSuccessAssign(table, trigger string) (string, []any, error) {
	slotSQL, slotArgs, err := slotAssign(versionTableSlotSuccessSQL, trigger, 2, func() (string, error) {
		return versionTableNextSlotStrict(table, time.Now().UTC())
	})
	if err != nil {
		return noopSlotAssignSQL, nil, fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	return slotSQL, slotArgs, nil
}

// versionTableSlotAdvanceAssign 版本表族失败/取消落的赋值片段与参数
// （IIF(auto_update=1, ?, next_update)：仅开自动更新的行才推进）。
func versionTableSlotAdvanceAssign(table string) (string, []any, error) {
	// 推进门不含 trigger 判据（versionTableSlotAdvanceSQL 只判 auto_update）。
	slotSQL, slotArgs, err := slotAssign(versionTableSlotAdvanceSQL, "", 0, func() (string, error) {
		return versionTableNextSlotStrict(table, time.Now().UTC())
	})
	if err != nil {
		return noopSlotAssignSQL, nil, fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	return slotSQL, slotArgs, nil
}

// versionTableScheduleTx 事务内读取版本表排程两列并归一（与 versionTableSchedule
// 同一归一实现）。供「先建行再算槽」的写事务使用——事务内新建的行在事务外的
// db.DB 连接上不可见。
// 读失败同样留痕：写事务里排程不可读时本轮槽推进被放弃，没有留痕就只剩
// 「自动更新莫名其妙停摆」这一现象。
func versionTableScheduleTx(tx *sql.Tx, table string) ([]int, string, error) {
	return scheduleRead(tx, "schedule-read-"+table, versionTableScheduleQuery(table))
}

// versionTableAutoUpdateEnabled 读版本表自动更新开关（读错 fail-closed）。
// 调度门（tick 侧 EnabledFn/NextSlotFn）使用本二态口径——读错只影响本轮。
func versionTableAutoUpdateEnabled(table string) bool {
	enabled, known := versionTableAutoUpdateState(table)
	return known && enabled
}

// versionTableAutoUpdateState 三态读取版本表自动更新开关：known=false 表示
// 启用状态不可判定（库不可读/行缺失）。业务驱动任务的调度对齐只对
// known=true 落 StartLoop/StopLoop——读失败保持上一次生效的调度态并等待
// 周期性重试（否则一次读失败会被固化为调度关闭，读恢复后也不再自救）。
func versionTableAutoUpdateState(table string) (enabled, known bool) {
	database := db.GetDB()
	if database == nil {
		return false, false
	}
	var v int
	if err := database.QueryRow(`SELECT COALESCE(auto_update,1) FROM ` + table + ` WHERE id=1`).Scan(&v); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			logScheduleReadFailure("schedule-auto-update-"+table, err)
		}
		return false, false
	}
	logScheduleReadRecovered("schedule-auto-update-" + table)
	return v == 1, true
}

// CRSSchedule 返回 CRS 更新任务排程（GET 载荷）。
func CRSSchedule() ([]int, string) { return versionTableSchedule("security_crs_version") }

// IP2RegionSchedule 返回 IP2Region 更新任务排程（GET 载荷）。
func IP2RegionSchedule() ([]int, string) { return versionTableSchedule("security_ip2region_version") }

// globalTaskSchedule 读任务级排程（global_config 两列；threat/crawler 共用
// 同一读取与归一逻辑，列前缀隔离配置）。
func globalTaskSchedule(prefix string) ([]int, string) {
	// nil 库守卫与 versionTableNextUpdate/versionTableAutoUpdateState 同口径；
	// 读取走原子句柄（引擎 tick 读侧）。
	database := db.GetDB()
	if database == nil {
		return normalizeScheduleRow(defaultScheduleDays, defaultScheduleTime)
	}
	days, hhmm, err := scheduleRead(database, "schedule-read-"+prefix, globalTaskScheduleQuery(prefix))
	if err != nil {
		return normalizeScheduleRow(defaultScheduleDays, defaultScheduleTime)
	}
	return days, hhmm
}

// globalTaskScheduleStrict 写路径的任务级排程读取（失败返回 error，不做默认
// 排程兜底）——理由见 versionTableScheduleStrict。
func globalTaskScheduleStrict(prefix string) ([]int, string, error) {
	database := db.GetDB()
	if database == nil {
		return nil, "", errScheduleUnavailable
	}
	return scheduleRead(database, "schedule-read-"+prefix, globalTaskScheduleQuery(prefix))
}

// ThreatSchedule 读威胁库任务级排程（global_config 两列；与 threat_auto_update
// 同表先例——任务级设置不落逐源表）。
func ThreatSchedule() ([]int, string) { return globalTaskSchedule("threat") }

// CrawlerSchedule 读爬虫地址库独立排程（不共享 threat_* 配置）。
func CrawlerSchedule() ([]int, string) { return globalTaskSchedule("crawler") }

// threatNextSlot 威胁库任务级排程槽（UTC 落库串）；读侧 fail-soft 形态。
func threatNextSlot(now time.Time) string {
	days, hhmm := ThreatSchedule()
	return nextSlotFrom(days, hhmm, now)
}

// threatNextSlotStrict 威胁库任务级排程槽的写路径形态（排程不可读返回 error）。
func threatNextSlotStrict(now time.Time) (string, error) {
	days, hhmm, err := globalTaskScheduleStrict("threat")
	if err != nil {
		return "", err
	}
	return nextSlotFrom(days, hhmm, now), nil
}

// crawlerNextSlot 爬虫地址库独立排程槽（UTC 落库串）；读侧 fail-soft 形态。
func crawlerNextSlot(now time.Time) string {
	days, hhmm := CrawlerSchedule()
	return nextSlotFrom(days, hhmm, now)
}

// crawlerNextSlotStrict 爬虫地址库排程槽的写路径形态（排程不可读返回 error）。
func crawlerNextSlotStrict(now time.Time) (string, error) {
	days, hhmm, err := globalTaskScheduleStrict("crawler")
	if err != nil {
		return "", err
	}
	return nextSlotFrom(days, hhmm, now), nil
}

// threatSlotSuccessAssign 威胁源族成功落的赋值片段与参数（成功门 trigger
// 两次 + 槽值）；排程不可读时返回 no-op 片段与错误（原因/调用方契约同
// versionTableSlotSuccessAssign）。
func threatSlotSuccessAssign(trigger string) (string, []any, error) {
	slotSQL, slotArgs, err := slotAssign(threatSlotSuccessSQL, trigger, 2, func() (string, error) {
		return threatNextSlotStrict(time.Now().UTC())
	})
	if err != nil {
		return noopSlotAssignSQL, nil, fmt.Errorf("%w: %v", errScheduleSlotNotAdvanced, err)
	}
	return slotSQL, slotArgs, nil
}

// threatSlotAdvanceAssign 威胁源族失败落（仅 auto 推进）。
func threatSlotAdvanceAssign(trigger string) (string, []any) {
	slotSQL, slotArgs, err := slotAssign(threatSlotAdvanceSQL, trigger, 1, func() (string, error) {
		return threatNextSlotStrict(time.Now().UTC())
	})
	if err != nil {
		return noopSlotAssignSQL, nil
	}
	return slotSQL, slotArgs
}

// earliestEnabledSourceUpdate 返回启用源最早排程槽（空=无排程）。
// sourceTable 仅由包内固定传入，不接受外部输入。
//
// names 非空时把「槽域」收窄到运行域（该族任务实际处理的源名集合）：
// 槽域必须 ⊆ 运行域，否则注册表外的启用行一旦过期，其 next_update 没有任何
// 推进写点（markSourceSuccess/failSourceRow 只按已处理源写），最早槽恒钉在
// 过去——auto 轮恒投递、运行体零到期源提前返回、槽永不被消费，该族自动更新
// 就此静默停摆。威胁族传内置源名集合（运行域=注册表三源）；爬虫族运行域=全部
// 启用行，传 nil 保持「全部启用行」语义。
//
// 排序按 datetime() 归一后的时间序而非原始串 MIN：库内允许 crsTimeLayout
// （空格）与 RFC3339（T 分隔）双形态（parseUTCSlot 明确兼容），字典序把
// "YYYY-MM-DD 05:00:00"（空格 0x20）排在 "...THH:MM:SS"（T 0x54）之前，选出的
// 「最早槽」可能不是真实最早（集群快照/备份导入/旧版本残留可产生混格式）。
// datetime() 同时把两种形态转成同一 UTC 形态，返回值即归一为 crsTimeLayout；
// 非法串 datetime()=NULL 被排除（旧实现对垃圾串会直接选中垃圾串）。
func earliestEnabledSourceUpdate(sourceTable string, names []string) string {
	database := db.GetDB()
	if database == nil {
		return ""
	}
	// 名过滤与威胁族运行域同源（threatSourceRegistryNames）。空名单不拼子句
	//（此时保持「全部启用行」——与爬虫族运行域一致）。
	nameClause, args := sourceNameSetClause("name", names, false)
	var next string
	if err := database.QueryRow(`SELECT datetime(next_update) FROM `+sourceTable+`
		WHERE update_enabled=1
		  AND NULLIF(next_update,'') IS NOT NULL
		  AND datetime(next_update) IS NOT NULL`+nameClause+`
		ORDER BY datetime(next_update) ASC LIMIT 1`, args...).Scan(&next); err != nil {
		// 「无启用源/无有效排程」＝正常形态（旧 SQL 的 MIN 返回 NULL 被当成
		// 读失败留痕）。读错误不得静默归零（引擎按零槽停摆）——接
		// logScheduleReadFailure 单源首报留痕，恢复补 info。
		if errors.Is(err, sql.ErrNoRows) {
			logScheduleReadRecovered("schedule-earliest-" + sourceTable)
			return ""
		}
		logScheduleReadFailure("schedule-earliest-"+sourceTable, err)
		return ""
	}
	logScheduleReadRecovered("schedule-earliest-" + sourceTable)
	return next
}

// threatSourceRegistryNames 威胁族运行域（内置注册表源名集合）单源：读侧最早
// 槽、首槽武装、时区重排与启动期注册表外槽清理必须共用同一集合——任一路径
// 漏过滤都会让「槽域=运行域」在数据面失效（清理刚清空的槽会被同一次装配的
// 无过滤武装反向补回）。
func threatSourceRegistryNames() []string {
	registry := db.ThreatSystemLists()
	names := make([]string, 0, len(registry))
	for _, source := range registry {
		if source.Source != "" {
			names = append(names, source.Source)
		}
	}
	return names
}

// sourceNameSetClause 把源名集合编译为含前导 " AND " 的 `column IN (...)` /
// `column NOT IN (...)` 谓词。集合为空返回空串与 nil：空集合加 IN 会命中零行、
// 加 NOT IN 会命中全部行，都不等价于「不过滤」，调用方必须按空名单显式决定
// 语义（威胁族注册表为空时不做过滤，与运行体不筛源的形态一致）。
func sourceNameSetClause(column string, names []string, negate bool) (string, []any) {
	if len(names) == 0 {
		return "", nil
	}
	op := " IN ("
	if negate {
		op = " NOT IN ("
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")
	args := make([]any, 0, len(names))
	for _, name := range names {
		args = append(args, name)
	}
	return " AND " + column + op + placeholders + ")", args
}

// earliestThreatNextUpdate 威胁族槽域 = 运行域（注册表源名集合）：
// 运行体 threatDueSources 只处理注册表列出的源，槽域必须同步收窄，
// 见 earliestEnabledSourceUpdate 的停滞机理说明。
func earliestThreatNextUpdate() string {
	return earliestEnabledSourceUpdate("security_threat_sources", threatSourceRegistryNames())
}

// earliestCrawlerNextUpdate 爬虫族槽域=内置名全集（crawlerSourceRegistryNames），
// 与运行域同源：RunUpdate 入口把未知名行收敛出运行域
// （filterBuiltinCrawlerSources，槽不再被推进），槽域必须同步收窄——否则带外
// 未知名行的惰性槽会让引擎逐 tick 空转（与威胁族同机理）。
func earliestCrawlerNextUpdate() string {
	return earliestEnabledSourceUpdate("security_crawler_sources", crawlerSourceRegistryNames())
}

// setVersionTableSchedule 版本表排程保存 + 保存即重排（auto_update 关闭时也
// 重排——「下次更新」如实展示，调度器仍受开关门控）。
func setVersionTableSchedule(table, seedVersion string, days []int, hhmm string) error {
	norm, err := validateScheduleInput(days, hhmm)
	if err != nil {
		return err
	}
	// 2026-09-25 用户裁定：失败退避撤除——一律重排到新槽（原失败行保留
	// 退避的 IIF 守卫随退避机制一并移除）。
	next := NextScheduledSlot(time.Now().UTC(), norm, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
	// 两步写事务化，与同文件 setGlobalTaskSchedule
	//同构——INSERT 成功而 UPDATE 失败会留「行已建、排程未生效、
	// next_update 为空」的中间态（下次自动更新按 DDL 默认触发）。
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("开启排程事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 已 Commit 后为 no-op
	if _, err := tx.Exec(`INSERT OR IGNORE INTO `+table+` (id, version, auto_update) VALUES (1, ?, TRUE)`, seedVersion); err != nil {
		return fmt.Errorf("初始化版本记录: %w", err)
	}
	if _, err := tx.Exec(`UPDATE `+table+` SET schedule_days=?, schedule_time=?, next_update=? WHERE id=1`,
		FormatScheduleDays(norm), hhmm, next); err != nil {
		return fmt.Errorf("保存定时更新设置: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交排程事务: %w", err)
	}
	return nil
}

// SetCRSSchedule 保存 CRS 更新排程（星期集 + 时间）并重排 next_update。
func SetCRSSchedule(days []int, hhmm string) error {
	return setVersionTableSchedule("security_crs_version", CRSBundledVersion, days, hhmm)
}

// SetIP2RegionSchedule 保存 IP2Region 更新排程并重排 next_update。
func SetIP2RegionSchedule(days []int, hhmm string) error {
	return setVersionTableSchedule("security_ip2region_version", "unknown", days, hhmm)
}

// setGlobalTaskSchedule 保存任务级排程并事务化重排启用源 next_update。
// 配置列前缀与源表由内部调用方固定传入，不接受外部输入。names 是该族的运行域
// 源名集合（威胁族传注册表源名，爬虫族传 nil=全部启用行）：槽域必须等于
// 运行域，否则保存排程会把注册表外的惰性槽一并写回（与启动期清理互相抵消）。
func setGlobalTaskSchedule(prefix, sourceTable string, names []string, days []int, hhmm string) error {
	norm, err := validateScheduleInput(days, hhmm)
	if err != nil {
		return err
	}
	next := NextScheduledSlot(time.Now().UTC(), norm, hhmm, CurrentLocation()).UTC().Format(crsTimeLayout)
	tx, err := db.DB.Begin()
	if err != nil {
		return fmt.Errorf("开启排程事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 已 Commit 后为 no-op
	query := `UPDATE global_config SET ` + prefix + `_schedule_days=?, ` + prefix + `_schedule_time=?, updated_at=datetime('now') WHERE id=1`
	res, err := tx.Exec(query, FormatScheduleDays(norm), hhmm)
	if err != nil {
		return fmt.Errorf("保存定时更新设置: %w", err)
	}
	// global_config 行被带外删除/导入异常缺失时，UPDATE 命中 0 行不得静默
	// 返回成功（排程列未落库、第二句重排也无效，零错误信号）。
	if affected, aerr := res.RowsAffected(); aerr != nil {
		return fmt.Errorf("确认定时更新设置写入结果: %w", aerr)
	} else if affected != 1 {
		return fmt.Errorf("保存定时更新设置失败: global_config 配置行缺失（命中 %d 行）", affected)
	}
	nameClause, nameArgs := sourceNameSetClause("name", names, false)
	if _, err := tx.Exec(`UPDATE `+sourceTable+` SET next_update=? WHERE update_enabled=1`+nameClause, append([]any{next}, nameArgs...)...); err != nil {
		return fmt.Errorf("重排规则库源更新计划: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交排程事务: %w", err)
	}
	return nil
}

// SetThreatSchedule 保存威胁库任务级排程（global_config）并重排注册表源的
// next_update（2026-09-25 用户裁定：失败源不再保留退避，一律重排到新槽）。
// 两步写事务化——跨表双写曾各自独立提交，第二步失败
// 留「排程已改、槽位照旧」中间态；现失败整体回滚报错。
func SetThreatSchedule(days []int, hhmm string) error {
	return setGlobalTaskSchedule("threat", "security_threat_sources", threatSourceRegistryNames(), days, hhmm)
}

// SetCrawlerSchedule 保存爬虫地址库独立排程并重排全部启用爬虫源。
func SetCrawlerSchedule(days []int, hhmm string) error {
	return setGlobalTaskSchedule("crawler", "security_crawler_sources", nil, days, hhmm)
}

// versionUpdateStatuses 是版本表/更新源表 update_status 列的合法词表
// （CRS/IP2Region 版本表与威胁/爬虫源表共用；与各族状态常量同值）。这些列
// 属于运行态簿记词表，前端状态徽标与轮询判定直读、渲染层零兜底。
// sourceUpdateStatusRunning 必须在词表内：源表族写侧只写该活动词，漏掉会把
// 合法的「更新中」行误判为词表外值（导入 warning 失实、归一丢真实状态）。
var versionUpdateStatuses = map[string]struct{}{
	string(CRSStatusIdle):        {},
	string(CRSStatusChecking):    {},
	string(CRSStatusDownloading): {},
	string(CRSStatusInstalling):  {},
	string(CRSStatusReloading):   {},
	string(CRSStatusSuccess):     {},
	string(CRSStatusFailed):      {},
	string(CRSStatusSkipped):     {},
	string(CRSStatusCancelled):   {},
	sourceUpdateStatusRunning:    {},
}

// IsActiveUpdateStatus 判定 update_status 是否属于「更新中」活动态（类判据）：
// 版本表四活动词（CRS/IP2Region）+ 源表族唯一活动词 running。活动态只属于
// 执行该任务的进程——跨进程序列化通道（配置导入、集群快照、读侧角色投影）
// 一律按本判据收敛，不得按表维护逐词白名单：白名单必然滞后于写侧新增活动词，
// running 就曾被漏在版本表词表之外。
func IsActiveUpdateStatus(status string) bool {
	return IsActiveCRSStatus(status) || IsActiveIP2RegionStatus(status) || status == sourceUpdateStatusRunning
}

// NormalizeVersionUpdateStatus 归一 update_status：词表外值（含空串/未知）
// → idle。写侧由各族更新器常量产出，本函数服务于导入门（旧备份/带外直写
// 可携带未定义值）。
func NormalizeVersionUpdateStatus(status string) string {
	if _, ok := versionUpdateStatuses[status]; ok {
		return status
	}
	return string(CRSStatusIdle)
}
