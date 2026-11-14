package services

// 会话级封禁存储（自动封禁 NAT 态复合候选的执法出口）：
//
// 身份与通道：键=autobanIdentityKey 复合形态（归一 IP|指纹）。会话封禁只经
// 挑战链（lbhuman）执法，不落 IP 名单、不写 IP 累犯表——NAT 共享出口下按
// 会话精确拒绝，不伤无辜会话。IP 级封禁（L4/IP ACL 消费的名单通道）零变化。
//
// 本地态：内存 map + 短 TTL（autobanSessionBanTTL，可配测试缝），不跨节点
// 同步（集群快照不携带；跨节点会话封禁是后续阶段）。重启即失忆——TTL 短，
// 攻击会话重新达标即再封，与「删除即解封、重新达标再封」裁定同语义。
//
// 跨进程交换：面板写 <data_dir>/autoban-session-bans.json（原子落盘），
// lbhuman 按 stat 热感知读取（与 crawler-ip-lists.json 同族交换契约）。
// 载荷只含未到期条目；条目自带 expires_at_ms，插件侧按条目时间判到期——
// 面板清理间隙（≤1 tick）不产生执法残留。
//
// 生命周期：写入=Run 轮复合候选达阈（autobanBanSession）；到期=读时过滤 +
// Run 轮/禁用收尾清扫；手动解封=AutobanForgetIPs 随母身份清除；禁用=
// AutobanDisableFlush 全清并交换空载荷（执法通道关闭）。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// autobanSessionBanTTL 会话封禁时长（短 TTL 可配；测试缝可覆写）。
// 独立于 IP 级 autobanDurations：会话执法是挑战链内的轻量拒绝，不是名单
// 封禁，时长语义不共享（IP 级 10m~permanent 档位不适用于会话通道）。
var autobanSessionBanTTL = 10 * time.Minute

// autobanMaxSessionBans 会话封禁键上限（超限丢新键——与计数桶/NAT 剖面
// 同族内存有界裁定；既有封禁不受影响）。
var autobanMaxSessionBans = 100000

// defaultAutobanSessionBanFile 交换文件容器默认路径（与 lbhuman 侧
// defaultSessionBanFile 逐字节一致——跨进程契约双锚，改一侧必须同步另一侧）。
const defaultAutobanSessionBanFile = "/app/data/autoban-session-bans.json"

// autobanSessionBanFile 交换文件当前路径（ConfigureWafDirs 按 data_dir 派生；
// 测试经 SetAutobanSessionBanFileForTest 改指）。
var autobanSessionBanFile = defaultAutobanSessionBanFile

// autobanSessionBans 会话封禁表（复合键 → 到期时刻）。autobanMu 保护
// （与计数桶/NAT 剖面同锁——解封清桶与封禁写入在锁上全序）。
var autobanSessionBans = make(map[string]time.Time)

// AutobanSessionBanEntry 交换载荷条目（lbhuman 消费契约：key=归一 IP|指纹，
// expires_at_ms=unix 毫秒到期时刻）。
type AutobanSessionBanEntry struct {
	Key         string `json:"key"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
}

// AutobanSessionBanSnapshot 交换文件载荷形态（{"bans":[...]}；空集序列化为
// 数组而非 null——与 /status suggestions 同契约）。
type AutobanSessionBanSnapshot struct {
	Bans []AutobanSessionBanEntry `json:"bans"`
}

// SetAutobanSessionBanFileForTest 改指交换文件路径（返回还原闭包；
// 与 SetCrawlerIPListFileForTest 同款测试缝约定）。
//
// testseam: 交换文件路径测试缝（同包测试消费，返回还原闭包）。
func SetAutobanSessionBanFileForTest(path string) func() {
	old := autobanSessionBanFile
	autobanSessionBanFile = path
	return func() { autobanSessionBanFile = old }
}

// autobanBanSession 写入一条会话封禁（复合键达阈执法）。非复合键拒绝
// （IP 级封禁走名单通道，会话存储只认复合身份）；超限丢新键。
// 写入即交换（调用方在 autobanMu 临界区内——交换读快照同锁）。
func autobanBanSession(key string) {
	if _, _, composite := autobanCompositeKeyParts(key); !composite {
		return
	}
	autobanMu.Lock()
	defer autobanMu.Unlock()
	now := autobanNow()
	if _, exists := autobanSessionBans[key]; !exists && len(autobanSessionBans) >= autobanMaxSessionBans {
		return // 内存有界：丢新键保既有（与计数桶同族裁定）
	}
	autobanSessionBans[key] = now.Add(autobanSessionBanTTL)
	autobanExchangeSessionBansLocked(now)
}

// autobanSessionBanActiveLocked 报告键是否仍在封禁期（调用方持 autobanMu）。
func autobanSessionBanActiveLocked(key string, now time.Time) bool {
	exp, ok := autobanSessionBans[key]
	return ok && exp.After(now)
}

// autobanSweepSessionBansLocked 清扫到期条目（调用方持 autobanMu）。
// 读时过滤已保证执法正确，清扫只收敛内存与交换文件体积。
func autobanSweepSessionBansLocked(now time.Time) {
	for key, exp := range autobanSessionBans {
		if !exp.After(now) {
			delete(autobanSessionBans, key)
		}
	}
}

// AutobanActiveSessionBanCount 当前生效会话封禁数（/status session_bans
// 数据源；到期条目不计——与执法面同口径）。顺带清扫到期条目并交换。
func AutobanActiveSessionBanCount() int {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	now := autobanNow()
	autobanSweepSessionBansLocked(now)
	autobanExchangeSessionBansLocked(now)
	return len(autobanSessionBans)
}

// autobanExchangeSessionBansLocked 把未到期会话封禁原子落盘交换
// （调用方持 autobanMu）。写失败只留痕不阻断执法——内存态仍是执法真相，
// 下一轮写入/清扫重试交换（与爬虫快照写失败留痕同口径）。
func autobanExchangeSessionBansLocked(now time.Time) {
	snap := AutobanSessionBanSnapshot{Bans: make([]AutobanSessionBanEntry, 0, len(autobanSessionBans))}
	for key, exp := range autobanSessionBans {
		if exp.After(now) {
			snap.Bans = append(snap.Bans, AutobanSessionBanEntry{Key: key, ExpiresAtMS: exp.UnixMilli()})
		}
	}
	// 键序稳定：同内容同字节（插件侧 stat 缓存命中零重建）。
	sort.Slice(snap.Bans, func(i, j int) bool { return snap.Bans[i].Key < snap.Bans[j].Key })
	raw, err := json.Marshal(snap)
	if err != nil {
		Logf("error", "会话封禁交换载荷序列化失败: %v", err)
		return
	}
	path := autobanSessionBanFile
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		Logf("error", "会话封禁交换目录创建失败 %s: %v", filepath.Dir(path), err)
		return
	}
	if err := writeFileAtomicSynced(path, raw, 0o644); err != nil {
		Logf("error", "会话封禁交换文件写入失败 %s: %v", path, err)
	}
}

// autobanForgetSessionBansLocked 按母身份清除会话封禁（调用方持 autobanMu）：
// 精确复合键或裸 IP 前缀（归一 IP|...）全清——手动解封随母身份生效。
func autobanForgetSessionBansLocked(identity string) {
	delete(autobanSessionBans, identity)
	prefix := identity + "|"
	for key := range autobanSessionBans {
		if strings.HasPrefix(key, prefix) {
			delete(autobanSessionBans, key)
		}
	}
}

// autobanClearSessionBansLocked 全清会话封禁（禁用收尾/测试复位；调用方持
// autobanMu）。
func autobanClearSessionBansLocked() {
	autobanSessionBans = make(map[string]time.Time)
}

// AutobanSeedSessionBanForTest 直填会话封禁（handlers 层双通道接线钉测用；
// ttl 负值=已到期条目）。绕过复合候选管线，键形态由调用方保证。
//
// testseam: handlers 层双通道钉测直填缝（跨包测试消费）。
func AutobanSeedSessionBanForTest(key string, ttl time.Duration) {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanSessionBans[key] = autobanNow().Add(ttl)
}

// AutobanResetSessionBansForTest 清空会话封禁存储（跨包测试复位；不交换——
// 测试各自改指临时交换文件）。
//
// testseam: 跨包测试复位缝。
func AutobanResetSessionBansForTest() {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanClearSessionBansLocked()
}

// AutobanSessionAuditAction 会话封禁审计动作名（独立于 IP「自动封禁」——
// AutobanBannedToday 只计 IP 动作，会话执法不混入今日封禁统计；会话通道
// 的可追溯性由本动作承载）。
const AutobanSessionAuditAction = "会话封禁"

// autobanAuditSessionBanned 逐会话「会话封禁」审计（Run 轮：降级窗口外、
// 执法已落定）。只计复合候选（IP 级候选由 autobanAuditBanned 承载）；
// 逐条上限与 IP 通道同口径（超限保留前 N 条+汇总行点名省略数）。
func autobanAuditSessionBanned(cfg AutobanConfig, candidates []AutobanSuggestion) {
	var keys []string
	for _, c := range candidates {
		if _, _, composite := autobanCompositeKeyParts(c.IP); composite {
			keys = append(keys, c.IP)
		}
	}
	if len(keys) == 0 {
		return
	}
	omitted := 0
	if len(keys) > autobanAuditPerRoundCap {
		omitted = len(keys) - autobanAuditPerRoundCap
		keys = keys[:autobanAuditPerRoundCap]
	}
	for _, key := range keys {
		RecordAuditLog("system", AutobanSessionAuditAction, "会话",
			FormatAuditDetail("会话："+key,
				fmt.Sprintf("命中：%d 次/%d 分钟", cfg.Threshold, cfg.WindowMinutes),
				"时长："+autobanSessionBanTTL.String()+"（本地态，不跨节点同步）",
				AuditResultPart("success")), "")
	}
	if omitted > 0 {
		RecordAuditLog("system", AutobanSessionAuditAction, "会话",
			fmt.Sprintf("%s%d 个会话省略逐条记录（本轮共 %d 个会话，逐条上限 %d）",
				autobanAuditSummaryPrefix, omitted, len(keys)+omitted, autobanAuditPerRoundCap), "")
	}
}
