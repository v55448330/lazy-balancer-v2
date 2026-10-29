package ownership

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"lazy-balancer-v2/internal/atomicfile"
	"lazy-balancer-v2/internal/dnsname"
)

// logf 是包级日志接缝（镜像 services/certjoblog.go certJobLogWarnf
// 先例）：默认落到标准 log（stdout）；ownership 是独立 module 边界（被
// dnsprovider/services 反向依赖，不得回依赖 services），故由
// cmd/server/main.go 装配时注入 services.Logf，使告警进入统一日志级别链。
var logf = func(level, format string, args ...any) { log.Printf(format, args...) }

// SetLogf 装配包级日志函数（main 启动早期调用；nil 忽略）。
func SetLogf(f func(level, format string, args ...any)) {
	if f != nil {
		logf = f
	}
}

const ownershipFileName = "acme_dns_ownership.json"

// StaleOwnershipAge is the age beyond which an ownership entry can no longer
// belong to a live issuance: the CA queue caps execution at 60 minutes and the
// deferred cleanup budget is capped at 8 minutes (acme dnsCleanupBudgetMax,
// so anything older is provably abandoned and may be removed by any
// later cleanup without endangering a concurrent challenge.
const StaleOwnershipAge = 75 * time.Minute

// OwnershipRetention 是账本条目的本地保留期：记录只服务「本轮挑战的清理归属
// 判定」，历史域名/失败中断留下的条目长期滞留没有价值，且账本是明文 JSON（含
// FQDN/记录 ID/账户摘要）。超过保留期的已归属条目在下一次写入时退役（只动本地
// 文件，不触碰远端 DNS，避免误删并发实例仍在使用的记录）；无法证明年龄的
// legacy 条目（CreatedAt 零值）保留，由 DecideRemoval 的保守口径处理。
//
// 已知后果（有意保留，记录于此避免被当成遗漏）：条目退役后远端 TXT 不再被账本
// 追踪——删除连续失败（provider 5xx/权限错误/换凭据后的 DispositionDrop）超过
// 保留期的记录只能靠后续签发按值/stale 偶然回收（同名不同值则不会回收）。退役
// 日志已明示该残留，运维需要时按日志人工清理；不延长保留期是因为「延长」只会
// 让无法证明归属的条目更久地滞留在明文账本里，并不能提升回收成功率。
const OwnershipRetention = 30 * 24 * time.Hour

var fileMu sync.Mutex

// AcquireFileLockForTest exposes the package lock's contention boundary to
// cross-package tests proving callers use the same writer. Production code must
// never call it; the returned release must be called exactly once.
func AcquireFileLockForTest() func() {
	fileMu.Lock()
	return fileMu.Unlock
}

// Record is one owned DNS TXT record. Value and CreatedAt were added later;
// files written by older binaries decode with zero values and are handled as
// legacy entries (see MatchingValue).
//
// Account是创建该条目的凭据摘要（见 AccountDigest）：
// 同一 zone 的 DNS 凭据换成另一账户后，旧条目仍留在文件里，按名称清理若照旧
// 用 record_id 调 provider 删除，新账户会去删「同 ID 的无关记录」（旧账户的
// TXT 在新账户查无此 ID，最多幂等删除；但 ID 在域内被复用时会命中他记录）。
// 旧文件没有该字段 → 空值 = legacy（无法归属），由 DecideRemoval 保守处理。
type Record struct {
	Provider  string    `json:"provider"`
	Zone      string    `json:"zone"`
	FQDN      string    `json:"fqdn"`
	Value     string    `json:"value"`
	RecordID  string    `json:"record_id"`
	Account   string    `json:"account,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// stale 报告该条目是否已超出任何在途签发的生命周期（CA 队列 60min + 清理
// 预算 8min 的上界，见 StaleOwnershipAge），即已可被任意后续清理回收。
// 零值 CreatedAt（更早版本写入且从未回填）不判 stale：无法证明它已过期，
// 保守按「可能仍在本轮签发中」处理（与 MatchingValue 的既有口径一致）。
// 仅本包消费，故不导出（跨包契约无消费者）。
func (r Record) stale(now time.Time) bool {
	return !r.CreatedAt.IsZero() && now.Sub(r.CreatedAt) > StaleOwnershipAge
}

// AccountDigest 由凭据派生账户身份（sha256 前 8 字节 = 16 位十六进制），
// 与 dnspod 的 domainIDCacheKey 同源口径：不落凭据明文（所有权文件是明文
// JSON，落盘/集群快照/排障转储都可读），且同一凭据多进程/多实例得到同一值。
// 该摘要是 DecideRemoval「按 record_id 删除还是只丢本地条目」的归属判据，
// 8 字节把碰撞界推到密码学可忽略域（32 位生日界约 7.7 万账户即有过半碰撞）。
// 口径变更后既有账本的 8 位摘要不再匹配当前凭据——旧条目按 legacy/他账户
// 语义降级为「只丢弃不删除」（DecideRemoval 保守方向），随同名清理自然淘汰。
func AccountDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

// Disposition 是清理方对一条所有权条目的处置结论。
type Disposition int

const (
	// DispositionDelete 表示可以调用 provider 删除该 record_id（条目可归属
	// 当前账户，或是本账户升级前写入的、仍在在途窗口内的 legacy 条目）。
	DispositionDelete Disposition = iota
	// DispositionDrop 表示不能证明条目归属当前账户：只丢弃本地所有权条目，
	// MUST NOT 按 record_id 调 provider 删除（换凭据后 ID 可能指向无关记录）。
	DispositionDrop
)

// DecideRemoval 判定清理方（account 为当前凭据摘要）能否按 record_id 删除该
// 条目。单源实现：dnspod 与 tencent 的 cleanUp 各自维护删除链（底层 SDK/ID
// 类型不同），但账户归属判定 MUST 共用此函数，避免两侧口径漂移。
//
// 规则（保守优先，安全方向一体）：①账户匹配 → 删；②账户明确不同 → 只丢弃；
// ③legacy（Account 空、无法归属）且未陈旧 → 删（升级前本账户写入的在途条目，
// 保持既有清理语义）；④legacy 且已陈旧 → 只丢弃——陈旧条目不可能属于在途
// 签发，而换过凭据后它可能来自旧账户，按 ID 删除有命中无关记录的风险。
// 两侧都无账户信息（调用方未声明身份且条目为 legacy，如测试/内存模式）按 ③
// 的宽松口径处理；条目有账户而调用方未声明身份则归入 ②（无法证明归属）。
func DecideRemoval(record Record, account string, now time.Time) Disposition {
	switch {
	case record.Account != "" && account != "":
		if record.Account == account {
			return DispositionDelete
		}
		return DispositionDrop
	case record.Account == "":
		if record.stale(now) {
			return DispositionDrop
		}
		return DispositionDelete
	default:
		// record.Account 非空而调用方未声明账户：无法证明归属，只丢弃。
		return DispositionDrop
	}
}

type Store struct {
	path string
}

type state struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

func New(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("DNS ownership data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create DNS ownership directory: %w", err)
	}
	return &Store{path: filepath.Join(dataDir, ownershipFileName)}, nil
}

// beforeReplaceLock / beforeReplaceWrite 是 Replace 的测试接缝（默认空操作）：
// 前者在取得 fileMu 之前调用、后者在持有 fileMu 且即将写盘时调用，用于确定
// 性地证明「Replace 与 Store 的 Add/Remove 共用同一把文件锁」——旧用例只能
// 用固定墙钟窗口猜「goroutine 是否已走到加锁点」，负载下会空转成真空断言。
// 生产代码不得依赖这两个钩子。
var (
	beforeReplaceLock  = func() {}
	beforeReplaceWrite = func() {}
)

// Replace atomically replaces the ownership file with a validated cluster
// snapshot. It deliberately shares fileMu and the same atomic writer as Store
// mutations so a snapshot apply cannot overwrite a concurrent Add/Remove.
func Replace(dataDir string, data []byte) error {
	// 先取锁再做任何准备工作（解码/建目录）——锁前
	// 的准备会给「Replace 确实共用 fileMu」的并发测试留下假绿窗口：goroutine
	// 还没走到加锁点，固定等待就静默通过，断言变成空断言。锁内解码的代价
	// 可忽略（快照为单文件、签发级频次）。
	beforeReplaceLock()
	fileMu.Lock()
	defer fileMu.Unlock()
	var snapshot state
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("decode DNS ownership snapshot: %w", err)
	}
	if snapshot.Version != 1 || snapshot.Records == nil {
		return errors.New("invalid DNS ownership snapshot")
	}
	store, err := New(dataDir)
	if err != nil {
		return err
	}
	if existing, readErr := os.ReadFile(store.path); readErr == nil && bytes.Equal(existing, data) {
		return nil
	}
	beforeReplaceWrite()
	return store.writeAtomic(data)
}

// normalizeRecordName 归一 DNS 名（大小写不敏感、尾点可省略），与挑战登记
// 共用 dnsname.NormalizeName 单源实现。账本比较若不归一，同一挑战以两种
// 书写形态分别 Present/CleanUp（例如新的调用方或手工验证路径）时命中失败——
// 该 TXT 既不按 ID 删除也不会被 MatchingValue 选中，只能等 StaleOwnershipAge
// 兜底，条目本身还要留到 OwnershipRetention。存量条目在比较侧同样归一，旧文件
// 无需迁移。
func normalizeRecordName(name string) string {
	return dnsname.NormalizeName(name)
}

func (s *Store) Add(record Record) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return err
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}
	// 落账即归一：后续所有匹配（含并发清理）都按同一形态比较。
	record.Zone = normalizeRecordName(record.Zone)
	record.FQDN = normalizeRecordName(record.FQDN)
	current.Records = append(current.Records, record)
	return s.save(current)
}

// Matching returns every ownership entry recorded under the challenge name,
// regardless of account :换凭据后旧账户的条目必须被清理方
// 看到，才能按 ownership.DecideRemoval 判定「丢弃本地条目而非按 ID 删除」。
// 调用方 MUST 在调用 provider 删除前做该归属判定。
func (s *Store) Matching(provider, zone, fqdn string) ([]Record, error) {
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return nil, err
	}
	zone = normalizeRecordName(zone)
	fqdn = normalizeRecordName(fqdn)
	matching := make([]Record, 0)
	for _, record := range current.Records {
		if record.Provider == provider && normalizeRecordName(record.Zone) == zone && normalizeRecordName(record.FQDN) == fqdn {
			matching = append(matching, record)
		}
	}
	return matching, nil
}

// MatchingValue returns the name-matching records that a cleanup for one
// challenge value may remove: the record created with that value, legacy
// entries persisted before value tracking (empty Value, best-effort), and
// provably stale entries. A recent record of another value may belong to a
// live concurrent issuance and is spared. An empty value disables the value
// filter (legacy name-based matching).
func (s *Store) MatchingValue(provider, zone, fqdn, value string) ([]Record, error) {
	if value == "" {
		return s.Matching(provider, zone, fqdn)
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	zone = normalizeRecordName(zone)
	fqdn = normalizeRecordName(fqdn)
	matching := make([]Record, 0)
	for _, record := range current.Records {
		if record.Provider != provider || normalizeRecordName(record.Zone) != zone || normalizeRecordName(record.FQDN) != fqdn {
			continue
		}
		legacy := record.Value == ""
		// 账户维度不参与选择：他账户/legacy 条目必须能被
		// 清理方看到——看不到就只能永久留存（每次清理重读、永不回收），而
		// 归属判定与「只丢弃不删除」的处置在 DecideRemoval。
		staleRecord := record.stale(now)
		if record.Value == value || legacy || staleRecord {
			matching = append(matching, record)
		}
	}
	return matching, nil
}

// sameRecord 语义相等：Record 结构内联 == 比较含
// time.Time（wall/ext/loc 指针 + monotonic）——从文件读回经 Matching/
// MatchingValue 得到的记录与调用方持有的原值逻辑时间相同，但 == 可能为
// false（JSON 解码丢弃 monotonic、loc 指针不同），Remove 静默 no-op 留下
// 未清理记录。CreatedAt 用 Equal，其余字段逐项比较。
func sameRecord(a, b Record) bool {
	// Account 纳入相等判定：同一 name/value/record_id 但
	// 账户不同的两条记录（换凭据后的历史残留 vs 当前账户条目）必须各自可
	// 独立 Remove，否则丢弃他账户条目会连带删掉本账户的在途条目。
	// 名称按 DNS 等价归一比较：调用方可能持有 Present 时的原始书写形态
	//（带尾点/大写），而账本落盘已归一。
	return a.Provider == b.Provider && normalizeRecordName(a.Zone) == normalizeRecordName(b.Zone) &&
		normalizeRecordName(a.FQDN) == normalizeRecordName(b.FQDN) &&
		a.Value == b.Value && a.RecordID == b.RecordID && a.Account == b.Account &&
		a.CreatedAt.Equal(b.CreatedAt)
}

func (s *Store) Remove(removed Record) error {
	return s.RemoveMany([]Record{removed})
}

// RemoveMany 在一次 load/save（一次全量重写 + fsync）内移除多条记录——
// 清理链逐条 Remove 的代价是 O(记录数) 字节 × 条目数（每条一次全文件
// fsync 重写），批量收敛后一次清理只付一次。语义与逐条 Remove 一致：
// 按 sameRecord 精确匹配，未命中的条目静默忽略（调用方只传「远端已删除/
// 判定丢弃」的条目，删除失败的条目不得传入——否则丢失重试追踪）。
func (s *Store) RemoveMany(removed []Record) error {
	if len(removed) == 0 {
		return nil
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	current, err := s.load()
	if err != nil {
		return err
	}
	remaining := make([]Record, 0, len(current.Records))
	for _, record := range current.Records {
		drop := false
		for _, target := range removed {
			if sameRecord(record, target) {
				drop = true
				break
			}
		}
		if !drop {
			remaining = append(remaining, record)
		}
	}
	if len(remaining) == len(current.Records) {
		// 零命中（调用方条目与账本漂移）——无变化不写盘，省一次全量 fsync。
		return nil
	}
	current.Records = remaining
	return s.save(current)
}

func (s *Store) load() (state, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state{Version: 1}, nil
	}
	if err != nil {
		return state{}, fmt.Errorf("read DNS ownership: %w", err)
	}
	var current state
	decodeErr := json.Unmarshal(data, &current)
	if decodeErr == nil && current.Version != 1 {
		decodeErr = fmt.Errorf("unsupported DNS ownership version %d", current.Version)
	}
	if decodeErr != nil {
		// The ownership file is a best-effort cache: quarantine the bad bytes
		// instead of failing every later Add/Matching/Remove (which would
		// brick all DNS-01 issuance) until manual deletion. The quarantined
		// file stays on disk for inspection; only a failed quarantine (bytes
		// not preserved) keeps returning the error.
		// 文件名原为秒级时间戳，同一秒内二次损坏会被
		// os.Rename 覆盖（POSIX rename 语义）而丢失上一份取证样本——改为
		// 纳秒时间戳 + 冲突探测。
		quarantined := s.quarantinePath()
		if err := os.Rename(s.path, quarantined); err != nil {
			return state{}, fmt.Errorf("quarantine DNS ownership %s: %w", s.path, errors.Join(decodeErr, err))
		}
		logf("warn", "DNS ownership file %s undecodable (%v), quarantined to %s and continued with empty state", s.path, decodeErr, quarantined)
		return state{Version: 1}, nil
	}
	return current, nil
}

// corruptClock 是隔离文件名的时间源（测试接缝：固定时钟下连续两次
// 隔离必须产生两份独立样本）。生产代码不得改写。
var corruptClock = time.Now

// quarantinePath 返回一个未被占用的隔离文件名：纳秒时间戳为基底，冲突时追加
// 递增序号（os.Stat 探测为 best-effort，命中竞态时由 Rename 的覆盖语义兜底，
// 仅为取证样本，不参与业务判定）。
func (s *Store) quarantinePath() string {
	stamp := corruptClock().UnixNano()
	for suffix := 0; ; suffix++ {
		candidate := fmt.Sprintf("%s.corrupt-%d", s.path, stamp)
		if suffix > 0 {
			candidate = fmt.Sprintf("%s.corrupt-%d-%d", s.path, stamp, suffix)
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		} else if err != nil {
			// 无法探测（权限等）：交给 Rename 报错，不在此吞掉。
			return candidate
		}
	}
}

func (s *Store) save(current state) error {
	if len(current.Records) > 0 {
		now := time.Now()
		retired := 0
		kept := current.Records[:0]
		for _, record := range current.Records {
			// 保留期（30d）远大于 StaleOwnershipAge（75min），Stale 判定已被
			// 保留期蕴含；legacy 条目（CreatedAt 零值）必须显式保留——零值时间
			// 与 now 的差值无意义。
			if !record.CreatedAt.IsZero() && now.Sub(record.CreatedAt) > OwnershipRetention {
				retired++
				continue
			}
			kept = append(kept, record)
		}
		current.Records = kept
		if retired > 0 {
			// 条目消失属于可观测事件：单行、只报条数与保留期（不打印 FQDN/记录
			// ID——账本落盘已是明文，运行日志不再额外扩散用户数据）。
			// 同时必须写明运维含义：按构造，能留在账本里超过保留期的条目都是
			// 「删除未确认」的（成功删除的条目早已 Remove），退役只动本地文件，
			// 远端 _acme-challenge TXT 可能继续存在，需要人工到 DNS 区核对。
			logf("info", "DNS ownership: 退役 %d 条超过 %d 天保留期的账本条目（仅本地文件，未触碰远端 DNS；这些条目从未确认删除成功，远端 _acme-challenge TXT 可能仍残留，必要时人工清理）",
				retired, int(OwnershipRetention.Hours()/24))
		}
	}
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("encode DNS ownership: %w", err)
	}
	return s.writeAtomic(data)
}

// writeAtomic writes one complete snapshot through the shared primitive so
// every failure path removes its uniquely named temporary file.
func (s *Store) writeAtomic(data []byte) error {
	if err := atomicfile.WriteAtomic(s.path, data, 0600); err != nil {
		return fmt.Errorf("write DNS ownership: %w", err)
	}
	return nil
}
