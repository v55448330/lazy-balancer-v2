package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
)

// defaultRuleLogDir 规则访问日志目录默认值（写入端写死 /app/logs/rules）。
// 单源供 ruleLogDir 初值与 TestMain 终态复位断言引用。
const defaultRuleLogDir = "/app/logs/rules"

// ruleLogDir 规则访问日志目录。包级 var 仅为
// 测试注入缝（handlers.wafAuditLogFile 同模式）；生产路径不得改写。
var ruleLogDir = defaultRuleLogDir

// SetRuleLogDirForTest 覆盖规则日志目录并返回恢复函数（handlers 侧端点测试
// 需要真实文件系统形态：目录/权限故障必须映射 500 而不是空日志）。
func SetRuleLogDirForTest(dir string) func() {
	original := ruleLogDir
	ruleLogDir = dir
	return func() { ruleLogDir = original }
}

func RuleLogPath(ruleID string) string {
	return filepath.Join(ruleLogDir, fmt.Sprintf("%s.log", RuleLogFileComponent(ruleID)))
}

// RuleLogFileComponent 是规则访问日志文件名主体的单源（写侧 RuleLogPath 与
// handlers 读侧共用），内部直接复用可逆编码 encodeFileComponent——此前经
// sanitizeRuleLogName 的纯透传二层已合并（两层同义委托只增加阅读跳转）。
// caddy_id 字母表 [A-Za-z0-9_-] 内的 ID 原样保留（既有文件命名零变化）；
// 含其他字符的 ID 不剔除字符——剔除不可逆且会让 `lb.dot` 与 `lbdot` 共用
// 同一日志文件（删除/读取互相污染），改为 "%" + hex(utf8)。编码分支服务于
// 集群快照/存量数据带入的带点 ID：v2 导入路径已由 ValidCertRuleID 拒绝
// 字母表外 ID（config_backup.go），故新写入不再产生此类 ID。
func RuleLogFileComponent(ruleID string) string {
	return encodeFileComponent(ruleID)
}

// fileComponentSafe 报告 value 是否仅含文件名安全字母表 [_-]
// （= caddy_id 字符集；rulelog 与 certjoblog 共用同一判定与编码）。
func fileComponentSafe(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// encodeFileComponent 把任意字符串转为文件名安全且**可逆**的主体：字母表内
// 原样返回（既有文件命名零变化），否则 "%" + hex(utf8)。'%' 不在字母表内，
// 与任何合法 ID 不可能碰撞，且不同 ID 恒得不同文件名（旧剔除实现会让
// `lb.dot`/`lbdot` 共文件与共写锁）。空串原样返回空串（fileComponentSafe 对
// 空串无迭代即判安全）——生产 caddy_id 由写入校验保证非空，日志端点另有
// 存在性门，空 ID 不会产生空文件名主体。
func encodeFileComponent(value string) string {
	if fileComponentSafe(value) {
		return value
	}
	return "%" + hex.EncodeToString([]byte(value))
}

// decodeFileComponent 还原 encodeFileComponent 的产物：非 '%' 前缀（字母表内
// ID 或旧实现剔除后的历史文件名）原样返回；hex 非法/为空时按字面值返回，
// 保证存量文件名恒可解析（向后兼容优先于严格性）。
func decodeFileComponent(component string) string {
	if !strings.HasPrefix(component, "%") {
		return component
	}
	raw, err := hex.DecodeString(component[1:])
	if err != nil || len(raw) == 0 {
		return component
	}
	return string(raw)
}

// ReadRuleLogFrom reads the access log from offset to EOF and returns the new
// lines plus the end offset, so callers can incrementally consume without any
// server-side state. Rotation is detected two ways: size < offset (新文件还没
// 长过旧偏移) 与「offset 不再落在行首」(新文件已长过旧偏移)——两者都从 0 重启。
// 第二形态是启发式：新文件已长过旧 offset 且 offset-1 恰在行边界时无法识别
// （残余窗口见下方实现注释），此时由调用方传 offset=0 触发全量重读。
// 日志文件尚不存在=正常空（规则刚创建/尚无流量，非法 caddy_id 另由端点
// 存在性门拦截）；其余 I/O 错误（权限/目录/EISDIR 等）必须上抛——静默返回
// 空会让「日志读不出来」与「没有日志」在 UI 与运维侧无从区分。
func ReadRuleLogFrom(ruleID string, offset int64) (lines []string, next int64, err error) {
	path := RuleLogPath(ruleID)
	f, openErr := os.Open(path)
	if openErr != nil {
		if errors.Is(openErr, os.ErrNotExist) {
			return nil, offset, nil
		}
		return nil, offset, fmt.Errorf("open rule log %s: %w", path, openErr)
	}
	defer f.Close()
	info, statErr := f.Stat()
	if statErr != nil {
		return nil, offset, fmt.Errorf("stat rule log %s: %w", path, statErr)
	}
	if info.Size() < offset {
		offset = 0
	} else if offset > 0 {
		// 轮转的第二种形态：新文件在两次轮询之间已增长到 ≥ 旧 offset
		// （默认 100MB 上限时约需 20MB/s 单规则写入，调大 roll_size_mb 后窗口
		// 更宽）。此时 size<offset 不成立，seek 会落进新文件中段 → 前段日志
		// 永久丢失且 offset 单调前进、log-stream 无 resync 通道。
		// 不变量：正常增长时返回的 offset 恒在行首，offset-1 必为 '\n'。
		// 「整窗无换行的超长单条记录」也会把 offset 推进到行中（maxRead 推进
		// 语义），故额外要求 offset 前 4KB 内确有换行才判轮转——真正的轮转文
		// 件几乎必然在窗口内带换行，纯二进制/超长单行不受影响。
		//
		// 已知残余窗口（启发式，无状态契约下不可消除）：轮转后的新文件在下一次
		// 轮询前已长过旧 offset，且 offset-1 恰好落在行边界时，两条判据都不成立
		// （新旧内容巧合），函数从中段继续读——新文件前 offset 字节不再交付，
		// 且 offset 单调前进、log-stream 无自动 resync。概率≈1/平均行长（访问
		// 日志 0.3%–1%），需「新文件已长过旧 offset」前提（默认 roll_size_mb=100
		// 时约 20MB/s 单规则写入）。需要全量重读时由调用方传 offset=0（端点
		// 契约支持），函数本身不持有 inode/指纹，无法自行判定。
		var prev [1]byte
		if _, readErr := f.ReadAt(prev[:], offset-1); readErr == nil && prev[0] != '\n' {
			window := int64(4096)
			if offset < window {
				window = offset
			}
			probe := make([]byte, window)
			if _, rerr := f.ReadAt(probe, offset-window); rerr == nil && bytes.ContainsRune(probe, '\n') {
				offset = 0
			}
		}
	}
	if offset < 0 {
		offset = 0
	}
	if _, seekErr := f.Seek(offset, io.SeekStart); seekErr != nil {
		return nil, offset, fmt.Errorf("seek rule log %s: %w", path, seekErr)
	}
	// Cap each poll so a huge or maliciously reset offset cannot force a
	// full-log allocation; the caller continues from the returned offset.
	// 8MB covers ~1.6-4K header-rich lines per 5s poll.
	data, readErr := io.ReadAll(io.LimitReader(f, maxRead+1))
	if readErr != nil {
		return nil, offset, fmt.Errorf("read rule log %s: %w", path, readErr)
	}
	if len(data) > maxRead {
		data = data[:maxRead]
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		// Hold back the unterminated trailing record so it is delivered
		// complete on the next poll instead of being skipped forever.
		// bytes.LastIndexByte 免去至多 8MB 窗口的
		// string(data) 整体复制（尾行未终结时每 5s 轮询各命中一次）。
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else if int64(len(data)) >= maxRead {
			// 整窗读满（达 maxRead）仍无换行——单条
			// 记录超过读取窗口（>8MB 单行/二进制/损坏日志）。旧式 data=nil 使
			// next==offset 原地不动，日志流永久卡死。至少前进一个窗口：丢弃
			// 本窗字节并把 next 推到窗口末，后续轮询从新 offset 继续。
			next = offset + int64(len(data))
			return nil, next, nil
		} else {
			// 未满窗且无换行（文件/记录暂未终结）：保持扣留语义——data 置空、
			// next 停在 offset，待写侧补全换行后下轮交付完整行（访问日志逐行
			// 落盘的正常中间态）。
			data = nil
		}
	}
	next = offset + int64(len(data))
	text := string(data)
	var parts []string
	if text != "" {
		parts = strings.Split(text, "\n")
		if parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
	}
	return parts, next, nil
}

// ReadRuleLogTail returns the last maxLines lines of the rule's access log
// and the file offset at which they begin, reading backwards in blocks so
// even very large logs cost only a few reads.
// maxBackwardScan:向前扫描字节上限——无换行的损坏/二进制文件
// 防止 O(n²) 全量拷贝(100MB 无换行 ≈ 数十 GB 级复制)
const maxBackwardScan = 4 << 20 // 4MB

// maxRead ReadRuleLogFrom 单次轮询的读取窗口上限（测试引用同一常量，
// 禁止在用例内重写字面量）。8MB 约合每 5s 轮询 1.6-4K 条头部丰富的日志行。
const maxRead = 8 << 20

func ReadRuleLogTail(ruleID string, maxLines int) (content string, offset int64, err error) {
	path := RuleLogPath(ruleID)
	f, openErr := os.Open(path)
	if openErr != nil {
		if errors.Is(openErr, os.ErrNotExist) {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("open rule log %s: %w", path, openErr)
	}
	defer f.Close()
	info, statErr := f.Stat()
	if statErr != nil {
		return "", 0, fmt.Errorf("stat rule log %s: %w", path, statErr)
	}
	if info.Size() == 0 {
		return "", 0, nil
	}
	size := info.Size()
	const blockSize = int64(64 * 1024)
	// 两段式倒扫——此前 `buf = append(chunk, buf...)`
	// 每块向前拼接是二次方拷贝（4MB 扫描上限内最坏 ≈130MB 瞬时分配，单次
	// GetRuleLogs 可反复触发）。第一段只倒序记窗口起点+数换行（单块 scratch
	// 复用），第二段对定窗单次 ReadAt 读回。行为逐字节不变：cap 判定、
	// ReadAt 错误丢弃所在块（窗口止于已读前缀）、换行计数、cut 扫描与旧实现
	// 逐分支等价，offset 返回值 size-len(buf)+cut 不变。
	scratch := make([]byte, blockSize)
	winStart := size
	newlines := 0
	scanned := int64(0)
	capped := false
	for end := size; end > 0 && newlines < maxLines+1; {
		// maxBackwardScan 接线：无换行/损坏文件
		// 不再一路扫到文件头，超限即停并返回部分 tail（一次性 warn 留痕）。
		if scanned >= maxBackwardScan {
			capped = true
			break
		}
		start := end - blockSize
		if start < 0 {
			start = 0
		}
		n := int(end - start)
		if _, readErr := f.ReadAt(scratch[:n], start); readErr != nil {
			// 首块即失败=文件根本读不出来（目录/EISDIR/权限/介质错误），
			// 必须上抛而不是伪装成「空日志」；后续块的失败维持既有「窗口止于
			// 已读前缀」语义（部分 tail 优于整体失败）。
			if scanned == 0 {
				return "", 0, fmt.Errorf("read rule log %s: %w", path, readErr)
			}
			break
		}
		winStart = start
		scanned += int64(n)
		for _, b := range scratch[:n] {
			if b == '\n' {
				newlines++
			}
		}
		end = start
	}
	// 首报留痕+节流：命中上限逐规则只报一次 warn（用户反复打开
	// 日志弹框不再每读一次刷一行），读到未截断 tail 时补一条恢复 info——
	// 与排程读失败/日志轮转刷新的 logStateTransition 口径同源。
	if lvl := logStateTransition("rulelog-tail-cap-"+ruleID, capped); lvl != "" {
		if capped {
			Logf(lvl, "rule log tail for %s hit %dMB backward scan cap, returning partial tail", ruleID, maxBackwardScan>>20)
		} else {
			Logf(lvl, "rule log tail for %s resumed below the backward scan cap", ruleID)
		}
	}
	buf := make([]byte, size-winStart)
	if n, err := f.ReadAt(buf, winStart); err != nil && n < len(buf) {
		// 理论不可达（窗口内各块第一段均已读成功）；保持旧实现「读取错误即
		// 以已读前缀为窗口」的语义。
		buf = buf[:n]
	}
	// keep only the last maxLines lines; when the log holds fewer lines than
	// maxLines, cut stays 0 and everything is returned. An unterminated
	// trailing record still counts as a line.
	lines := 0
	cut := 0
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		lines = 1
	}
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] == '\n' {
			lines++
			if lines > maxLines {
				cut = i + 1
				break
			}
		}
	}
	return string(buf[cut:]), size - int64(len(buf)-cut), nil
}

// RemoveRuleLogFiles 删除规则的访问日志与全部轮转副本（基层 + `.<n>` +
// timberjack 时间戳副本）。返回聚合错误：文件不存在视为成功（幂等重试），
// 其余失败（权限/只读挂载/IO）必须回报——删除失败即磁盘残留，与
// RemoveCertJobLogFiles 同口径，调用方据此审计「清理失败」。
//
// 删除面单点：认领、枚举与删除全在 removeRuleLogRotations（认领口径与孤儿
// 扫描共用 ruleLogComponentOf）。此前另有 `base.1..5` 显式循环，与随后整目录
// 扫描完全重叠——目录可读时纯冗余 syscall，还把「错误条数=6」变成了对外契约。
func RemoveRuleLogFiles(ruleID string) error {
	return removeRuleLogRotations(RuleLogPath(ruleID))
}

// timberjackRotationReasons 会写进轮转副本名 reason 段的上游取值（timberjack
// v1.4.8）：rotate("size")（按 roll_size_mb）、rotate("time")
// （RotationInterval/RotateAtMinutes/RotateAt 触发）与 openNew("initial")
// ——后者只在「现存文件存在但不可追加打开」的回退路径上触发（属主/权限不匹配、
// 只读挂载、被替换为目录等），此时 openNew 会先把现存文件改名为
// `<stem>-<ts>-initial.log[.gz]` 再新建，故该 reason 确实会落进副本名。
// 渲染侧当前只发射 roll_size_mb，time/initial 家族正常路径不可达，但白名单按
// 上游家族完整覆盖——新增轮转触发键时必须在此登记，否则副本永久残留而清理
// 报成功。键集↔家族的双向门禁在 rulelog_rotation_naming_test.go
// （TestTimberjackRotationReasonFamily_…）。
var timberjackRotationReasons = []string{"size", "time", "initial"}

// timberjackRotationReasonSuffix 匹配 timberjack 副本的 reason+扩展尾部：
// `-<reason>[_<碰撞计数>].log`（调用方已剥压缩后缀 .gz/.zst）。reason 家族
// 取自 timberjackRotationReasons（上游写侧白名单），删除侧与统计侧共用本
// 正则——两侧曾各写一份命名知识（`-size` 与 `_N` 碰撞后缀的分歧即由此产生）。
var timberjackRotationReasonSuffix = regexp.MustCompile(
	`-(?:` + strings.Join(timberjackRotationReasons, "|") + `)(?:_\d+)?\.log$`)

// rotationTimestampShape 时间戳段的形状（唯一形表，删除侧与统计侧共用），
// 三种上游/历史形态：
//   - 紧凑 YYYYMMDD[T|-]HHMMSS（任务/运行日志族与旧删除侧形态）；
//   - 紧凑日期 + 短横线时刻 YYYYMMDDTHH-MM-SS（旧删除侧接受的形态）；
//   - 短横线日期 + T + 短横线时刻 YYYY-MM-DDTHH-MM（timberjack 默认时间格式）。
var rotationTimestampShape = regexp.MustCompile(`^(?:\d{8}[T-]\d{6}|\d{8}T\d{2}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}T\d{2}-\d{2})`)

// rotationTimestampTail 判定 s 是否以「时间戳段」开头（其后可带毫秒/尺寸等
// 余段）——轮转副本名族的唯一时间戳判据。
func rotationTimestampTail(s string) bool {
	return rotationTimestampShape.MatchString(s)
}

// StripRotationCollisionSuffix 剥掉同秒重复轮转的碰撞后缀 -N（N≥2，至多两位）：
// 写侧在同秒重名时产出 <副本名>-2/-3…。位数上限避免误剥时间戳时刻段（-150405）。
// 删除侧（归属反解的重试）与统计侧（副本归基）共用。
func StripRotationCollisionSuffix(s string) (string, bool) {
	dash := strings.LastIndexByte(s, '-')
	if dash <= 0 || len(s)-dash-1 == 0 || len(s)-dash-1 > 2 {
		return "", false
	}
	digits := s[dash+1:]
	if !ruleLogAllDigits(digits) {
		return "", false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 2 {
		return "", false
	}
	return s[:dash], true
}

// SplitTimberjackRotationCopy 解析 timberjack 轮转副本名，返回副本主体
// （轮转尾之前的部分）与是否命中。core 必须已由调用方剥掉压缩后缀。
//
// 识别形状：`<stem>-<时间戳>[.<毫秒>][-<尺寸/其它数字段>]*-<reason>[_<碰撞>].log`
// ——时间戳段起点从右往左找（stem 允许含 '-<数字>'，兄弟规则 ID 不被切走），
// 判据=rotationTimestampTail；reason 家族=timberjackRotationReasonSuffix。
// 删除侧（ruleLogComponentOf 的归属反解）与统计侧
// （handlers.classifyRotationCopyName）共用本函数：两侧各持一份解析曾让统计侧
// 认领的 `-<时间戳>-<尺寸>-<reason>.log` 在删除侧落成一个幻影规则 ID，只能靠
// 孤儿兜底延迟收敛。
func SplitTimberjackRotationCopy(core string) (string, bool) {
	if stem, ok := splitTimberjackTail(core); ok {
		return stem, true
	}
	// 同秒碰撞后缀（<副本名>-2）先剥再试；剥失败/无匹配时按原名返回未命中
	// （避免把 `<component>-2.log` 这类合法活动文件名误判为副本）。
	if stripped, ok := StripRotationCollisionSuffix(core); ok {
		return splitTimberjackTail(stripped)
	}
	return "", false
}

func splitTimberjackTail(core string) (string, bool) {
	loc := timberjackRotationReasonSuffix.FindStringIndex(core)
	if loc == nil {
		return "", false
	}
	head := core[:loc[0]]
	for i := len(head) - 1; i > 0; i-- {
		if head[i] != '-' {
			continue
		}
		if !rotationTimestampTail(head[i+1:]) {
			continue
		}
		return head[:i], true
	}
	return "", false
}

// timberjackRotationCopyStem 返回文件名去掉 .log / .log.gz / .log.zst 后的
// 主体（不是 .log 族时返回空串）。删除与孤儿判定用它做归属反解：规则日志
// 文件名以词法承载归属，当构造 caddy_id 自身以「完整时间戳 + reason」结尾时，
// 它的活动文件与「前缀规则的轮转副本」同形——只有把整段主体当候选规则日志
// 主体去查存活清单，才能把两者分开。
func timberjackRotationCopyStem(name string) string {
	for _, suffix := range []string{".log", ".log.gz", ".log.zst"} {
		if trimmed, ok := strings.CutSuffix(name, suffix); ok {
			return trimmed
		}
	}
	return ""
}

// ruleLogLiveIDsForOwnership 读取存活规则的 caddy_id 集合（删除侧归属反解）。
// 库不可用/读取失败返回 (nil, err)：调用方据此对「可能与某条规则活文件同形」
// 的候选保留不删并留痕——宁可留一份派生日志副本，也不 unlink 存活规则正在
// 写的文件（写侧仍持有 fd，丢失在下次轮转前不可见）。
func ruleLogLiveIDsForOwnership() (map[string]bool, error) {
	return liveRuleIDs(context.Background())
}

// removeRuleLogRotations 删除 base（活动文件）与其全部已识别轮转副本。认领与
// 孤儿扫描共用 ruleLogComponentOf，覆盖任意移位代次、压缩后缀与 timberjack
// 时间戳副本；目录不存在=无副本（nil），删除失败聚合返回。
//
// 目录不可枚举（权限/被占位为非目录）时无法确定副本名域，退化为「活动文件 +
// 确定性 .1..5」逐项尝试，并把枚举失败原因一并返回（无法枚举=可能有未识别
// 残留，静默吞掉会让残留永久不可见）。
func removeRuleLogRotations(base string) error {
	dir := filepath.Dir(base)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		var errs []error
		errs = append(errs, fmt.Errorf("读取规则日志目录 %s: %w", dir, err))
		for _, path := range []string{base, base + ".1", base + ".2", base + ".3", base + ".4", base + ".5"} {
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				errs = append(errs, fmt.Errorf("删除规则日志 %s: %w", path, rmErr))
			}
		}
		return errors.Join(errs...)
	}
	return removeRuleLogRotationsInEntries(dir, strings.TrimSuffix(filepath.Base(base), filepath.Ext(base)), entries)
}

// removeRuleLogRotationsInEntries 在调用方提供的目录清单上执行删除面（批量
// 入口一次枚举、逐规则复用——此前逐规则各自 ReadDir 同一目录，删除成本
// O(规则数×目录条目数)；枚举与删除之间目录变化的 TOCTOU 由 os.Remove 吞
// ENOENT 兜底，扫描后新产生的轮转副本留给下一轮周期清理）。清单必须来自
// dir 的当次 ReadDir；路径按 dir 现值拼接（把 ruleLogDir 改指故障路径的
// 钉测依赖此语义）。
func removeRuleLogRotationsInEntries(dir, component string, entries []os.DirEntry) error {
	var errs []error
	var liveIDs map[string]bool
	liveLoaded := false
	unverifiedRetained := 0
	ownedByLiveRule := func(copyStem string) bool {
		// 归属反解只在「整段主体也在 caddy_id 字母表内」时有意义：生产轮转
		// 副本名含毫秒点（-2026-10-23T18-38-57.122-size），不可能等于规则 ID，
		// 故默认形态零额外查询。
		if !fileComponentSafe(copyStem) {
			return false
		}
		if !liveLoaded {
			loaded, loadErr := ruleLogLiveIDsForOwnership()
			liveIDs = loaded
			liveLoaded = true
			if loadErr != nil {
				Logf("warn", "规则日志轮转副本归属无法核对（存活规则清单读取失败），候选保留不删: %v", loadErr)
			}
		}
		if liveIDs == nil {
			unverifiedRetained++ // 无法核对：保留（见 helper 注释的取舍）
			return true
		}
		return liveIDs[decodeFileComponent(copyStem)]
	}
	for _, e := range entries {
		name := e.Name()
		owner, ok := ruleLogComponentOf(name)
		if !ok {
			continue
		}
		// 剥尾主体 ≠ 待删规则时的唯一可删形态：类副本 ID 规则（待删规则
		// caddy_id = 存活前缀 + 真实轮转尾）的文件——其整段主体恰为本规则
		// ID，剥尾主体落在存活前缀上。整段主体（字母表安全门）不等于本规则
		// ID 的一律跳过：前缀规则本体的活动文件 <前缀>.log 与其轮转副本
		// 不得被连带删除。TOCTOU（扫描后文件被并发改写/替换）由下方
		// os.Remove 吞 ENOENT 兜底。
		if owner != component {
			body, _ := ruleLogFileBody(name)
			if body != component {
				continue
			}
		}
		// 归属反解：若整段主体本身是另一条存活规则的 caddy_id，该文件是那条
		// 规则的活文件/副本（构造 ID 恰好以 <完整时间戳>-<reason> 结尾），
		// 不得作为本规则的轮转副本删除。活动文件本身（copyStem == component）
		// 是本规则自己的日志，不做归属反解（否则存活规则的自身文件被保留，
		// 删除规则后残留永久不可见）。
		if copyStem := timberjackRotationCopyStem(name); copyStem != "" && copyStem != component && ownedByLiveRule(copyStem) {
			continue
		}
		path := filepath.Join(dir, name)
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			errs = append(errs, fmt.Errorf("删除规则日志 %s: %w", path, rmErr))
		}
	}
	if unverifiedRetained > 0 {
		// 归属无法核对的候选副本被保留=本轮清理未完成，必须进错误面——
		// 此前只留 warn 日志，事件型删除入口（删规则/导入差集/集群差集）
		// 按成功收尾，审计口径与磁盘残留不一致。
		errs = append(errs, fmt.Errorf("存活规则清单读取失败，%d 个轮转副本归属无法核对已保留（清理未完成）", unverifiedRetained))
	}
	return errors.Join(errs...)
}

// ruleLogOrphanPurgePerRun 单轮最多清理的孤儿规则数（有界：首次上线/历史残留
// 可能有大量规则目录条目，本轮清不完留下轮继续；与 metrics 孤儿清理同形）。
var ruleLogOrphanPurgePerRun = 500

// RuleLogHousekeepingResult 孤儿规则访问日志清理明细。
type RuleLogHousekeepingResult struct {
	// Purged 本轮已清理（活动文件 + 全部轮转副本）的规则 ID。
	Purged []string
	// RemoveFailed 删除失败数（权限/只读挂载/IO）——失败即残留，必须进结果
	// 错误面，摘要不得称完成。
	RemoveFailed int
	// ScanError 目录读取/存活规则清单读取失败原因（非空=本轮未删除任何文件：
	// 无法区分「规则已删除」与「清单读不出来」时删除会误删存活规则的日志）。
	ScanError string
	// Remaining 达单轮上限未处理的孤儿规则数（下轮继续，非失败）。
	Remaining int
}

// Summary 一行明细摘要（空动作时「清理 0 个」）。
func (r RuleLogHousekeepingResult) Summary() string {
	list := func(names []string) string {
		if len(names) == 0 {
			return "无"
		}
		if len(names) > 5 {
			return strings.Join(names[:5], "、") + fmt.Sprintf(" 等 %d 个", len(names))
		}
		return strings.Join(names, "、")
	}
	summary := fmt.Sprintf("规则访问日志：孤儿规则清理 %d 个[%s]", len(r.Purged), list(r.Purged))
	var notes []string
	if r.RemoveFailed > 0 {
		notes = append(notes, fmt.Sprintf("删除失败 %d 个", r.RemoveFailed))
	}
	if r.ScanError != "" {
		notes = append(notes, "目录/存活清单读取失败"+r.ScanError)
	}
	if r.Remaining > 0 {
		notes = append(notes, fmt.Sprintf("本轮达上限，剩余 %d 个下轮继续", r.Remaining))
	}
	if len(notes) > 0 {
		summary += "、" + strings.Join(notes, "、")
	}
	return summary
}

// purgedErr 删除失败/扫描失败的错误面（nil=本轮每个动作都成功或无事可做）。
func (r RuleLogHousekeepingResult) purgedErr() error {
	var errs []error
	if r.ScanError != "" {
		errs = append(errs, fmt.Errorf("规则日志孤儿扫描失败: %s", r.ScanError))
	}
	if r.RemoveFailed > 0 {
		errs = append(errs, fmt.Errorf("规则日志删除失败 %d 个", r.RemoveFailed))
	}
	return errors.Join(errs...)
}

// ruleLogOrphanPurgeBeforeRemoveForTest 仅测试注入（nil=生产直通）：在算出
// 孤儿清单、开始删除之前触发，用于确定性钉住任务取消时的提前退出语义
// （删除不可逆，取消后不得继续）。
var ruleLogOrphanPurgeBeforeRemoveForTest func()

// PurgeOrphanRuleLogs 清理「规则已不存在」的规则访问日志（活动文件 + 移位/
// 时间戳轮转副本）。规则日志此前只有三个事件型删除入口（删除规则 / 导入差集 /
// 集群差集），任一路径失败即永久残留（单规则含副本上限约 6×caddy_log_size_mb），
// 且无重试——本任务提供周期兜底（与 metrics 孤儿清理同构）。
//
// 判定域是 lb_rules.caddy_id：清单读取失败时一个文件都不删（否则会把存活规则
// 的日志当孤儿清掉），按 ScanError 上抛。文件名还原失败的条目一律跳过——外来
// 文件不属于本规则的日志族，不得误删。ctx 取消时提前返回，未处理条目计入
// Remaining；库未初始化（启动早期）时按 ScanError 上抛（不删除）——与实现
// 及钉测一致（rulelog_orphan_purge_test.go 要求 ScanError != ""，本轮清理
// 全停必须在任务终态可见）。
func PurgeOrphanRuleLogs(ctx context.Context) RuleLogHousekeepingResult {
	result := RuleLogHousekeepingResult{}
	// 与 PurgeOrphanMetricsHistory 同口径：库未初始化（启动早期/关停竞态里仍
	// 在跑的本轮/嵌入形态）时无可判定的存活规则——不删除，并把原因进错误面
	// （静默零值会让「本轮清理全停」与「无事可做」同形）。
	if db.DB == nil {
		result.ScanError = "数据库未初始化，跳过孤儿规则日志清理（不删除）"
		return result
	}
	entries, err := os.ReadDir(ruleLogDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result // 尚无规则访问日志（首次运行/未启用）：正常空目录
		}
		result.ScanError = err.Error()
		return result
	}
	liveIDs, err := liveRuleIDs(ctx)
	if err != nil {
		result.ScanError = fmt.Sprintf("读取存活规则清单失败: %v", err)
		return result
	}
	seen := map[string]bool{}
	var orphans []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		component, ok := ruleLogComponentOf(e.Name())
		if !ok {
			continue
		}
		ruleID := decodeFileComponent(component)
		// 归属优先按「整段主体是否为存活规则」反解：构造 ID 恰以
		// <完整时间戳>-<reason> 结尾时，其活动文件在词法上等价于前缀规则的
		// 轮转副本，前缀规则已删除时会被误判为孤儿——整段主体是存活规则 ID
		// 则归属它，不清理。
		// 第三态：整段主体解码为已删规则、剥尾主体却是存活前缀——已删「类
		// 副本 ID」规则（caddy_id = 存活前缀 + 真实轮转尾）的残留永不收敛。
		// 可安全归属给已删主体：存活规则的活动文件恒为 <其主体>.log，而本
		// 文件整段主体解码非存活，故不可能是任何存活规则的活动文件（字母表
		// 安全门排除 %hex 编码与带点毫秒尾形态）；扫描与删除之间并发轮转的
		// TOCTOU 由删除侧 os.Remove 吞 ENOENT 兜底。
		if copyStem := timberjackRotationCopyStem(e.Name()); copyStem != "" && copyStem != component && fileComponentSafe(copyStem) {
			if ownerID := decodeFileComponent(copyStem); liveIDs[ownerID] {
				ruleID = ownerID
			} else if liveIDs[ruleID] {
				ruleID = ownerID
			}
		}
		if liveIDs[ruleID] || seen[ruleID] {
			continue
		}
		seen[ruleID] = true
		orphans = append(orphans, ruleID)
	}
	if len(orphans) == 0 {
		return result
	}
	sort.Strings(orphans) // 确定性：同一积压跨轮次优先清理同一前缀
	if limit := ruleLogOrphanPurgePerRun; limit > 0 && len(orphans) > limit {
		result.Remaining = len(orphans) - limit
		orphans = orphans[:limit]
	}
	if ruleLogOrphanPurgeBeforeRemoveForTest != nil {
		ruleLogOrphanPurgeBeforeRemoveForTest()
	}
	for i, ruleID := range orphans {
		// 任务取消/停机时及时退出：已删条目不可逆，未处理条目计入 Remaining
		// 交下一轮（与 PurgeOrphanMetricsHistory 的 ctx 检查同口径）。
		if err := ctx.Err(); err != nil {
			result.Remaining += len(orphans) - i
			Logf("warn", "规则日志孤儿清理被取消（本轮已清理 %d 个，剩余 %d 个待下轮）: %v", i, len(orphans)-i, err)
			return result
		}
		// 目录清单复用扫描期快照（一次枚举，逐规则不再重扫）；删除主体仍是
		// 规则自身文件名主体（RuleLogFileComponent，与单条 API 同口径——扫描
		// 期的归属主体只是归因，不能当删除面）；路径按 dir 现值拼接，快照后
		// 新增/消失的条目分别留给下轮/由 ENOENT 吞掉。
		if err := removeRuleLogRotationsInEntries(ruleLogDir, RuleLogFileComponent(ruleID), entries); err != nil {
			Logf("error", "规则日志孤儿清理失败（%s）: %v", ruleID, err)
			result.RemoveFailed++
			continue
		}
		result.Purged = append(result.Purged, ruleID)
	}
	return result
}

// ruleLogComponentOf 从规则日志文件名还原文件名主体（encodeFileComponent 的
// 产物，decodeFileComponent 可逆还原为 caddy_id）。识别三形态：活动文件
// <component>.log、移位副本 <component>.log.<n>（旧版本/外来 logrotate 残留）
// 与 timberjack 时间戳副本 <component>-<ts>-<reason>[_N].log[.gz|.zst]；
// 压缩后缀先剥。ok=false 表示不属于任何规则的日志族（外来文件不得被清理）。
//
// 有意不认领：<副本>.log.gz.tmp / .log.zst.tmp（timberjack 压缩进行中的临时
// 文件，压缩完成即原子改名；进程崩溃则遗留）。压缩后缀剥离只认结尾 .gz/.zst，
// CutSuffix(".log") 对该名失败 → ok=false 一律跳过：认领删除会与压缩器的
// rename 竞态，而崩溃遗留的体积上界=一份未压缩副本（≤ roll_size_mb），
// 不参与统计与任何删除族，属可接受的瞬态残留。
func ruleLogComponentOf(name string) (string, bool) {
	core := name
	for _, suffix := range []string{".gz", ".zst"} {
		core = strings.TrimSuffix(core, suffix)
	}
	// 移位副本 <component>.log.<n>：只有剥掉数字段后仍以 .log 结尾才算，
	// 基名本身不含 '.'（encodeFileComponent 的产物只用 [A-Za-z0-9_-%]）。
	if dot := strings.LastIndexByte(core, '.'); dot > 0 && dot < len(core)-1 && ruleLogAllDigits(core[dot+1:]) {
		if trimmed := core[:dot]; strings.HasSuffix(trimmed, ".log") {
			core = trimmed
		}
	}
	// timberjack 时间戳副本：与统计侧共用 SplitTimberjackRotationCopy
	// （时间戳/尺寸余段/reason 家族/碰撞后缀单源）——两侧各持一份解析曾让
	// 统计侧认领的 `-<ts>-<size>-<reason>.log` 在这里落成幻影规则 ID。
	if stem, ok := SplitTimberjackRotationCopy(core); ok && stem != "" {
		return stem, true
	}
	base, ok := strings.CutSuffix(core, ".log")
	if !ok || base == "" || strings.Contains(base, ".") {
		return "", false
	}
	return base, true
}

// ruleLogFileBody 还原文件名的整段主体（encodeFileComponent 的**编码形态**，
// 与 lb_rules.caddy_id 经 encodeFileComponent 一一对应，可直接比对）：剥压缩
// 后缀与移位代次后取 .log 前段——与 ruleLogComponentOf 的前半段同变换，但
// **不做** timberjack 尾剥离。删除侧「类副本 ID 规则」的删除面用它把
// <主体>.log[.<n>][.gz|.zst] 整族认领回来（剥尾主体落在存活前缀上，owner
// 比对不到待删规则本身）。
func ruleLogFileBody(name string) (string, bool) {
	core := name
	for _, suffix := range []string{".gz", ".zst"} {
		core = strings.TrimSuffix(core, suffix)
	}
	if dot := strings.LastIndexByte(core, '.'); dot > 0 && dot < len(core)-1 && ruleLogAllDigits(core[dot+1:]) {
		if trimmed := core[:dot]; strings.HasSuffix(trimmed, ".log") {
			core = trimmed
		}
	}
	stem, ok := strings.CutSuffix(core, ".log")
	if !ok || stem == "" || strings.Contains(stem, ".") {
		return "", false
	}
	return stem, true
}

// ruleLogAllDigits 报告 s 是否全部为 ASCII 数字（非空）。
func ruleLogAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
