package services

// 轮转副本命名以生产链为准：Caddy v2.11.7 的 logging FileWriter 把
// BackupTimeFormat/Compression 原样交给 timberjack，渲染侧不写这两个配置
// （只写 output/filename/roll_size_mb/roll_keep），故取 timberjack 默认值——
// 时间格式为虚线日期 + 毫秒（日期与时刻段均以 '-' 分隔）、压缩默认 gzip
// （副本名追加 .gz）。夹具必须用真实命名，否则删除侧正则与真实文件不符
// 却仍然全绿（残留不可见）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveRuleLogFiles_deletesRealTimberjackRotationCopies(t *testing.T) {
	dir := t.TempDir()
	restore := SetRuleLogDirForTest(dir)
	t.Cleanup(restore)

	// 本规则的副本：真实形态（虚线日期 + .gz）+ 未压缩形态 + 紧凑日期历史
	// 形态 + zstd 压缩形态。
	ownCopies := []string{
		"lb_live.log",
		"lb_live-2026-10-23T18-38-57.122-size.log.gz",
		"lb_live-2026-10-23T18-38-57.122-size.log",
		"lb_live-20261023T18-38-57.122-size.log",
		"lb_live-2026-10-23T18-39-01.004-size.log.zst",
		// 同毫秒同 reason 碰撞：timberjack 的 uniqueBackupName 把计数写在
		// reason 段内（`-size_1`），不是文件名尾部。
		"lb_live-2026-10-23T18-38-57.122-size_1.log.gz",
		// 时间触发 reason（RotationInterval/RotateAtMinutes 改名时写入）：
		// 渲染侧当前不发射这三列，但白名单必须按上游家族覆盖，否则未来
		// 接入即永久残留。
		"lb_live-2026-10-23T18-38-57.122-time.log.gz",
		"lb_live-2026-10-23T18-38-57.122-time_2.log",
		// 「现存文件不可追加打开」回退 reason：timberjack 的 openNew("initial")
		// 会 rename 现存文件并保留该 reason 段（`-initial`），与 size/time
		// 同属上游命名家族。
		"lb_live-2026-10-23T18-38-57.122-initial.log.gz",
		"lb_live-2026-10-23T18-38-57.122-initial.log",
	}
	// 兄弟规则副本（caddy_id 以本规则 id 为前缀）：一个都不能动。
	brotherCopies := []string{
		"lb_live-extra-2026-10-23T18-38-57.122-size.log.gz",
		"lb_live-1-2026-10-23T18-38-57.122-size.log.gz",
		"lb_live-extra-2026-10-23T18-38-57.122-size_1.log.gz",
		"lb_live-1-2026-10-23T18-38-57.122-time.log.gz",
		"lb_live-extra-2026-10-23T18-38-57.122-initial.log.gz",
	}
	for _, name := range append(append([]string{}, ownCopies...), brotherCopies...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := RemoveRuleLogFiles("lb_live"); err != nil {
		t.Fatalf("RemoveRuleLogFiles: %v", err)
	}

	for _, name := range ownCopies {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("本规则日志 %s 未被删除（轮转副本永久残留）: %v", name, err)
		}
	}
	for _, name := range brotherCopies {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("兄弟规则副本 %s 被误删: %v", name, err)
		}
	}
}

// TestReadRuleLogFrom_knownRotationGapAtLineBoundary 把第二形态轮转检测的
// 残余窗口钉成「已知限制」：新文件已长过旧 offset 且 offset-1 恰在行边界时
// 无法识别，从新文件中段继续读（前 offset 字节不交付）。属性断言：
// ①不 rewind（offset 单调）；②调用方传 offset=0 时全量交付（唯一 resync 通道）。
func TestReadRuleLogFrom_knownRotationGapAtLineBoundary(t *testing.T) {
	dir := t.TempDir()
	restore := SetRuleLogDirForTest(dir)
	t.Cleanup(restore)
	// 轮转后的新文件：前 8 字节一行，其后一行更长，总长 > 旧 offset=8。
	content := "OLDOLD0\nNEW-LINE-AFTER-ROTATION\n"
	if err := os.WriteFile(RuleLogPath("lb_gap"), []byte(content), 0o644); err != nil {
		t.Fatalf("write rule log: %v", err)
	}

	// When：旧 offset=8 恰好落在新文件行边界（第 8 字节是 '\n' 后的首个字节）。
	lines, next, err := ReadRuleLogFrom("lb_gap", 8)
	if err != nil {
		t.Fatalf("ReadRuleLogFrom: %v", err)
	}

	// Then：已知限制——不识别轮转、不回退，前 8 字节静默丢弃。
	if next != int64(len(content)) {
		t.Fatalf("next=%d, want %d（offset 单调推进）", next, len(content))
	}
	if len(lines) != 1 || lines[0] != "NEW-LINE-AFTER-ROTATION" {
		t.Fatalf("已知限制形态应只交付中段之后的行，got %q", lines)
	}

	// Then：offset=0 是全量重读通道（运维 resync 路径）。
	all, _, err := ReadRuleLogFrom("lb_gap", 0)
	if err != nil {
		t.Fatalf("ReadRuleLogFrom(0): %v", err)
	}
	if len(all) != 2 || all[0] != "OLDOLD0" {
		t.Fatalf("offset=0 必须全量交付: %q", all)
	}
}

// writer 键 → timberjack reason 家族的绑定表（双向门禁的数据源）：
// roll_size_mb 触发 rotate("size")；时间族配置触发 rotate("time")。
// 新增任一键都必须先在 timberjackRotationReasons 里登记对应 reason，否则
// 副本命名家族与删除侧白名单失联，清理会「成功」但磁盘永久残留。
var (
	caddyLogSizeTriggerKeys = map[string]bool{"roll_size_mb": true}
	caddyLogTimeTriggerKeys = map[string]bool{"roll_interval": true, "roll_minutes": true, "roll_at": true}
	// 与 reason 无关的 writer 键（I/O 形态 / 保留份数 / 编码与时间格式）。
	caddyLogNonTriggerKeys = map[string]bool{
		"output": true, "filename": true, "roll_keep": true,
		"compression": true, "backup_time_format": true, "local_time": true,
	}
)

// TestTimberjackRotationReasonFamily_bindsRenderedWriterKeys 双向门禁：
// ①渲染 writer 键集里出现的每个轮转触发键，其 reason 家族都必须在删除侧
// 白名单内（未登记即红）；②白名单里的每个 reason 都必须能被删除侧正则匹配
// 真实副本名（避免「登记了但正则写不中」）。两者由同一处数据源驱动，
// 未来接入 roll_interval/roll_minutes/roll_at 时本门先于故障红。
func TestTimberjackRotationReasonFamily_bindsRenderedWriterKeys(t *testing.T) {
	writer := caddyLogFileWriter("/app/logs/probe.log", 100)
	if len(writer) == 0 {
		t.Fatal("writer 键集为空——门禁空洞")
	}
	reasons := map[string]bool{}
	for _, r := range timberjackRotationReasons {
		reasons[r] = true
	}
	for key := range writer {
		switch {
		case caddyLogNonTriggerKeys[key]:
		case caddyLogSizeTriggerKeys[key]:
			if !reasons["size"] {
				t.Fatalf("writer 键 %q 会产生 size 轮转副本，但删除侧白名单未登记 size", key)
			}
		case caddyLogTimeTriggerKeys[key]:
			if !reasons["time"] {
				t.Fatalf("writer 键 %q 会产生 time 轮转副本，但删除侧白名单未登记 time", key)
			}
		default:
			t.Fatalf("未知 writer 键 %q：新增轮转触发形态必须先确认 timberjack reason 家族并同步删除侧白名单", key)
		}
	}
	for reason := range reasons {
		name := "lb_probe-2026-10-23T18-38-57.122-" + reason + ".log.gz"
		if !timberjackRotationSuffix.MatchString(strings.TrimPrefix(name, "lb_probe")) {
			t.Fatalf("白名单 reason %q 的副本名 %s 不被删除侧正则匹配（登记与实现失联）", reason, name)
		}
		collision := "lb_probe-2026-10-23T18-38-57.122-" + reason + "_1.log"
		if !timberjackRotationSuffix.MatchString(strings.TrimPrefix(collision, "lb_probe")) {
			t.Fatalf("同毫秒碰撞副本 %s 不被删除侧正则匹配（uniqueBackupName 的 _N 后缀）", collision)
		}
	}
}

// 规则日志文件名以词法承载归属：若某条存活规则的 caddy_id 自身以「完整时间戳
// + reason」结尾（如 lb_abc-20260102T03-04-05-size，字母表内、导入/备份可达），
// 它的活动文件在词法上等价于前缀规则 lb_abc 的一条轮转副本。删除 lb_abc 时
// 不得把这条存活规则的文件 unlink（写侧仍持有 fd，日志会静默丢失直到下次
// 轮转/重载）。归属必须结合存活规则清单反解，而不是只看文件名。
func TestRemoveRuleLogFiles_keepsLiveSiblingWhoseIDLooksLikeRotationCopy(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))

	const prefixID = "lb_abc"
	const lookalikeID = "lb_abc-20260102T03-04-05-size"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES (?,?,?,?,1)`, lookalikeID, "lookalike", "http", 18096); err != nil {
		t.Fatalf("seed lookalike rule: %v", err)
	}
	files := []string{prefixID + ".log", lookalikeID + ".log"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	if err := RemoveRuleLogFiles(prefixID); err != nil {
		t.Fatalf("RemoveRuleLogFiles(%s): %v", prefixID, err)
	}

	if _, err := os.Stat(filepath.Join(dir, prefixID+".log")); !os.IsNotExist(err) {
		t.Fatalf("%s.log 未被删除: %v", prefixID, err)
	}
	if _, err := os.Stat(filepath.Join(dir, lookalikeID+".log")); err != nil {
		t.Fatalf("存活规则 %s 的活动日志被前缀规则删除动作误删: %v", lookalikeID, err)
	}
}
