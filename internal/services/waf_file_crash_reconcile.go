package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

// processStartedAt 标记本进程启动时刻。它给出「可以断定不属于本进程」的时间
// 上界：本进程还没写过任何 WAF 文件，早于该时刻的产物只可能来自上一次运行
// （崩溃残留或上一次会话的正常产物），而正在进行的导入/更新产物天然晚于它，
// 因此崩溃残留对账不会误删在途文件。测试可注入更早/更晚的时刻控制判据。
var processStartedAt = time.Now()

// wafSnapshotParentDir 是导入快照临时目录的父目录（测试可注入）。
var wafSnapshotParentDir = os.TempDir

// wafFileStartupWritesAllowed 是「启动期规则库文件/版本行本地修复」的统一写
// 入门（ip2region 与威胁名单共用）：从节点的文件与版本行都由集群同步治理，
// 本地改写会与主端声明打架；角色读失败按不可写处理并留痕（静默 fail-open 会
// 让从节点擅自改写主端声明）。
func wafFileStartupWritesAllowed(label string) bool {
	if db.DB == nil {
		return false
	}
	isMaster, err := RoleOf(context.Background(), db.DB)
	if err != nil {
		Logf("warn", "%s: 读取节点角色失败，跳过启动期文件/版本行本地修复（角色不可证实，宁停勿写）: %v", label, err)
		return false
	}
	return isMaster
}

// ReconcileWafFileCrashLeftovers 收敛「规则库文件先落盘、事务随后才提交」这个
// 窗口里进程被 SIGKILL/断电留下的残留。启动（以及手动重载）时调用一次，
// 四项互相独立、全部幂等：
//
//  1. 导入快照临时目录 <tmp>/lbbak-waf-snapshot-*：导入成功即 discard，崩溃
//     则永久残留——目录里是导入前的 CRS 树/威胁名单/xdb 副本（可达数十 MB）。
//  2. live xdb 的 .version 伴生标记与 security_ip2region_version 行分叉：启动
//     装载只处理「缺失/损坏」，版本不一致会一直停留到下次成功更新，期间版本
//     展示与集群 ref（wafFilesRefDiffers）与在役库不符。
//  3. security_threat_sources 里已不存在的 threat-*.iplist/.fast 残留：DB 无
//     记录而文件仍被 WAF 加载，集群 ref 也会认为本端持有该源。
//  4. live rules 下点前缀 .conf：同步打包/哈希按瞬态名跳过，Coraza 的
//     Include glob 却会加载；只清理这个可执行但未纳管的交集，保留其它留底。
//
// 「早于本进程启动」是前三项共同的判据（见 processStartedAt）：在途导入/更新的
// 产物晚于启动时刻，不会被误收敛。第 2、3 项改 DB/执行面引用，与 CRS 对账
// 同口径只在主节点执行；第 1、4 项是纯节点本地磁盘清理，任何角色都做。
func ReconcileWafFileCrashLeftovers() {
	pruneStaleWafSnapshotDirs()
	pruneUnmanagedHiddenCRSConf()
	if !wafFileStartupWritesAllowed("WAF 文件崩溃残留对账") {
		return
	}
	reconcileIP2RegionVersionFromDiskMarker()
	pruneOrphanThreatFiles()
}

// pruneStaleWafSnapshotDirs 删除上一次运行遗留的导入快照目录。
func pruneStaleWafSnapshotDirs() {
	matches, err := filepath.Glob(filepath.Join(wafSnapshotParentDir(), "lbbak-waf-snapshot-*"))
	if err != nil {
		Logf("warn", "WAF 导入快照目录扫描失败（跳过本轮清理）: %v", err)
		return
	}
	removed := 0
	for _, dir := range matches {
		info, statErr := os.Stat(dir)
		if statErr != nil || !info.IsDir() || !info.ModTime().Before(processStartedAt) {
			continue
		}
		if removeErr := os.RemoveAll(dir); removeErr != nil {
			Logf("warn", "WAF 导入快照目录清理失败 %s: %v", dir, removeErr)
			continue
		}
		removed++
	}
	if removed == 0 {
		return
	}
	Logf("warn", "已清理 %d 个导入崩溃残留的 WAF 文件快照目录（%s）", removed, wafSnapshotParentDir())
	RecordAuditLog("system", "清理", "配置备份",
		fmt.Sprintf("启动对账清理 %d 个导入崩溃残留的 WAF 文件快照目录（进程在导入提交前退出留下的副本）", removed), "")
}

// pruneUnmanagedHiddenCRSConf 清理 live rules 下不会被同步打包/哈希纳管、
// 却会被 Coraza Include rules/*.conf 加载的点前缀规则文件。其它隐藏标记、
// 管理员留底与正式规则均保留；仅删除这个「可执行但不可见」的交集。
func pruneUnmanagedHiddenCRSConf() {
	rulesDir := filepath.Join(crsLiveDir, "rules")
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if !os.IsNotExist(err) {
			Logf("warn", "CRS live 未纳管规则扫描失败 %s: %v", rulesDir, err)
		}
		return
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		path := filepath.Join(rulesDir, name)
		if err := os.Remove(path); err != nil {
			Logf("warn", "CRS live 未纳管点前缀规则清理失败 %s: %v", path, err)
			continue
		}
		removed++
	}
	if removed == 0 {
		return
	}
	Logf("warn", "已清理 %d 个 live 中不参与同步校验但会被 Include 加载的点前缀 .conf", removed)
	RecordAuditLog("system", "清理", "规则库",
		fmt.Sprintf("启动对账清理 %d 个未纳管但会被 Coraza 加载的点前缀 .conf", removed), "")
}

// reconcileIP2RegionVersionFromDiskMarker 按磁盘的 .version 伴生标记校正版本行。
//
// 分工：磁盘是在役库的事实来源（GeoIP 判决用的是它），版本行驱动展示与集群
// ref。导入在提交前崩溃时文件与标记已是备份代、事务回滚让版本行停在旧代——
// 只校正版本行，不反向改文件（把在役库换回旧代属回滚，需要快照，不在此处）。
func reconcileIP2RegionVersionFromDiskMarker() {
	info, err := os.Stat(ip2regionLivePath)
	if err != nil || !info.Mode().IsRegular() || !info.ModTime().Before(processStartedAt) {
		return
	}
	raw, err := os.ReadFile(ip2regionLivePath + ".version")
	if err != nil {
		// 标记缺失无从判定，保留现状（InitIP2Region 的缺失/损坏分支自理）。
		return
	}
	tag := sanitizeBundleVersion(strings.TrimSpace(string(raw)))
	if tag == "" {
		return
	}
	current, verr := GetIP2RegionVersion()
	if verr != nil && !errors.Is(verr, sql.ErrNoRows) {
		Logf("warn", "ip2region: 启动对账读取版本行失败，保留原记录（不按磁盘标记覆盖）: %v", verr)
		return
	}
	if current == tag {
		return
	}
	if err := SetIP2RegionVersion(tag); err != nil {
		Logf("warn", "ip2region: 启动对账版本行校正失败（保留原记录，不写成功审计）: %v", err)
		return
	}
	Logf("warn", "ip2region: 启动对账把版本行从 %q 校正为磁盘标记 %q（文件已在导入提交前落盘、进程随后退出）", current, tag)
	RecordAuditLog("system", "更新", "IP数据库",
		fmt.Sprintf("启动对账：live 库版本标记为 %q 而版本行为 %q，已按在役库校正版本行", tag, current), "")
}

// pruneOrphanThreatFiles 删除「源已不在 security_threat_sources」的威胁名单文件。
//
// 表是执行面的唯一真相：DB 无该源时文件不应继续被加载，残留会让记录与执行面
// 分叉（面板不可见但 WAF 生效），集群 ref 也会认为本端持有该源。
func pruneOrphanThreatFiles() {
	if db.DB == nil {
		return
	}
	rows, err := db.DB.Query(`SELECT name FROM security_threat_sources`)
	if err != nil {
		Logf("warn", "威胁名单孤儿文件对账：读取威胁源失败，跳过本轮: %v", err)
		return
	}
	defer rows.Close()
	known := map[string]struct{}{}
	for rows.Next() {
		var name string
		if scanErr := rows.Scan(&name); scanErr != nil {
			Logf("warn", "威胁名单孤儿文件对账：扫描威胁源失败，跳过本轮: %v", scanErr)
			return
		}
		if name != "" {
			known[name] = struct{}{}
		}
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		Logf("warn", "威胁名单孤儿文件对账：遍历威胁源失败，跳过本轮: %v", rowsErr)
		return
	}
	dir := WafDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		Logf("warn", "威胁名单孤儿文件对账：扫描名单目录失败，跳过本轮: %v", err)
		return
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "threat-") {
			continue
		}
		source := strings.TrimPrefix(name, "threat-")
		source = strings.TrimSuffix(strings.TrimSuffix(source, ".fast"), ".iplist")
		if source == "" || source == name {
			continue
		}
		if _, ok := known[source]; ok {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.ModTime().Before(processStartedAt) {
			continue
		}
		if removeErr := os.Remove(filepath.Join(dir, name)); removeErr != nil && !os.IsNotExist(removeErr) {
			Logf("warn", "威胁名单孤儿文件删除失败 %s: %v", name, removeErr)
			continue
		}
		removed++
	}
	if removed == 0 {
		return
	}
	Logf("warn", "已清理 %d 个已删除威胁源的残留名单文件（%s）", removed, dir)
	RecordAuditLog("system", "清理", "安全策略",
		fmt.Sprintf("启动对账清理 %d 个已删除威胁源的残留名单文件（DB 无记录仍会被 WAF 加载）", removed), "")
}
