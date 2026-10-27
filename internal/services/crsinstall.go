package services

import (
	"context"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/db"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// mergeOverridesLines 生成合并后的 overrides 内容：既有 overrides 的有效行
// 在前（保留历史自定义），本次迁移 diff 追加在后，按行文本去重（同一行只写
// 一次，消除新-2 的重复 SecRule id 顾虑），header 仅保留新的一份。
// 既有文件不可读时视作空（首次迁移场景）。
func mergeOverridesLines(existingPath, header string, diff []string) []byte {
	var merged []string
	seen := make(map[string]bool)
	if raw, err := os.ReadFile(existingPath); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			// 跳过旧迁移 header 注释行——让注释参与合并后，此前
			// 每次成功迁移会累积 2 行旧 header（"由 CRS 更新自动迁移"/"生成时间"）。
			if strings.HasPrefix(trimmed, "# 由 CRS 更新自动迁移") || strings.HasPrefix(trimmed, "# 生成时间") {
				continue
			}
			// 注释行与迁移 diff 同等保留——extractSetupDiff 把注释计为
			// 有效行（被注释禁用的自定义规则行也承载用户意图），此前仅跳空行导致
			// 第二次迁移合并时既有注释行被静默丢弃。
			if !seen[trimmed] {
				seen[trimmed] = true
				merged = append(merged, line)
			}
		}
	}
	for _, line := range diff {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			merged = append(merged, line)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return []byte(header + strings.Join(merged, "\n") + "\n")
}

// extractSetupDiff 返回 live 相对 stock 的新增有效行；空行忽略，注释行保留。
func extractSetupDiff(stock, live []string) []string {
	stockSet := make(map[string]struct{}, len(stock))
	for _, line := range stock {
		stockSet[strings.TrimSpace(line)] = struct{}{}
	}
	var diff []string
	for _, line := range live {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if _, ok := stockSet[trimmed]; !ok {
			diff = append(diff, trimmed)
		}
	}
	return diff
}

// readConfLines splits a config file into lines; a missing/unreadable file
// yields nil.
func readConfLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

// crsTransientDir 返回 CRS 更新瞬态目录（crsDir 的兄弟目录 crs.transient）
// .staging/rules.bak/rules.old 与各 *.bak 此前散落在 crsDir 内，会混入集群
// waf-files 同步打包（tarGzDir 已加过滤兜底）与目录扫描；迁出后 crsDir 只含
// 正式内容。同库 .sync-in 的「兄弟目录暂存」模式。
func crsTransientDir(crsDir string) string {
	return filepath.Join(filepath.Dir(crsDir), "crs.transient")
}

// crsTransientPath 计算 crs.transient/ 下瞬态文件路径；目录不存在由首个使用者
// 的 MkdirAll/copyDir 创建（staging/copyDirTransactional 均覆盖）。
func crsTransientPath(crsDir, name string) string {
	return filepath.Join(crsTransientDir(crsDir), name)
}

// crsReloadError 包装「下载安装成功但 Caddy 重载失败」——非瞬断网络错误，
// 任务内重试（crsupdate.go runWithInTaskRetry）不覆盖（重试会重复整套
// 下载/安装/restore 编舞；ip2regionupdate.go 的 errIP2RegionReload 同型先例）。
type crsReloadError struct{ cause error }

func (e *crsReloadError) Error() string { return e.cause.Error() }
func (e *crsReloadError) Unwrap() error { return e.cause }

// downloadAndInstall downloads, validates and swaps in the new rules. The
// live tree persists across rebuilds via the /app/waf bind mount, so no
// snapshot is taken. On failure the live tree is restored from backup by
// restoreBackup.
// cleanupLegacyCRSTransient 2026-09 复审裁定 3：迁移瞬态目录前的历史残留
// （crsDir 内 .staging/、rules.bak/、rules.old/ 与具名文件形 *.bak）随 bind
// mount 跨升级存活并混入集群同步 tar——更新成功路径一次性清理，审计留痕。
func (m *CRSUpdateManager) cleanupLegacyCRSTransient() {
	// 只删**本产品自己产生**的瞬态目标（具名集合，与 crsTransientPath 的
	// 写入点一一对应）。不得按 *.bak/*.old 后缀兜底：/app/waf/crs 下的
	// backup-2026.bak、ops-notes.bak、tree.old 之类是管理员手工留底（改
	// overrides 前自备份/运维备注），旧实现一次成功更新后把它们静默删除，
	// 日志也只报「cleaned N」不点名——数据丢失且不可归因。
	// 非具名的点前缀文件同样不在此删除——waf 同步 tar 的 skipWafSyncTransient
	// 过滤另行兜底（重构：单次 ReadDir + 具名集合判断）。
	legacyNames := map[string]bool{
		".staging":                   true, // crsTransientPath(liveDir, ".staging")
		"rules.bak":                  true, // 备份目录（事务化生成）
		"rules.bak.tmp":              true, // 备份拷贝中途残留
		"rules.old":                  true, // 树交换的旧树
		"crs-setup.conf.bak":         true, // 事务备份（setupBak）
		"crs-setup.stock.conf.bak":   true, // 事务备份（stockBak）
		"zz-user-overrides.conf.bak": true, // 事务备份（overridesBak）
	}
	entries, err := os.ReadDir(m.liveDir())
	if err != nil {
		return
	}
	removed := make([]string, 0, len(legacyNames))
	for _, e := range entries {
		if !legacyNames[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(m.liveDir(), e.Name())); err == nil {
			removed = append(removed, e.Name())
		}
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		Logf("info", "crs update: cleaned %d legacy transient artifacts from live dir: %v", len(removed), removed)
	}
}

func (m *CRSUpdateManager) downloadAndInstall(parent context.Context, tag string) error {
	// 每次运行重置：restoreBackup 仅消费本运行创建的备份（1.1 +
	// 收敛至全四件套：rules/setup/stock/overrides）。
	m.overridesBakCreated = false
	m.rulesBakCreated = false
	m.setupBakCreated = false
	m.stockBakCreated = false
	m.setStage(CRSStatusDownloading, fmt.Sprintf("下载 %s", tag))
	staging := crsTransientPath(m.liveDir(), ".staging")
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("清理 staging 目录: %w", err)
	}
	if err := os.MkdirAll(staging, 0755); err != nil {
		return fmt.Errorf("创建 staging 目录: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(staging); err != nil {
			Logf("error", "crs update: failed to clean staging dir: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	tarball := filepath.Join(staging, "crs.tar.gz")
	if err := m.downloadTarballLogged(ctx, tag, tarball); err != nil {
		return fmt.Errorf("下载 CRS 发布包: %w", err)
	}
	// TOFU 基线比对先于解包：被劫持/损坏的工件必须在展开到数据卷之前否决
	// （解包上限 500MB，先解后判等于把磁盘/CPU 放大留给攻击者，且发现点远离
	// 真实原因）。基线记录仍推迟到格式验证成功之后——验证前的坏工件（如代理
	// 返回的 200 垃圾）写入基线会让下次同 tag 好下载误报。
	// I/O 类比对失败维持仅记日志不阻断（与记录阶段同口径）。
	integrityRec, integrityErr := verifyDownloadIntegrity(crsTarballBaselineKey(tag), tarball, "CRS规则库")
	if integrityErr != nil {
		if errors.Is(integrityErr, errDownloadIntegrityMismatch) {
			return fmt.Errorf("CRS 发布包完整性校验失败: %w", integrityErr)
		}
		Logf("error", "crs update: failed to verify download integrity: %v", integrityErr)
	}
	if err := extractCRSTarball(tarball, staging); err != nil {
		return fmt.Errorf("解压 CRS 发布包: %w", err)
	}

	m.setStage(CRSStatusInstalling, "校验并安装规则")
	if err := validateCRSStaging(staging); err != nil {
		return fmt.Errorf("校验 CRS 发布包: %w", err)
	}
	// 内容与基线 mismatch 时阻断安装并保留旧基线——错误消息已含人工清基线
	// 指引（确认上游更新合法后删除 data/.download-integrity.json 对应条目
	// 重试）；此时 rules 尚未替换，直接返回即可。I/O 类记录失败维持仅记日志
	// 不阻断。
	if integrityErr != nil {
		// 比对阶段 I/O 失败（不阻断安装）：记录阶段按单步路径重试一次。
		if rerr := recordDownloadIntegrity(crsTarballBaselineKey(tag), tarball, "CRS规则库"); rerr != nil {
			if errors.Is(rerr, errDownloadIntegrityMismatch) {
				return fmt.Errorf("CRS 发布包完整性校验失败: %w", rerr)
			}
			Logf("error", "crs update: failed to record download integrity: %v", rerr)
		}
	} else if rerr := recordDownloadIntegrityRecord(crsTarballBaselineKey(tag), integrityRec); rerr != nil {
		Logf("error", "crs update: failed to record download integrity: %v", rerr)
	}

	rulesPath := filepath.Join(m.liveDir(), "rules")
	rulesBak := crsTransientPath(m.liveDir(), "rules.bak")
	// 陈旧 rules.bak 不在此无条件删除——上一运行崩溃现场残留的完整
	// 备份是唯一恢复素材，而下载/解压/校验/完整性门都在本段之前。替换发生在本运行
	// 备份拷贝成功之后（copyDirTransactional 先建 .tmp 再删旧目标），拷贝失败时
	// 陈旧备份原样保全。
	// 注意：crs-setup.conf.bak 不再在此无条件清除。上一次运行
	// 可能因还原失败保全了 .bak（三-1：唯一恢复副本）；若本运行在创建新备份前
	// 失败，该副本是仅有的自愈素材，先删后建会使其永久丢失。restoreBackup 只
	// 消费本运行创建的 .bak（overridesBakCreated 标记），陈旧 .bak 永不消费，
	// 三-2 的「还原到两版本之前」随之闭合；迁移分支创建新备份时写入覆盖
	// 自然顶掉陈旧内容。
	if _, err := os.Stat(rulesPath); err == nil {
		// backup: the live rules dir may be baked into an image
		// lower layer, where rename is impossible (EXDEV on overlayfs).
		// 事务化拷贝：中途失败（ENOSPC/EIO）只留下 rules.bak.tmp
		// 并被清理，restoreBackup 永远不会消费到部分残树。
		if err := copyDirTransactional(rulesPath, rulesBak); err != nil {
			return fmt.Errorf("备份现有 rules: %w", err)
		}
		// 本运行已创建 rules.bak：restoreBackup 自此可消费。
		m.rulesBakCreated = true
	}
	setupPath := filepath.Join(m.liveDir(), "crs-setup.conf")
	setupBak := crsTransientPath(m.liveDir(), "crs-setup.conf.bak")
	if _, err := os.Stat(setupPath); err == nil {
		if err := copyFile(setupPath, setupBak); err != nil {
			m.restoreBackup()
			return fmt.Errorf("备份 crs-setup.conf: %w", err)
		}
		m.setupBakCreated = true // 本运行已创建
	}
	// stock 基线同点备份：回滚只恢复 rules/setup/overrides 会让
	// stock 基线停留在新版本，下次迁移的 diff 基线错位——两版之间上游改动过
	// 的默认行被误判为用户自定义迁入 overrides，上游默认值变更被静默回退。
	stockPath := filepath.Join(m.liveDir(), "crs-setup.stock.conf")
	stockBak := crsTransientPath(m.liveDir(), "crs-setup.stock.conf.bak")
	if _, err := os.Stat(stockPath); err == nil {
		if err := copyFile(stockPath, stockBak); err != nil {
			m.restoreBackup()
			return fmt.Errorf("备份 crs-setup.stock.conf: %w", err)
		}
		m.stockBakCreated = true // 本运行已创建
	}

	// Migrate user customizations out of the live setup before the new stock
	// setup replaces it: diff against the last-installed stock baseline (the
	// image copy on first migration) and carry the remainder into the
	// overrides file included after the stock setup.
	// 迁移分两段：此处只算 diff 并留底.bak，实际写入推迟到 rules
	// 与新 setup 落盘成功之后——若在 rules 替换前写入，写入点与 RemoveAll(rules)
	// 之间的进程崩溃会留下「新 overrides + 旧 setup」双重应用同一批自定义行，
	// 重复 SecRule id 使 coraza 拒绝配置再生成。
	var pendingOverrides []byte
	baseline := readConfLines(filepath.Join(m.liveDir(), "crs-setup.stock.conf"))
	if baseline == nil {
		baseline = readConfLines(filepath.Join(crsDistDir, "crs-setup.conf"))
	}
	if diff := extractSetupDiff(baseline, readConfLines(setupPath)); len(diff) > 0 {
		header := fmt.Sprintf("# 由 CRS 更新自动迁移的用户自定义配置\n# 生成时间: %s\n",
			time.Now().In(CurrentLocation()).Format(crsTimeLayout))
		overridesPath := filepath.Join(m.liveDir(), "zz-user-overrides.conf")
		overridesBak := crsTransientPath(m.liveDir(), "zz-user-overrides.conf.bak")
		// 迁移写入前先留底：已有 overrides 则备份内容，没有则用空 .bak 标记
		// 「更新前不存在」。restoreBackup 据此把 overrides 还原到更新前状态——
		// 否则恢复后的旧 setup（含自定义行）与 overrides（同一批行）重复应用，
		// coraza 拒绝重复 SecRule id 致 reload 失败、更新永久卡死。
		if _, err := os.Stat(overridesPath); err == nil {
			if err := copyFile(overridesPath, overridesBak); err != nil {
				m.restoreBackup()
				return fmt.Errorf("备份 zz-user-overrides.conf: %w", err)
			}
		} else if err := os.WriteFile(overridesBak, nil, 0644); err != nil {
			m.restoreBackup()
			return fmt.Errorf("标记 zz-user-overrides.conf 更新前状态: %w", err)
		}
		// 本运行已创建 bak：restoreBackup 自此可消费。
		m.overridesBakCreated = true
		// B-新2：按行去重合并既有 overrides——此前整体覆写会在「两次手改
		// setup 跨两次成功更新」时丢弃前次迁移的自定义行（且成功路径随后
		// 删除 .bak，不可恢复）；失败路径却还原前次内容（保全语义不对称，
		// crsinstall_test.go:248 的测试证明设计意图是保全）。合并规则：
		// 既有有效行 ∪ 本次 diff，行内容（含注释）做键，保持出现顺序，
		// header 仅一份。重复 SecRule id 风险由行级去重
		// 消除——同一行不会写入两次。
		pendingOverrides = mergeOverridesLines(filepath.Join(m.liveDir(), "zz-user-overrides.conf"), header, diff)
		WriteCRSUpdateLog("INFO", string(CRSStatusInstalling),
			fmt.Sprintf("已迁移 %d 行用户自定义配置到 zz-user-overrides.conf", len(diff)))
	}

	// 崩溃窗口（文档级）：RemoveAll(rules) 与 moveTree 完成之间的进程崩溃会留下
	// 缺失的 rules/ 与孤立的 rules.bak——刚安装的版本丢失，且 restoreBackup 只在
	// 进程内错误路径执行、不会恢复。属小概率事件且可自愈：下次启动 SeedCRSRules
	// 从 dist/快照重新播种（见 crsseed.go），影响面仅限 CRS 版本回退。
	// 陈旧 .bak 不主动清理：它是崩溃现场的唯一恢复素材（见本函数前段），成功安装
	// 时由 copyDirTransactional 的事务替换覆盖、成功路径末尾 os.RemoveAll(rulesBak)
	// 删除；跨运行残留按崩溃现场保全。
	// RemoveAll→overrides 写入的树交换段抽为 swapCRSTreeFromStaging，
	// 在 wafFileMu 互斥段内执行（lbbak 导入 untarGzTo 交换同一棵树，交错产
	// 混合/残缺 rules 树）；网络下载与 Caddy 重载在锁外。
	// 版本行随交换段（锁内）落库，prevTag 由交换段锁内读出返回。
	prevTag, err := m.swapCRSTreeFromStaging(staging, setupPath, pendingOverrides, tag)
	if err != nil {
		return err
	}

	// 交换段已把 DB 版本行与 live VERSION 落为新
	// tag——此后观察到取消必须走 rollbackAfterReloadFailure 同代回滚（树+标记+
	// 版本行，同一 wafFileMu 临界区），不得交由 run() 的 cancel(..., true) 只
	// 还原文件树：任何「树回滚而版本行/标记不回滚」的组合都会留下
	// 「旧树+新版本号」，被下轮 tag==current「已是最新」短路永久固化
	//（ReconcileCRSState 因 liveV==dbV 也不修复）。
	// 角色判定改三态门——DB 读失败（角色不可判定）同样
	// 回滚（见 observeCancelAfterSwap）；已知从节点（真降级）保持
	// 语义不回滚——树/行/标记同为新 tag 是一致态，交集群同步收敛。
	if cerr := m.observeCancelAfterSwap(parent, prevTag, string(CRSStatusInstalling)); cerr != nil {
		return cerr
	}

	// Reload BEFORE deleting backups: if reload fails, restoreBackup can still roll back.
	// 版本行必须先于 reloader 更新（已随上方交换段落库）——
	// crsPoolFingerprint 以版本行为池键输入，先重载则指纹仍为旧值、coraza 池
	// 命中旧实例，磁盘新规则要等下一次生成才生效（无限期静默陈旧）。
	// 先写后失败的版本行回滚——不回滚则
	// currentCRSVersion() 已为新 tag，下轮自动更新短路「已是最新」、失败被掩盖
	// 且永不重试（直到重启）。旧 tag 由交换段锁内读出（prevTag）。
	WriteCRSUpdateLog("INFO", string(CRSStatusReloading), "应用新规则并重载 Caddy")
	if m.reloader != nil {
		err := m.reloader()
		recordSystemReloadAudit("crs_update", err)
		if err != nil {
			WriteCRSUpdateLog("ERROR", string(CRSStatusReloading), fmt.Sprintf("重载失败: %v", err))
			// 回滚必须同代（树 + live VERSION + DB 版本行）——旧实现
			// restoreBackup 取锁后立即释放，标记/版本行在锁外写（持锁读者可见
			// 「旧树+新标记」；并发导入可在窗口内被本轮标记覆盖）。
			m.rollbackAfterReloadFailure(prevTag)
			return &crsReloadError{cause: fmt.Errorf("重载 Caddy: %w", err)}
		}
	}

	// 取消发生在重载期间（reloader 无 ctx 入参，只能在其返回后
	// 观察）——与重载失败同编舞同代回滚。必须在下方备份清理之前：清理后
	// rollback 无本运行基线可还原。demote/角色不可判定门径同上一观察点
	//（见 observeCancelAfterSwap）。
	if cerr := m.observeCancelAfterSwap(parent, prevTag, string(CRSStatusReloading)); cerr != nil {
		return cerr
	}

	os.RemoveAll(rulesBak)
	// rules.old 只可能来自上一次失败更新的崩溃窗口（restoreRulesBackup
	// 内 moveTree 序列中断），成功路径顺带清理——否则它只能等下一次失败的更新
	// 才被回收，长期占用一整棵规则树的磁盘。restoreRulesBackup 开头本就会先清
	// rules.old，此处删除不影响任何恢复路径。
	os.RemoveAll(crsTransientPath(m.liveDir(), "rules.old"))
	os.Remove(setupBak)
	// 崩溃窗口说明：stock 写入（上方）与本清理之间的进程崩溃会残留陈旧
	// stock.bak；它与 setup.bak 语义一致——下次运行在备份点用新拷贝覆盖，
	// 且 自此非本运行创建的.bak 一律不被 restoreBackup 消费（标记守卫）。
	os.Remove(stockBak)
	os.Remove(crsTransientPath(m.liveDir(), "zz-user-overrides.conf.bak"))
	// 标记磁盘实际版本 + 持久化到数据卷快照：未挂载 /app/waf 的部署在容器
	// 重建后依赖该快照恢复用户更新的版本（见 ReconcileCRSState）。
	// VERSION 标记已在 swapCRSTreeFromStaging（wafFileMu 内）与树/DB
	// 版本行同代落盘，此处不再锁外重写。
	if err := persistCRSSnapshotFrom(m.liveDir(), crsSnapshotDir, tag); err != nil {
		Logf("error", "crs update: failed to persist snapshot to %s: %v", crsSnapshotDir, err)
		// 普通快照 IO 失败保留既有「更新成功但降级可见」语义；代际
		// 不一致则必须让任务失败，不能向调用方伪装成同代成功。
		WriteCRSUpdateLog("ERROR", string(CRSStatusFailed), fmt.Sprintf("规则快照持久化失败: %v（容器重建后将回退，请检查数据卷磁盘空间）", err))
		RecordAuditLog("system", "写入失败", "CRS规则库", FormatAuditDetail(fmt.Sprintf("版本：%s 规则快照持久化失败: %v（容器重建后将回退到镜像捆绑版本）", tag, err), AuditResultPart("failed")), "")
		if errors.Is(err, errCRSSnapshotVersionMismatch) {
			return err
		}
	}
	return nil
}

// swapCRSTreeFromStaging 树交换段：staging 内新规则树替换 live
// rules/、落盘新 setup/stock 基线与迁移 overrides。全程持 wafFileMu——与
// lbbak 导入（untarGzTo 交换同一棵树）、威胁库/ip2region 文件相位串行，杜绝
// 混合/残缺 rules 树经 waf_files 节传播。失败路径的 restoreBackup（同为树
// 变更）也在锁内；网络下载与 Caddy 重载不进锁——锁内取 CaddyOpLock 虽与全局锁序
// （导入=排空→wafFileMu→CaddyOpLock）同向、不构成 AB-BA，但重载耗时会让导入
// 在该锁上无谓排队；反向嵌套（持 CaddyOpLock 再取 wafFileMu）才是 AB-BA，禁止。
// security_crs_version 版本行写入收进本段——此前
// 在锁外（downloadAndInstall 尾段），写相位中段导出侧（BuildWafFileBundle 读
// 相位持同一锁）可打出「文件新/行旧」偏斜 bundle。单行 UPDATE 毫秒级，与段内
// 树交换 IO 同量级，不新增锁内长阻塞。prevTag 锁内读出返回，供重载失败回滚
// （版本行先于 reloader 写入的语义不变）。
func (m *CRSUpdateManager) swapCRSTreeFromStaging(staging, setupPath string, pendingOverrides []byte, tag string) (prevTag string, err error) {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	// 窗口标记：RemoveAll→moveTree→setup 落盘期间 rules 树可能整体缺失或部分
	// 拷贝；渲染侧不持 wafFileMu（锁序不可反转），据此在生成期拒绝发布降级/
	// 弱化配置（见 errCRSTreeSwapInFlight）。
	leaveSwapWindow := enterCRSTreeSwapWindow()
	defer leaveSwapWindow()
	rulesPath := filepath.Join(m.liveDir(), "rules")
	if err := os.RemoveAll(rulesPath); err != nil {
		m.restoreBackupInLock()
		return "", fmt.Errorf("清理现有 rules: %w", err)
	}
	if err := moveTree(filepath.Join(staging, "rules"), rulesPath); err != nil {
		m.restoreBackupInLock()
		return "", fmt.Errorf("安装新 rules: %w", err)
	}
	newSetup := filepath.Join(staging, "crs-setup.conf.example")
	// 写序必须 stock → setup：两步各自原子，崩溃只会落在两者之间。
	// 旧序（setup→stock）在中间崩溃留下「新 setup + 旧 stock」，下次迁移以旧
	// stock 为基线、对新 setup 求差 → 上游默认行被当作自定义行写进
	// zz-user-overrides.conf，重复 SecRule id 使 coraza 拒绝配置再生成，此后
	// 每轮更新都被拒并回滚（恢复的也是同组合，无法自愈）。
	// 新序残留「新 stock + 旧 setup」：以新 stock 为基线求差只保留真正的用户
	// 自定义行，下一次更新自动收敛。
	stockPath := filepath.Join(m.liveDir(), "crs-setup.stock.conf")
	if err := copyFile(newSetup, stockPath); err != nil {
		m.restoreBackupInLock()
		return "", fmt.Errorf("写入 crs-setup.stock.conf 基线: %w", err)
	}
	if err := copyFile(newSetup, setupPath); err != nil {
		m.restoreBackupInLock()
		return "", fmt.Errorf("写入 crs-setup.conf: %w", err)
	}
	// 写后自检：两文件同源，差集必须为空（stock-first 写序的一致性钉子；
	// 任何非空差都意味着下一步迁移会把它当自定义行）。
	if diff := extractSetupDiff(readConfLines(stockPath), readConfLines(setupPath)); len(diff) > 0 {
		m.restoreBackupInLock()
		return "", fmt.Errorf("crs-setup.conf 与基线不一致（差 %d 行），已回滚本次更新", len(diff))
	}
	// 新-2：overrides 迁移写入推迟到此处（rules 与新 setup 均已落盘）——
	// 此点之后的崩溃留下「新 stock setup（不含自定义行）+ 旧 overrides」，
	// 不再有「新 overrides + 旧 setup」重复 SecRule id 的窗口。残余风险
	//仅当用户曾修改过 stock 规则（修改行 id 跨 CRS v4
	// 版本稳定）且新版本仍含同 id 时，旧 overrides 与新 stock 组合才会出现
	// 重复 SecRule id 致配置再生成失败——条件触发而非确定；用户未改过 stock
	// 规则时 coraza 正常加载，仅丢失自上次更新以来新增的自定义行，下次成功
	// 更新自愈。
	if pendingOverrides != nil {
		if err := os.WriteFile(filepath.Join(m.liveDir(), "zz-user-overrides.conf"), pendingOverrides, 0644); err != nil {
			m.restoreBackupInLock()
			return "", fmt.Errorf("写入 zz-user-overrides.conf: %w", err)
		}
	}
	// 版本行与文件树同互斥区落库——导出读相位（持同一锁）不会
	// 读到「文件新/行旧」偏斜。语义保持：版本行先于 reloader 写入
	// （crsPoolFingerprint 以版本行为池键输入）；写失败仅 WARN，run() 成功
	// 路径稍后重写全量行（crsupdate.go），重载失败路径用 prevTag 回滚。
	// prevTag 必须真实可靠——展示口径 currentCRSVersion() 读失败
	// 回落 bundled，重载失败回滚会把 bundled 写成真实版本（版本溯源永久降级）。
	prevTag, prevErr := crsCurrentVersionForRun()
	if prevErr != nil {
		m.restoreBackupInLock()
		return "", fmt.Errorf("读取更新前 CRS 版本失败（未写版本标记/版本行，规则树已回滚）: %w", prevErr)
	}
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET version=?, updated_at=datetime('now') WHERE id=1",
		tag,
	); err != nil {
		// 版本行写入失败不得仅 WARN 后继续——树已换而
		// 版本行仍旧会让 crsPoolFingerprint 命中旧池（新规则静默不生效），且
		// 后续任务内重试会用已变的树覆盖原始备份基线。此刻原备份仍可用：回滚
		// 规则树并返回明确错误，downloadAndInstall 不会调用 reloader。
		m.restoreBackupInLock()
		return prevTag, fmt.Errorf("写入 CRS 版本行失败（已回滚规则树）: %w", err)
	}
	// VERSION 标记与规则树/DB 版本行同锁同代——读者（BuildWafFileRef）
	// 不会观察到「树新/标记旧」或反向的混合代。
	if err := writeCRSVersionMarker(m.liveDir(), tag); err != nil {
		if !m.restoreBackupInLock() {
			return prevTag, fmt.Errorf("写入 CRS VERSION 标记失败且规则树回滚失败: %w", err)
		}
		if _, rbErr := db.DB.Exec("UPDATE security_crs_version SET version=?, updated_at=datetime('now') WHERE id=1", prevTag); rbErr != nil {
			return prevTag, fmt.Errorf("写入 CRS VERSION 标记失败；规则树已回滚但版本行回滚失败: %v（原错误: %w）", rbErr, err)
		}
		return prevTag, fmt.Errorf("写入 CRS VERSION 标记失败（规则树与版本行已回滚）: %w", err)
	}
	return prevTag, nil
}

// persistCRSSnapshotFrom copies the live rules tree, setup files and version
// marker into the data-volume snapshot dir so a rebuilt container (or a
// wiped bind mount) can restore the user-updated version at startup.
var errCRSSnapshotVersionMismatch = errors.New("CRS live 版本与待持久化版本不一致")

func persistCRSSnapshotFrom(liveDir, snapshotDir, version string) error {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	return persistCRSSnapshotFromInLock(liveDir, snapshotDir, version)
}

// persistCRSSnapshotFromInLock 是调用方已持 wafFileMu 的快照持久化实现。
func persistCRSSnapshotFromInLock(liveDir, snapshotDir, version string) error {
	// 树交换段释放锁到本段重新取锁之间，lbbak 导入 /
	// cluster apply 可换掉整棵树并写入自己的 VERSION——此时快照会把并发
	// 导入的树标记成本次更新的 tag（假快照）。以 live VERSION 做代际校验：
	// 与期望版本不一致则保留旧快照并告警，不产出错误标签。
	if marker, err := os.ReadFile(filepath.Join(liveDir, crsVersionFile)); err != nil {
		return fmt.Errorf("读取 live 版本标记: %w", err)
	} else if strings.TrimSpace(string(marker)) != version {
		return fmt.Errorf("%w: live VERSION=%q，期望 %q，保留旧快照", errCRSSnapshotVersionMismatch, strings.TrimSpace(string(marker)), version)
	}

	// 先在快照旁的临时目录构建完整快照，成功后才替换旧快照——
	// 旧实现先 RemoveAll(snapshotDir) 再逐项 copy，磁盘满/IO 中断会留下
	// 「旧快照已删 + 新快照半树」，下次启动按退化快照回退 dist（用户更新版本丢失）。
	tmpDir := snapshotDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("清理快照暂存: %w", err)
	}
	cleanupTmp := func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			Logf("error", "crs update: failed to clean snapshot staging %s: %v", tmpDir, err)
		}
	}
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("创建快照暂存: %w", err)
	}
	if err := copyDir(filepath.Join(liveDir, "rules"), filepath.Join(tmpDir, "rules")); err != nil {
		cleanupTmp()
		return fmt.Errorf("快照 rules: %w", err)
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf", "zz-user-overrides.conf"} {
		if _, err := os.Stat(filepath.Join(liveDir, name)); err == nil {
			if err := copyFile(filepath.Join(liveDir, name), filepath.Join(tmpDir, name)); err != nil {
				cleanupTmp()
				return fmt.Errorf("快照 %s: %w", name, err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(tmpDir, crsVersionFile), []byte(version+"\n"), 0644); err != nil {
		cleanupTmp()
		return fmt.Errorf("快照版本标记: %w", err)
	}
	// 两阶段命名替换（目录无法原地原子覆盖）：旧快照先改名到 .old，新树
	// rename 到位后再删 .old；任一步失败都把旧快照复位。旧实现
	// RemoveAll(snapshotDir)+Rename 在两步之间旧快照已不存在，rename 失败
	// 时再 cleanupTmp() 会把唯一完整的新树也删掉——两份快照同时消失，
	// 容器重建即回退镜像捆绑版本（快照缺席不自愈，只有退化快照会自愈）。
	oldDir := snapshotDir + ".old"
	if err := os.RemoveAll(oldDir); err != nil {
		cleanupTmp()
		return fmt.Errorf("清理旧快照残骸: %w", err)
	}
	prevExisted := false
	if _, err := os.Stat(snapshotDir); err == nil {
		if err := osRename(snapshotDir, oldDir); err != nil {
			// 旧快照原封未动：清理暂存即可（保留 tmp 会与「旧快照仍有效」
			// 的现场混淆，且下一次调用入口本就会清 tmp）。
			cleanupTmp()
			return fmt.Errorf("暂存旧快照: %w", err)
		}
		prevExisted = true
	}
	if err := osRename(tmpDir, snapshotDir); err != nil {
		// 新树到位失败：旧快照复位（失败时保留 .old 与完整 tmp 供人工/
		// 下次启动识别，绝不主动删除任何一份）。
		if prevExisted {
			if rbErr := osRename(oldDir, snapshotDir); rbErr != nil {
				Logf("error", "crs update: failed to restore previous snapshot %s from %s: %v（两份快照均保留在磁盘）", snapshotDir, oldDir, rbErr)
			}
		}
		return fmt.Errorf("替换快照: %w", err)
	}
	if err := os.RemoveAll(oldDir); err != nil {
		Logf("warn", "crs update: failed to remove replaced snapshot %s: %v（新快照已生效，残留下次覆盖）", oldDir, err)
	}
	return nil
}

// observeCancelAfterSwap 树交换段之后的取消观察点：
// 返回 nil=未取消；非 nil=已取消（调用方直接返回该错误）。
//
// 角色判定用三态 updateRunRole（taskrun.go），取代已退役的二态角色复核
// （updateRunStillMaster）——后者把 DB 读失败并入「非主节点」而跳过回滚，随后
// run() 的 cancel(..., true) 走 restoreBackup 只还文件树、不还 VERSION 标记与
// DB 版本行，留下「旧树+新版本行」被下轮 tag==current「已是最新」短路永久
// 固化。门径：
//   - !known（角色不可判定，DB 读失败）：按主节点口径执行同代回滚——主节点
//     避免永久固化；真从节点多回滚一次由集群同步自愈，安全方向一致。
//   - known && isMaster（手动取消）：同代回滚（不变）。
//     known &&!isMaster（真降级）：不回滚——树/行/标记同为
//     新 tag 是一致态，且 run() 的 demote 分支（skipped 终态）不做 restore，
//     交集群同步收敛。
func (m *CRSUpdateManager) observeCancelAfterSwap(parent context.Context, prevTag, stage string) error {
	cerr := parent.Err()
	if cerr == nil {
		return nil
	}
	isMaster, known := updateRunRole()
	switch {
	case !known:
		WriteCRSUpdateLog("WARN", stage, "取消时节点角色不可判定（DB 读失败），按主节点口径执行同代回滚（防「旧树+新版本行」固化）")
		m.rollbackAfterReloadFailure(prevTag)
	case isMaster:
		m.rollbackAfterReloadFailure(prevTag)
	default:
		WriteCRSUpdateLog("INFO", stage, "节点已降级为从节点，中止更新且不回滚（树/版本行/标记同为新版本，交集群同步收敛）")
	}
	return cerr
}

// rollbackAfterReloadFailure 重载失败回滚：树还原、
// live VERSION 标记回写与 DB 版本行回滚在同一 wafFileMu 临界区内完成——旧
// 实现 restoreBackup() 取锁后立即释放，标记/版本行在锁外写：持锁读者
// （BuildWafFileRef/Bundle 读相位）可导出「旧树 + 新标记/新版本行」，并发的
// lbbak 导入可在释放窗口换树后被本轮回滚标记覆盖，形成跨代污染。prevTag 为空
// （锁内读版本失败）时显式 ERROR 留痕并跳过标记回写（writeCRSVersionMarker 对
// 空版本是静默 no-op，不得让「未回写」不可见）。
func (m *CRSUpdateManager) rollbackAfterReloadFailure(prevTag string) {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	if !m.restoreBackupInLock() {
		// 规则树未完整还原（退化备份/IO 失败）——live 仍是本次安装的
		// 新树，此时回写 prevTag 会把「新树 + 旧版本」写进标记与版本行（版本行是
		// crsPoolFingerprint 的池键，可能命中旧池）。保留更新后的版本并显式留痕，
		// 由下次成功更新/启动对账收敛。
		WriteCRSUpdateLog("ERROR", string(CRSStatusReloading),
			"回滚未能完整还原规则树：VERSION 标记与版本行保持更新后的值（避免新树+旧版本跨代），等待下次成功更新或启动对账校正")
		return
	}
	if prevTag == "" {
		WriteCRSUpdateLog("ERROR", string(CRSStatusReloading),
			"回滚时无法确定更新前的 CRS 版本（VERSION 标记/版本行保持现状，重启后 ReconcileCRSState 校正）")
		return
	}
	writeCRSVersionMarker(m.liveDir(), prevTag)
	// 版本行回滚到旧值，恢复下轮重试能力；失败留痕并依赖启动对账自愈。
	if _, rbErr := db.DB.Exec(
		"UPDATE security_crs_version SET version=?, updated_at=datetime('now') WHERE id=1",
		prevTag,
	); rbErr != nil {
		WriteCRSUpdateLog("ERROR", string(CRSStatusReloading), fmt.Sprintf("版本行回滚失败（重启后 ReconcileCRSState 自愈）: %v", rbErr))
	}
}

// restoreBackup puts rules.bak and crs-setup.conf.bak back in place and undoes
// the current run's zz-user-overrides.conf write: with content it restores the
// pre-update file, with the empty marker it removes the freshly created file,
// so the restored config equals the pre-update state. Without the
// .bak the overrides were not touched by this run and stay as-is. The stock
// baseline is restored alongside: leaving it at the new version after
// a rollback would misalign the next migration's diff baseline and silently
// revert upstream default changes as "customizations".
func (m *CRSUpdateManager) restoreBackup() {
	// 失败/回滚路径的还原同为树变更（restoreRulesBackup
	// moveTree live rules），必须在 wafFileMu 内执行——持锁读者
	// BuildWafFileBundle/BuildWafFileRef 否则可导出缺失/混合 rules 树并经
	// waf_files 节扩散到从节点。swapCRSTreeFromStaging 已持锁，其内部调用
	// restoreBackupInLock（不得在此重入）。
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	m.restoreBackupInLock()
}

// restoreBackupInLock 是 restoreBackup 的锁内实现（调用方须持 wafFileMu）。
// 返回「规则树是否已完整还原到更新前状态」：调用方（重载失败
// 回滚）据此决定是否回写 VERSION 标记与 DB 版本行——还原失败时回写会制造
// 「live 新树 + 旧版本」跨代态（版本行是池键输入）。
func (m *CRSUpdateManager) restoreBackupInLock() bool {
	rulesPath := filepath.Join(m.liveDir(), "rules")
	rulesBak := crsTransientPath(m.liveDir(), "rules.bak")
	// 辅助文件的恢复结果与规则树同权：本运行创建过的每类备份只要没成功还原，
	// 聚合结果就是 false。只核对规则树会让 setup/stock/overrides 的恢复失败
	// 被「树已还原」掩盖——回滚方随即把 prevTag 写回 VERSION 标记与版本行，
	// 留下「旧 rules + 新 setup/stock/overrides + 旧版本号」混合代：下一次更新
	// 以新 stock 为基线求差，用户自定义行被误迁移、上游默认行被当成自定义。
	auxRestored := true
	// 契约：true 仅当「live 规则树已完整还原到更新前状态」——无本运行备份可
	// 消费（首装/带外清空旧树后直达交换）或备份不可读（带外清理）时，live
	// 仍是新树，必须上报 false：回滚方据此跳过 VERSION 标记/DB 版本行回写，
	// 避免「新树+旧版本」跨代态（版本行是 crsPoolFingerprint 池键输入）。
	treeRestored := false
	// 只消费本运行创建的 rules.bak——跨运行崩溃残留的陈旧备份不得
	// 在本运行早期失败（尚未到备份点）时被还原进 live（崩溃现场保全素材，
	// 且可能把 live 树回滚到与 DB 版本行跨代分叉的状态）。
	if m.rulesBakCreated {
		if _, err := os.Stat(rulesBak); err == nil {
			treeRestored = restoreRulesBackup(rulesPath, rulesBak)
		}
	}
	setupPath := filepath.Join(m.liveDir(), "crs-setup.conf")
	setupBak := crsTransientPath(m.liveDir(), "crs-setup.conf.bak")
	// setup.bak 缺失不得早退——stock.bak/overrides.bak
	// 的还原独立于 setup,缺失只跳过本段(此前 return 跳过了后续全部还原)。
	// 同上——只消费本运行创建的 setup.bak。
	if m.setupBakCreated {
		if _, err := os.Stat(setupBak); err == nil {
			if err := copyFile(setupBak, setupPath); err != nil {
				Logf("error", "crs update: failed to restore crs-setup.conf backup: %v", err)
				auxRestored = false
			} else {
				os.Remove(setupBak)
			}
		} else {
			// 本运行创建过的备份已不在（带外清除/搬移）：setup 未回到更新前
			// 状态，不得按「无需还原」处理。
			auxRestored = false
		}
	}
	stockPath := filepath.Join(m.liveDir(), "crs-setup.stock.conf")
	stockBak := crsTransientPath(m.liveDir(), "crs-setup.stock.conf.bak")
	// stock 段失败不得 return——
	// overrides 还原独立于 stock,失败只记日志继续(否则旧 setup+新 overrides
	// 双重应用,restore 后 reload 再失败)。
	// 同上——只消费本运行创建的 stock.bak。
	if m.stockBakCreated {
		if _, err := os.Stat(stockBak); err == nil {
			if err := copyFile(stockBak, stockPath); err != nil {
				Logf("error", "crs update: failed to restore crs-setup.stock.conf backup: %v", err)
				auxRestored = false
			} else {
				os.Remove(stockBak)
			}
		} else {
			// 同 setup 段：本运行备份已不在=未还原。
			auxRestored = false
		}
	}
	overridesPath := filepath.Join(m.liveDir(), "zz-user-overrides.conf")
	overridesBak := crsTransientPath(m.liveDir(), "zz-user-overrides.conf.bak")
	if !m.overridesBakCreated {
		// 非本运行创建的.bak 不得消费：跨运行保全副本在下次成功更新
		// 前始终可用，且不会把 overrides 还原到两版本之前。
		return treeRestored && auxRestored && crsRulesTreeIntact(rulesPath)
	}
	if _, err := os.Stat(overridesBak); err != nil {
		// 本运行已创建 overrides.bak 但备份消失：overrides 未回到更新前状态，
		// 同 setup/stock 段按未还原上报。
		auxRestored = false
	} else {
		// 仅还原成功才消费.bak：内容还原或空标记移除失败时保留备份，
		// 否则「旧 setup + 新 overrides」双重应用状态失去唯一恢复副本、不可自愈
		// （对照上方 setup 段：copyFile 失败记日志保留 bak, 后不再 return）。
		if data, err := os.ReadFile(overridesBak); err == nil && len(data) == 0 {
			if err := os.Remove(overridesPath); err != nil && !os.IsNotExist(err) {
				Logf("error", "crs update: failed to remove migrated zz-user-overrides.conf: %v", err)
				auxRestored = false
			}
		} else if err := copyFile(overridesBak, overridesPath); err != nil {
			Logf("error", "crs update: failed to restore zz-user-overrides.conf backup: %v", err)
			auxRestored = false
		}
		if auxRestored {
			os.Remove(overridesBak)
		}
	}
	return treeRestored && auxRestored && crsRulesTreeIntact(rulesPath)
}

// restoreRulesBackup moves rules.bak back into place without ever installing a
// tree weaker than what it replaces and without leaving the live path empty
// a degenerate backup — no.conf at all, or missing the probe file
// like a partial tree left by an interrupted copy — is
// rejected with a log and left in place for diagnosis; the live tree is first
// moved aside to rules.old and moved back if the restore move itself fails.
//
// 返回 true 表示 live rules 已是备份中的更新前规则树（调用方据此
// 决定是否回写版本标记/版本行）。
// 本函数搬移 live 规则树（live→rules.old→恢复）——必须进入树交换窗口，否则
// 与渲染并发生成会读到 missing/部分树（窗口在该函数栈内可能已由 swap 段置位，
// 嵌套计数保证旧标记不会被提前清除）。
func restoreRulesBackup(rulesPath, rulesBak string) bool {
	restored := false
	_ = withTreeSwapWindow(func() error {
		restored = restoreRulesBackupInWindow(rulesPath, rulesBak)
		return nil
	})
	return restored
}

func restoreRulesBackupInWindow(rulesPath, rulesBak string) bool {
	if !crsRulesTreeIntact(rulesBak) {
		Logf("warn", "crs update: rules backup %s is degenerate (no .conf files or missing %s), skipping restore (live rules left untouched)", rulesBak, crsRulesProbeFile)
		return false
	}
	// rules.old 属瞬态残树，落 crs.transient（live 目录不留.old）。
	rulesOld := crsTransientPath(filepath.Dir(rulesPath), "rules.old")
	if err := os.RemoveAll(rulesOld); err != nil {
		Logf("error", "crs update: failed to clear %s, restore aborted (live rules untouched): %v", rulesOld, err)
		return false
	}
	liveMoved := false
	if _, err := os.Stat(rulesPath); err == nil {
		if err := moveTree(rulesPath, rulesOld); err != nil {
			Logf("error", "crs update: failed to move live rules aside, restore aborted (live rules untouched): %v", err)
			return false
		}
		liveMoved = true
	}
	if err := moveTree(rulesBak, rulesPath); err != nil {
		Logf("error", "crs update: failed to restore rules backup: %v", err)
		if liveMoved {
			// 搬回前清掉失败搬移在 live 路径留下的残影：rules.old 持有完整
			// 原树，清空目标后整体搬回，live 不会混入残树文件也不为空。
			if rmErr := os.RemoveAll(rulesPath); rmErr != nil {
				Logf("error", "crs update: failed to clear partial restore at %s: %v", rulesPath, rmErr)
			}
			if rbErr := moveTree(rulesOld, rulesPath); rbErr != nil {
				Logf("error", "crs update: failed to move live rules back from %s: %v", rulesOld, rbErr)
			}
		}
		return false
	}
	if liveMoved {
		if err := os.RemoveAll(rulesOld); err != nil {
			Logf("error", "crs update: failed to remove old rules tree %s: %v", rulesOld, err)
		}
	}
	WriteCRSUpdateLog("INFO", string(CRSStatusInstalling), "已从备份恢复规则")
	return crsRulesTreeIntact(rulesPath)
}

// crsRulesProbeFile 是完整 CRS rules 树必然携带的探针文件（crsProbeFile 去掉
// rules/ 前缀，相对 rules 树根）。「≥1 个 .conf」只排除全空树，不排除拷贝
// 中途崩溃留下的部分残树——探针缺失即视为退化。
//
// 单探针判据的强度由写入相位保证，而非靠探针数量：
//   - copyDir/moveTree 回退把探针排在拷贝序最后（任何中断都缺探针）；
//   - 备份/替换/移动回退全部 tmp+rename 事务写（半树不落最终路径）；
//   - 打包/解包/哈希共用一个瞬态谓词。
//
// 因此「探针在、树却半份」只能来自带外污染（旧版本遗留残树/手工改盘），
// 启动 seed 与备份门在探针缺失时按退化处理（重播/拒绝恢复）。
const crsRulesProbeFile = "REQUEST-901-INITIALIZATION.conf"

// crsRulesTreeIntact reports whether rulesDir looks like a complete CRS rules
// tree: at least one .conf file AND the release-invariant probe file present
// and non-empty.
func crsRulesTreeIntact(rulesDir string) bool {
	if !treeContainsConfFile(rulesDir) {
		return false
	}
	info, err := os.Stat(filepath.Join(rulesDir, crsRulesProbeFile))
	return err == nil && !info.IsDir() && info.Size() > 0
}

// treeContainsConfFile reports whether dir holds at least one regular .conf
// file anywhere below it; a missing/unreadable dir reports false.
func treeContainsConfFile(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".conf") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// copyDirTransactional 在同级 .tmp 完整构建副本后，以 dst→.old→复位
// 的两阶段 rename 替换备份。任何失败都保住上一份完整备份；该路径不进入
// live 树交换窗口（调用方生成的是备份，不是正在渲染的 rules 树）。
func copyDirTransactional(src, dst string) error {
	tmp := dst + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	cleanupTmp := func() {
		if err := os.RemoveAll(tmp); err != nil {
			Logf("error", "crs update: failed to clean backup staging %s: %v", tmp, err)
		}
	}
	if err := copyDir(src, tmp); err != nil {
		cleanupTmp()
		return err
	}
	old := dst + ".old"
	previousExisted := false
	if _, err := os.Stat(dst); err == nil {
		if err := os.RemoveAll(old); err != nil {
			cleanupTmp()
			return err
		}
		if err := copyDirRename(dst, old); err != nil {
			cleanupTmp()
			return err
		}
		previousExisted = true
	} else if !errors.Is(err, os.ErrNotExist) {
		cleanupTmp()
		return err
	} else if _, oldErr := os.Stat(old); oldErr == nil {
		// 上次回滚未完成时 .old 是唯一旧备份，必须保留用于本次回滚。
		previousExisted = true
	} else if !errors.Is(oldErr, os.ErrNotExist) {
		cleanupTmp()
		return oldErr
	}
	if err := copyDirRename(tmp, dst); err != nil {
		if previousExisted {
			if restoreErr := copyDirRename(old, dst); restoreErr != nil {
				Logf("error", "crs update: failed to restore previous backup %s from %s: %v（旧备份保留在 .old）", dst, old, restoreErr)
			}
		}
		cleanupTmp()
		return err
	}
	if err := os.RemoveAll(old); err != nil {
		Logf("warn", "crs update: failed to remove replaced backup %s: %v（新备份已生效）", old, err)
	}
	return nil
}

// replaceDirFrom 用 src 的完整副本替换 dst 目录：先复制到 dst+".tmp"，
// 再把旧 dst rename 到 .old，最后把 tmp rename 到位并删除 .old。最终 rename
// 失败时旧树从 .old 复位，完整 tmp 保留供诊断；第一步失败则 dst 原样不动。
// 与 copyDirTransactional 的区别：后者用于「生成备份」，本函数用于「替换
// 现有目录」（恢复/播种路径），因此需要旧树回滚语义。
// 唯一调用面是 live rules 树（快照恢复/播种）——必须进入树交换窗口：旧树
// 与 tmp 两次 rename 之间 live 缺失，窗口内生成须失败而不是发布无安全链配置。
func replaceDirFrom(src, dst string) error {
	return withTreeSwapWindow(func() error { return replaceDirFromInWindow(src, dst) })
}

func replaceDirFromInWindow(src, dst string) error {
	tmp := dst + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	cleanupTmp := func() {
		if err := os.RemoveAll(tmp); err != nil {
			Logf("error", "crs: failed to clean staging tree %s: %v", tmp, err)
		}
	}
	if err := copyDir(src, tmp); err != nil {
		cleanupTmp()
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		cleanupTmp()
		return err
	}
	old := dst + ".old"
	previousExisted := false
	if _, err := os.Stat(dst); err == nil {
		// dst 完好时 .old 只是上次成功替换后的残骸，可以安全清理。
		if err := os.RemoveAll(old); err != nil {
			cleanupTmp()
			return err
		}
		if err := osRename(dst, old); err != nil {
			cleanupTmp()
			return err
		}
		previousExisted = true
	} else if !errors.Is(err, os.ErrNotExist) {
		cleanupTmp()
		return err
	} else if _, oldErr := os.Stat(old); oldErr == nil {
		// dst 缺失而 .old 存在 = 上次回滚未完成；它是唯一旧树，
		// 本次无论成功还是再次失败都必须以它恢复，而非当残骸删除。
		previousExisted = true
	} else if !errors.Is(oldErr, os.ErrNotExist) {
		cleanupTmp()
		return oldErr
	}
	if err := osRename(tmp, dst); err != nil {
		if previousExisted {
			if restoreErr := osRename(old, dst); restoreErr != nil {
				Logf("error", "crs: failed to restore previous tree %s from %s: %v（旧树与完整暂存树均保留在磁盘）", dst, old, restoreErr)
			}
		}
		return err
	}
	if err := os.RemoveAll(old); err != nil {
		Logf("warn", "crs: failed to remove replaced tree %s: %v（新树已生效，残留下次替换前清理）", old, err)
	}
	return nil
}

// osRename is a seam for tests: Docker overlayfs cannot rename a directory
// baked into an image lower layer (EXDEV), so the fallback path matters.
// 消费方：moveTree 的跨挂载点回退判定、快照两阶段命名替换（替换失败必须
// 走「旧快照复位 + 两份保留」分支，测试需要能注入 rename 失败）。
var osRename = os.Rename

// copyDirRename 是 copyDirTransactional 的测试缝；与 moveTree 的覆盖式
// 回退分离，避免全局 rename 失败钩子把事务化备份也打失败。
var copyDirRename = os.Rename

// moveTree relocates a directory tree, falling back to copy + remove when a
// plain rename is impossible (e.g. overlayfs image layers or bind mounts).
//
// 回退路径必须事务化：直写 dst 的中断（ENOSPC/EIO/强杀）会在 dst 留下半棵树，
// 而完整性门只看探针存在——探针若已落地，半棵树会被当作完整树（seed 不重播、
// 备份被当权威旧树）。复制到 dst 同父级暂存树后再 rename，失败只在 .tmp 留残
// （清理），dst 保持「不存在或上一代完整树」。
func moveTree(src, dst string) error {
	if err := osRename(src, dst); err == nil {
		return nil
	}
	tmp := dst + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := copyDir(src, tmp); err != nil {
		if rErr := os.RemoveAll(tmp); rErr != nil {
			Logf("error", "crs: failed to clean partial move staging %s: %v", tmp, rErr)
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		if rErr := os.RemoveAll(tmp); rErr != nil {
			Logf("error", "crs: failed to clean move staging %s: %v", tmp, rErr)
		}
		return err
	}
	if err := copyDirRename(tmp, dst); err != nil {
		if rErr := os.RemoveAll(tmp); rErr != nil {
			Logf("error", "crs: failed to clean move staging %s after rename failure: %v", tmp, rErr)
		}
		return err
	}
	return os.RemoveAll(src)
}

// copyFile 复制单个文件：单源原子落盘（tmp+fsync+父目录 fsync），
// 崩溃中拷贝只会留下临时文件，读者/Reload 永远看到完整旧文件或完整新文件，
// 不会读到截断半成品（xdb live 路径被截断会让下次 Reload 失败）。注意内部
// 使用 os.Rename 而非 osRename seam：moveTree 的 copyDir 回退依赖 copyFile
// 在「目录不可 rename」环境下仍可用。
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return writeFileAtomicSynced(dst, data, 0644)
}

// copyDir 逐文件复制（copyFile 单文件原子）。探针文件（crsRulesProbeFile）
// 恒最后复制：完整性门只以「探针存在」为判据，而 os.ReadDir 是文件名升序——
// 探针 REQUEST-901-* 在真实 CRS 树里排在头部，排序拷贝中断时它已落地，半树
// 会被判完整（seed 不重播、备份被当权威旧树）。把它挪到最后后，任何中途失败
// 都缺探针，门/自愈按退化处理。
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	probe := ""
	if info, statErr := os.Stat(filepath.Join(src, crsRulesProbeFile)); statErr == nil && !info.IsDir() {
		probe = crsRulesProbeFile
	}
	for _, entry := range entries {
		if entry.Name() == probe {
			continue // 探针延后到循环末尾
		}
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	if probe != "" {
		if err := copyFile(filepath.Join(src, probe), filepath.Join(dst, probe)); err != nil {
			return err
		}
	}
	return nil
}
