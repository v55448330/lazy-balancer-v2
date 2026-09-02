package services

import (
	"context"
	"fmt"
	"lazy-balancer-v2/internal/db"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// extractSetupDiff returns the lines present in live but not in stock — the
// user customizations carried forward across an update. Comparison trims
// whitespace, blank lines are skipped, and comments count because they
// toggle rules.
// mergeOverridesLines 生成合并后的 overrides 内容：既有 overrides 的有效行
// 在前（保留历史自定义），本次迁移 diff 追加在后，按行文本去重（同一行只写
// 一次，消除 R53 新-2 的重复 SecRule id 顾虑），header 仅保留新的一份。
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
			// R72 S-4：跳过旧迁移 header 注释行——B-N1 让注释参与合并后，此前
			// 每次成功迁移会累积 2 行旧 header（"由 CRS 更新自动迁移"/"生成时间"）。
			if strings.HasPrefix(trimmed, "# 由 CRS 更新自动迁移") || strings.HasPrefix(trimmed, "# 生成时间") {
				continue
			}
			// R71 B-N1：注释行与迁移 diff 同等保留——extractSetupDiff 把注释计为
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

// downloadAndInstall downloads, validates and swaps in the new rules. The
// live tree persists across rebuilds via the /app/waf bind mount, so no
// snapshot is taken. On failure the live tree is restored from backup by
// restoreBackup.
func (m *CRSUpdateManager) downloadAndInstall(tag string) error {
	// 每次运行重置：restoreBackup 仅消费本运行创建的 overrides 备份（R39 1.1）。
	m.overridesBakCreated = false
	m.setStage(CRSStatusDownloading, fmt.Sprintf("下载 %s", tag))
	staging := filepath.Join(m.crsDir, ".staging")
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("清理 staging 目录: %w", err)
	}
	if err := os.MkdirAll(staging, 0755); err != nil {
		return fmt.Errorf("创建 staging 目录: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(staging); err != nil {
			log.Printf("crs update: failed to clean staging dir: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tarball := filepath.Join(staging, "crs.tar.gz")
	if err := m.downloadTarballLogged(ctx, tag, tarball); err != nil {
		return fmt.Errorf("下载 CRS 发布包: %w", err)
	}
	if err := extractCRSTarball(tarball, staging); err != nil {
		return fmt.Errorf("解压 CRS 发布包: %w", err)
	}

	m.setStage(CRSStatusInstalling, "校验并安装规则")
	if err := validateCRSStaging(staging); err != nil {
		return fmt.Errorf("校验 CRS 发布包: %w", err)
	}
	// TOFU 完整性基线在格式验证成功之后记录（R33 F6）：验证前的坏工件（如代理
	// 返回的 200 垃圾）留下基线会让下次同 tag 好下载误报。记录失败不阻断安装。
	if ierr := recordDownloadIntegrity(crsTarballSourceURL(tag), tarball, "CRS规则库"); ierr != nil {
		log.Printf("crs update: failed to record download integrity: %v", ierr)
	}

	rulesPath := filepath.Join(m.crsDir, "rules")
	rulesBak := filepath.Join(m.crsDir, "rules.bak")
	os.RemoveAll(rulesBak)
	// 注意：zz-user-overrides.conf.bak 不再在此无条件清除（R39 1.1）。上一次运行
	// 可能因还原失败保全了 .bak（三-1：唯一恢复副本）；若本运行在创建新备份前
	// 失败，该副本是仅有的自愈素材，先删后建会使其永久丢失。restoreBackup 只
	// 消费本运行创建的 .bak（overridesBakCreated 标记），陈旧 .bak 永不消费，
	// R38 三-2 的「还原到两版本之前」随之闭合；迁移分支创建新备份时写入覆盖
	// 自然顶掉陈旧内容。
	if _, err := os.Stat(rulesPath); err == nil {
		// Copy-based backup: the live rules dir may be baked into an image
		// lower layer, where rename is impossible (EXDEV on overlayfs).
		// 事务化拷贝（R49 B-N2）：中途失败（ENOSPC/EIO）只留下 rules.bak.tmp
		// 并被清理，restoreBackup 永远不会消费到部分残树。
		if err := copyDirTransactional(rulesPath, rulesBak); err != nil {
			return fmt.Errorf("备份现有 rules: %w", err)
		}
	}
	setupPath := filepath.Join(m.crsDir, "crs-setup.conf")
	setupBak := setupPath + ".bak"
	if _, err := os.Stat(setupPath); err == nil {
		if err := copyFile(setupPath, setupBak); err != nil {
			m.restoreBackup()
			return fmt.Errorf("备份 crs-setup.conf: %w", err)
		}
	}
	// stock 基线同点备份（R54-N3）：回滚只恢复 rules/setup/overrides 会让
	// stock 基线停留在新版本，下次迁移的 diff 基线错位——两版之间上游改动过
	// 的默认行被误判为用户自定义迁入 overrides，上游默认值变更被静默回退。
	stockPath := filepath.Join(m.crsDir, "crs-setup.stock.conf")
	stockBak := stockPath + ".bak"
	if _, err := os.Stat(stockPath); err == nil {
		if err := copyFile(stockPath, stockBak); err != nil {
			m.restoreBackup()
			return fmt.Errorf("备份 crs-setup.stock.conf: %w", err)
		}
	}

	// Migrate user customizations out of the live setup before the new stock
	// setup replaces it: diff against the last-installed stock baseline (the
	// image copy on first migration) and carry the remainder into the
	// overrides file included after the stock setup.
	// 迁移分两段（R53 新-2）：此处只算 diff 并留底 .bak，实际写入推迟到 rules
	// 与新 setup 落盘成功之后——若在 rules 替换前写入，写入点与 RemoveAll(rules)
	// 之间的进程崩溃会留下「新 overrides + 旧 setup」双重应用同一批自定义行，
	// 重复 SecRule id 使 coraza 拒绝配置再生成。
	var pendingOverrides []byte
	baseline := readConfLines(filepath.Join(m.crsDir, "crs-setup.stock.conf"))
	if baseline == nil {
		baseline = readConfLines(filepath.Join(crsDistDir, "crs-setup.conf"))
	}
	if diff := extractSetupDiff(baseline, readConfLines(setupPath)); len(diff) > 0 {
		header := fmt.Sprintf("# 由 CRS 更新自动迁移的用户自定义配置\n# 生成时间: %s\n",
			time.Now().In(CurrentLocation()).Format(crsTimeLayout))
		overridesPath := filepath.Join(m.crsDir, "zz-user-overrides.conf")
		overridesBak := overridesPath + ".bak"
		// 迁移写入前先留底：已有 overrides 则备份内容，没有则用空 .bak 标记
		// 「更新前不存在」。restoreBackup 据此把 overrides 还原到更新前状态——
		// 否则恢复后的旧 setup（含自定义行）与 overrides（同一批行）重复应用，
		// coraza 拒绝重复 SecRule id 致 reload 失败、更新永久卡死（R37 S3）。
		if _, err := os.Stat(overridesPath); err == nil {
			if err := copyFile(overridesPath, overridesBak); err != nil {
				m.restoreBackup()
				return fmt.Errorf("备份 zz-user-overrides.conf: %w", err)
			}
		} else if err := os.WriteFile(overridesBak, nil, 0644); err != nil {
			m.restoreBackup()
			return fmt.Errorf("标记 zz-user-overrides.conf 更新前状态: %w", err)
		}
		// 本运行已创建 bak：restoreBackup 自此可消费（R39 1.1）。
		m.overridesBakCreated = true
		// R60 B-新2：按行去重合并既有 overrides——此前整体覆写会在「两次手改
		// setup 跨两次成功更新」时丢弃前次迁移的自定义行（且成功路径随后
		// 删除 .bak，不可恢复）；失败路径却还原前次内容（保全语义不对称，
		// crsinstall_test.go:248 的测试证明设计意图是保全）。合并规则：
		// 既有有效行 ∪ 本次 diff，行内容（含注释）做键，保持出现顺序，
		// header 仅一份。重复 SecRule id 风险（R53 新-2 关注点）由行级去重
		// 消除——同一行不会写入两次。
		pendingOverrides = mergeOverridesLines(filepath.Join(m.crsDir, "zz-user-overrides.conf"), header, diff)
		writeCRSUpdateLog("INFO", string(CRSStatusInstalling),
			fmt.Sprintf("已迁移 %d 行用户自定义配置到 zz-user-overrides.conf", len(diff)))
	}

	// 崩溃窗口（文档级）：RemoveAll(rules) 与 moveTree 完成之间的进程崩溃会留下
	// 缺失的 rules/ 与孤立的 rules.bak——刚安装的版本丢失，且 restoreBackup 只在
	// 进程内错误路径执行、不会恢复。属小概率事件且可自愈：下次启动 SeedCRSRules
	// 从 dist/快照重新播种（见 crsseed.go），影响面仅限 CRS 版本回退；孤立的
	// .bak 也会在下次安装的 RemoveAll(rulesBak) 中被清理。不改行为，仅说明。
	if err := os.RemoveAll(rulesPath); err != nil {
		m.restoreBackup()
		return fmt.Errorf("清理现有 rules: %w", err)
	}
	if err := moveTree(filepath.Join(staging, "rules"), rulesPath); err != nil {
		m.restoreBackup()
		return fmt.Errorf("安装新 rules: %w", err)
	}
	newSetup := filepath.Join(staging, "crs-setup.conf.example")
	if err := copyFile(newSetup, setupPath); err != nil {
		m.restoreBackup()
		return fmt.Errorf("写入 crs-setup.conf: %w", err)
	}
	if err := copyFile(newSetup, filepath.Join(m.crsDir, "crs-setup.stock.conf")); err != nil {
		m.restoreBackup()
		return fmt.Errorf("写入 crs-setup.stock.conf 基线: %w", err)
	}
	// R53 新-2：overrides 迁移写入推迟到此处（rules 与新 setup 均已落盘）——
	// 此点之后的崩溃留下「新 stock setup（不含自定义行）+ 旧 overrides」，
	// 不再有「新 overrides + 旧 setup」重复 SecRule id 的窗口。残余风险
	//（R54-N2，已接受）：仅当用户曾修改过 stock 规则（修改行 id 跨 CRS v4
	// 版本稳定）且新版本仍含同 id 时，旧 overrides 与新 stock 组合才会出现
	// 重复 SecRule id 致配置再生成失败——条件触发而非确定；用户未改过 stock
	// 规则时 coraza 正常加载，仅丢失自上次更新以来新增的自定义行，下次成功
	// 更新自愈。
	if pendingOverrides != nil {
		if err := os.WriteFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"), pendingOverrides, 0644); err != nil {
			m.restoreBackup()
			return fmt.Errorf("写入 zz-user-overrides.conf: %w", err)
		}
	}

	// Reload BEFORE deleting backups: if reload fails, restoreBackup can still roll back.
	// 审计 U1-F4：版本行必须先于 reloader 更新——crsPoolFingerprint 以版本行为池键
	// 输入，先重载则指纹仍为旧值、coraza 池命中旧实例，磁盘新规则要等下一次生成
	// 才生效（无限期静默陈旧）。
	if _, err := db.DB.Exec(
		"UPDATE security_crs_version SET version=?, updated_at=datetime('now') WHERE id=1",
		tag,
	); err != nil {
		writeCRSUpdateLog("WARN", string(CRSStatusReloading), fmt.Sprintf("提前写入版本行失败（稍后重写）: %v", err))
	}
	writeCRSUpdateLog("INFO", string(CRSStatusReloading), "应用新规则并重载 Caddy")
	if m.reloader != nil {
		if err := m.reloader(); err != nil {
			writeCRSUpdateLog("ERROR", string(CRSStatusReloading), fmt.Sprintf("重载失败: %v", err))
			m.restoreBackup()
			return fmt.Errorf("重载 Caddy: %w", err)
		}
	}

	os.RemoveAll(rulesBak)
	// R50 B-#4：rules.old 只可能来自上一次失败更新的崩溃窗口（restoreRulesBackup
	// 内 moveTree 序列中断），成功路径顺带清理——否则它只能等下一次失败的更新
	// 才被回收，长期占用一整棵规则树的磁盘。restoreRulesBackup 开头本就会先清
	// rules.old，此处删除不影响任何恢复路径。
	os.RemoveAll(rulesPath + ".old")
	os.Remove(setupBak)
	// 崩溃窗口说明：stock 写入（上方）与本清理之间的进程崩溃会残留陈旧
	// stock.bak；它与 setup.bak 语义一致——下次运行在备份点用新拷贝覆盖，
	// 只可能在「备份点之前失败」的极端路径被 restoreBackup 消费（R54-N3）。
	os.Remove(stockBak)
	os.Remove(filepath.Join(m.crsDir, "zz-user-overrides.conf.bak"))
	// 标记磁盘实际版本 + 持久化到数据卷快照：未挂载 /app/waf 的部署在容器
	// 重建后依赖该快照恢复用户更新的版本（见 ReconcileCRSState）。
	writeCRSVersionMarker(m.crsDir, tag)
	if err := persistCRSSnapshotFrom(m.crsDir, crsSnapshotDir, tag); err != nil {
		log.Printf("crs update: failed to persist snapshot to %s: %v", crsSnapshotDir, err)
		// R55-B-F2：快照持久化失败不否决本次更新（磁盘规则树已是新版本），但
		// 未挂载 /app/waf 的部署在容器重建后会回退到镜像/旧快照版本——仅进
		// 组件日志会让运维在重建前毫无察觉，写一条操作日志使降级状态可见
		//（重建后 ReconcileCRSState 的版本校正另有审计）。
		writeCRSUpdateLog("ERROR", string(CRSStatusFailed), fmt.Sprintf("规则快照持久化失败: %v（容器重建后将回退，请检查数据卷磁盘空间）", err))
		RecordAuditLog("system", "写入失败", "CRS规则库", FormatAuditDetail(fmt.Sprintf("版本：%s 规则快照持久化失败: %v（容器重建后将回退到镜像捆绑版本）", tag, err), AuditResultPart("failed")), "")
	}
	return nil
}

// persistCRSSnapshotFrom copies the live rules tree, setup files and version
// marker into the data-volume snapshot dir so a rebuilt container (or a
// wiped bind mount) can restore the user-updated version at startup.
func persistCRSSnapshotFrom(liveDir, snapshotDir, version string) error {
	if err := os.RemoveAll(snapshotDir); err != nil {
		return fmt.Errorf("清理旧快照: %w", err)
	}
	if err := copyDir(filepath.Join(liveDir, "rules"), filepath.Join(snapshotDir, "rules")); err != nil {
		return fmt.Errorf("快照 rules: %w", err)
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf", "zz-user-overrides.conf"} {
		if _, err := os.Stat(filepath.Join(liveDir, name)); err == nil {
			if err := copyFile(filepath.Join(liveDir, name), filepath.Join(snapshotDir, name)); err != nil {
				return fmt.Errorf("快照 %s: %w", name, err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(snapshotDir, crsVersionFile), []byte(version+"\n"), 0644); err != nil {
		return fmt.Errorf("快照版本标记: %w", err)
	}
	return nil
}

// restoreBackup puts rules.bak and crs-setup.conf.bak back in place and undoes
// the current run's zz-user-overrides.conf write: with content it restores the
// pre-update file, with the empty marker it removes the freshly created file,
// so the restored config equals the pre-update state (R37 S3). Without the
// .bak the overrides were not touched by this run and stay as-is. The stock
// baseline is restored alongside (R54-N3): leaving it at the new version after
// a rollback would misalign the next migration's diff baseline and silently
// revert upstream default changes as "customizations".
func (m *CRSUpdateManager) restoreBackup() {
	rulesPath := filepath.Join(m.crsDir, "rules")
	rulesBak := filepath.Join(m.crsDir, "rules.bak")
	if _, err := os.Stat(rulesBak); err == nil {
		restoreRulesBackup(rulesPath, rulesBak)
	}
	setupPath := filepath.Join(m.crsDir, "crs-setup.conf")
	setupBak := setupPath + ".bak"
	if _, err := os.Stat(setupBak); err != nil {
		return
	}
	if err := copyFile(setupBak, setupPath); err != nil {
		log.Printf("crs update: failed to restore crs-setup.conf backup: %v", err)
		return
	}
	os.Remove(setupBak)
	stockPath := filepath.Join(m.crsDir, "crs-setup.stock.conf")
	stockBak := stockPath + ".bak"
	if _, err := os.Stat(stockBak); err == nil {
		if err := copyFile(stockBak, stockPath); err != nil {
			log.Printf("crs update: failed to restore crs-setup.stock.conf backup: %v", err)
			return
		}
		os.Remove(stockBak)
	}
	overridesPath := filepath.Join(m.crsDir, "zz-user-overrides.conf")
	overridesBak := overridesPath + ".bak"
	if !m.overridesBakCreated {
		// 非本运行创建的 .bak 不得消费（R39 1.1）：跨运行保全副本在下次成功更新
		// 前始终可用，且不会把 overrides 还原到两版本之前（R38 三-2）。
		return
	}
	if _, err := os.Stat(overridesBak); err != nil {
		return
	}
	// 仅还原成功才消费 .bak（R38 三-1）：内容还原或空标记移除失败时保留备份，
	// 否则「旧 setup + 新 overrides」双重应用状态失去唯一恢复副本、不可自愈
	// （对照上方 setup 段：copyFile 失败即 return，setup.bak 保留）。
	if data, err := os.ReadFile(overridesBak); err == nil && len(data) == 0 {
		if err := os.Remove(overridesPath); err != nil && !os.IsNotExist(err) {
			log.Printf("crs update: failed to remove migrated zz-user-overrides.conf: %v", err)
			return
		}
	} else if err := copyFile(overridesBak, overridesPath); err != nil {
		log.Printf("crs update: failed to restore zz-user-overrides.conf backup: %v", err)
		return
	}
	os.Remove(overridesBak)
}

// restoreRulesBackup moves rules.bak back into place without ever installing a
// tree weaker than what it replaces and without leaving the live path empty
// (R49 B-N2): a degenerate backup — no .conf at all, or missing the probe file
// like a partial tree left by an interrupted pre-R49 copy (R50 B-#3) — is
// rejected with a log and left in place for diagnosis; the live tree is first
// moved aside to rules.old and moved back if the restore move itself fails.
func restoreRulesBackup(rulesPath, rulesBak string) {
	if !crsRulesTreeIntact(rulesBak) {
		log.Printf("crs update: rules backup %s is degenerate (no .conf files or missing %s), skipping restore (live rules left untouched)", rulesBak, crsRulesProbeFile)
		return
	}
	rulesOld := rulesPath + ".old"
	if err := os.RemoveAll(rulesOld); err != nil {
		log.Printf("crs update: failed to clear %s, restore aborted (live rules untouched): %v", rulesOld, err)
		return
	}
	liveMoved := false
	if _, err := os.Stat(rulesPath); err == nil {
		if err := moveTree(rulesPath, rulesOld); err != nil {
			log.Printf("crs update: failed to move live rules aside, restore aborted (live rules untouched): %v", err)
			return
		}
		liveMoved = true
	}
	if err := moveTree(rulesBak, rulesPath); err != nil {
		log.Printf("crs update: failed to restore rules backup: %v", err)
		if liveMoved {
			// 搬回前清掉失败搬移在 live 路径留下的残影：rules.old 持有完整
			// 原树，清空目标后整体搬回，live 不会混入残树文件也不为空。
			if rmErr := os.RemoveAll(rulesPath); rmErr != nil {
				log.Printf("crs update: failed to clear partial restore at %s: %v", rulesPath, rmErr)
			}
			if rbErr := moveTree(rulesOld, rulesPath); rbErr != nil {
				log.Printf("crs update: failed to move live rules back from %s: %v", rulesOld, rbErr)
			}
		}
		return
	}
	if liveMoved {
		if err := os.RemoveAll(rulesOld); err != nil {
			log.Printf("crs update: failed to remove old rules tree %s: %v", rulesOld, err)
		}
	}
	writeCRSUpdateLog("INFO", string(CRSStatusInstalling), "已从备份恢复规则")
}

// crsRulesProbeFile 是完整 CRS rules 树必然携带的探针文件（crsProbeFile 去掉
// rules/ 前缀，相对 rules 树根）。「≥1 个 .conf」只排除全空树，不排除拷贝
// 中途崩溃留下的部分残树（pre-R49 裸 copyDir 备份、moveTree 直写回退）——
// 探针缺失即视为退化（R50 B-#3/#5）。
const crsRulesProbeFile = "REQUEST-901-INITIALIZATION.conf"

// crsRulesTreeIntact reports whether rulesDir looks like a complete CRS rules
// tree: at least one .conf file AND the release-invariant probe file present.
func crsRulesTreeIntact(rulesDir string) bool {
	if !treeContainsConfFile(rulesDir) {
		return false
	}
	info, err := os.Stat(filepath.Join(rulesDir, crsRulesProbeFile))
	return err == nil && !info.IsDir()
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

// copyDirTransactional copies src to dst via a sibling temp dir (R49 B-N2):
// a partial copy stays at dst+".tmp" and is removed on failure, so consumers
// of dst either see the previous complete tree or no tree at all — never a
// half-copied one. The final rename uses os.Rename directly (same rationale
// as copyFile): tmp is created in the same parent as dst, so it always lives
// on the same filesystem even on overlayfs.
func copyDirTransactional(src, dst string) error {
	tmp := dst + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := copyDir(src, tmp); err != nil {
		if rErr := os.RemoveAll(tmp); rErr != nil {
			log.Printf("crs update: failed to clean partial backup staging %s: %v", tmp, rErr)
		}
		return err
	}
	// rename 失败同样清理暂存树（与 copyFile 对称，R50 B-#2）：否则完整拷贝
	// 残留在 rules.bak.tmp，任何按 *.tmp 扫描的路径都会误消费。
	if err := os.Rename(tmp, dst); err != nil {
		if rErr := os.RemoveAll(tmp); rErr != nil {
			log.Printf("crs update: failed to clean backup staging %s after rename failure: %v", tmp, rErr)
		}
		return err
	}
	return nil
}

// osRename is a seam for tests: Docker overlayfs cannot rename a directory
// baked into an image lower layer (EXDEV), so the fallback path matters.
var osRename = os.Rename

// moveTree relocates a directory tree, falling back to copy + remove when a
// plain rename is impossible (e.g. overlayfs image layers or bind mounts).
func moveTree(src, dst string) error {
	if err := osRename(src, dst); err == nil {
		return nil
	}
	if err := copyDir(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

// copyFile 复制单个文件：先写 dst+".tmp" 再原子重命名（镜像 copyAuditLogTo，
// R45 F1-B），崩溃中拷贝只会留下临时文件，读者/Reload 永远看到完整旧文件或
// 完整新文件，不会读到截断半成品（xdb live 路径被截断会让下次 Reload 失败）。
// 重命名失败时清理临时文件。注意内部使用 os.Rename 而非 osRename seam：
// moveTree 的 copyDir 回退依赖 copyFile 在「目录不可 rename」环境下仍可用。
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	for _, entry := range entries {
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
	return nil
}
