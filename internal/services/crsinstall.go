package services

import (
	"context"
	"fmt"
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
	if err := m.downloadTarball(ctx, tag, tarball); err != nil {
		return fmt.Errorf("下载 CRS 发布包: %w", err)
	}
	if err := extractCRSTarball(tarball, staging); err != nil {
		return fmt.Errorf("解压 CRS 发布包: %w", err)
	}

	m.setStage(CRSStatusInstalling, "校验并安装规则")
	if err := validateCRSStaging(staging); err != nil {
		return fmt.Errorf("校验 CRS 发布包: %w", err)
	}

	rulesPath := filepath.Join(m.crsDir, "rules")
	rulesBak := filepath.Join(m.crsDir, "rules.bak")
	os.RemoveAll(rulesBak)
	if _, err := os.Stat(rulesPath); err == nil {
		// Copy-based backup: the live rules dir may be baked into an image
		// lower layer, where rename is impossible (EXDEV on overlayfs).
		if err := copyDir(rulesPath, rulesBak); err != nil {
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

	// Migrate user customizations out of the live setup before the new stock
	// setup replaces it: diff against the last-installed stock baseline (the
	// image copy on first migration) and carry the remainder into the
	// overrides file included after the stock setup.
	baseline := readConfLines(filepath.Join(m.crsDir, "crs-setup.stock.conf"))
	if baseline == nil {
		baseline = readConfLines(filepath.Join(crsDistDir, "crs-setup.conf"))
	}
	if diff := extractSetupDiff(baseline, readConfLines(setupPath)); len(diff) > 0 {
		header := fmt.Sprintf("# 由 CRS 更新自动迁移的用户自定义配置\n# 生成时间: %s\n",
			time.Now().In(CurrentLocation()).Format(crsTimeLayout))
		content := header + strings.Join(diff, "\n") + "\n"
		if err := os.WriteFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"), []byte(content), 0644); err != nil {
			m.restoreBackup()
			return fmt.Errorf("写入 zz-user-overrides.conf: %w", err)
		}
		writeCRSUpdateLog("INFO", string(CRSStatusInstalling),
			fmt.Sprintf("已迁移 %d 行用户自定义配置到 zz-user-overrides.conf", len(diff)))
	}

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

	// Reload BEFORE deleting backups: if reload fails, restoreBackup can still roll back.
	writeCRSUpdateLog("INFO", string(CRSStatusReloading), "应用新规则并重载 Caddy")
	if m.reloader != nil {
		if err := m.reloader(); err != nil {
			writeCRSUpdateLog("ERROR", string(CRSStatusReloading), fmt.Sprintf("重载失败: %v", err))
			m.restoreBackup()
			return fmt.Errorf("重载 Caddy: %w", err)
		}
	}

	os.RemoveAll(rulesBak)
	os.Remove(setupBak)
	return nil
}

// restoreBackup puts rules.bak and crs-setup.conf.bak back in place. The
// overrides file and the stock baseline are left untouched: they were
// written before the failure and stay valid for the restored setup.
func (m *CRSUpdateManager) restoreBackup() {
	rulesPath := filepath.Join(m.crsDir, "rules")
	rulesBak := filepath.Join(m.crsDir, "rules.bak")
	if _, err := os.Stat(rulesBak); err == nil {
		os.RemoveAll(rulesPath)
		if err := moveTree(rulesBak, rulesPath); err != nil {
			log.Printf("crs update: failed to restore rules backup: %v", err)
		} else {
			writeCRSUpdateLog("INFO", string(CRSStatusInstalling), "已从备份恢复规则")
		}
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

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
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
