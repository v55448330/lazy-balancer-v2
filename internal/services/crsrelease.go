package services

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// validateCRSStaging ensures an extracted CRS release tree is complete enough
// to swap into place: the setup template plus an intact rules tree. R51 F3：
// 探针文件（crsRulesProbeFile）是 backup restore / seed / snapshot 消费门共用
// 的完整性契约，安装期必须同步把关——否则未来 CRS 重组 rules/ 的发布会装出
// 退化树，之后每次启动都触发清空重播循环。
func validateCRSStaging(dir string) error {
	if info, err := os.Stat(filepath.Join(dir, "crs-setup.conf.example")); err != nil || info.IsDir() {
		return fmt.Errorf("staging 缺少 crs-setup.conf.example")
	}
	if !crsRulesTreeIntact(filepath.Join(dir, "rules")) {
		return fmt.Errorf("staging rules 树不完整（无 .conf 规则文件或缺失 %s）；该探针文件是安装契约——若上游 CRS 发布结构已变更，请等待适配版本或手动回退，切勿绕过校验强行安装", crsRulesProbeFile)
	}
	return nil
}

// countSecRules counts SecRule directives across all *.conf files in dir.
// Only lines whose first token is exactly "SecRule" count; comments and
// lookalike directives (SecRuleUpdateTargetById, SecRuleRemoveById, ...) do not.
func countSecRules(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("读取规则目录: %w", err)
	}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return 0, fmt.Errorf("读取规则文件 %s: %w", entry.Name(), err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimLeft(line, " \t")
			if trimmed == "SecRule" || strings.HasPrefix(trimmed, "SecRule ") || strings.HasPrefix(trimmed, "SecRule\t") {
				total++
			}
		}
	}
	return total, nil
}

// CountSecRulesLive counts SecRule directives in the live rules directory.
func CountSecRulesLive() (int, error) {
	return countSecRules(filepath.Join(crsLiveDir, "rules"))
}

// compareCRSVersions compares two dotted version tags (optional leading "v"),
// returning -1, 0 or 1. Missing segments are treated as 0.
func compareCRSVersions(a, b string) (int, error) {
	pa, err := parseVersionParts(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersionParts(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1, nil
		}
		if va > vb {
			return 1, nil
		}
	}
	return 0, nil
}

// CompareCRSVersions exposes compareCRSVersions for handlers.
func CompareCRSVersions(a, b string) (int, error) {
	return compareCRSVersions(a, b)
}

func parseVersionParts(tag string) ([]int, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(tag), "v")
	if trimmed == "" {
		return nil, fmt.Errorf("无法解析版本号 %q", tag)
	}
	parts := strings.Split(trimmed, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("无法解析版本号 %q: %w", tag, err)
		}
		out = append(out, value)
	}
	return out, nil
}

// parseGitHubLatestTag extracts tag_name from a GitHub releases/latest body.
func parseGitHubLatestTag(body []byte) (string, error) {
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}
	if payload.TagName == "" {
		return "", errors.New("GitHub 响应缺少 tag_name")
	}
	return payload.TagName, nil
}

// crsExtractMaxBytes 是解压总字节上限（防 gzip 炸弹耗尽数据卷，R33 F8）：
// tar 头声明的 hdr.Size 即解压后写入的确切字节数，跨条目累计超限即中止。
const crsExtractMaxBytes = 500 << 20

// extractCRSTarball extracts a GitHub release tar.gz into destDir, stripping
// the single top-level root directory GitHub adds to every entry.
func extractCRSTarball(tarballPath, destDir string) error {
	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("打开 tarball: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("解压 gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var totalBytes int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("读取 tar: %w", err)
		}
		totalBytes += hdr.Size
		if totalBytes > crsExtractMaxBytes {
			return fmt.Errorf("tarball 解压超过大小上限（%d MB）", crsExtractMaxBytes>>20)
		}
		rel, err := stripTarRoot(hdr.Name)
		if err != nil {
			return err
		}
		if rel == "" {
			continue
		}
		target := filepath.Join(destDir, rel)
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("tarball 包含非法路径 %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("创建目录 %s: %w", rel, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("创建目录 %s: %w", filepath.Dir(rel), err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("写入 %s: %w", rel, err)
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return fmt.Errorf("写入 %s: %w", rel, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("写入 %s: %w", rel, closeErr)
			}
		}
	}
}

// stripTarRoot removes the first path component (the GitHub root directory)
// and rejects absolute paths or any remaining ".." traversal component.
func stripTarRoot(name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("tarball 包含绝对路径 %q", name)
	}
	parts := strings.Split(filepath.ToSlash(name), "/")
	rest := parts[1:]
	for _, part := range rest {
		if part == ".." {
			return "", fmt.Errorf("tarball 包含非法路径 %q", name)
		}
	}
	if len(rest) == 0 {
		return "", nil
	}
	return filepath.Join(rest...), nil
}
