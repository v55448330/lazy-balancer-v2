package services

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WafFileBundle carries the CRS rules tree and GeoIP xdb inside a cluster
// snapshot so slaves converge on the master's actual rule files, not just the
// version rows. Files are serialized as a deterministic tar.gz (sorted paths,
// no mtimes) so identical trees produce identical bytes and fingerprints.
type WafFileBundle struct {
	CRSVersion   string `json:"crs_version"`
	CRSSha256    string `json:"crs_sha256"`
	IP2RegionTag string `json:"ip2region_version"`
	IP2RegionSha string `json:"ip2region_sha256"`
	CRSTarGzB64  []byte `json:"crs_tar_gz,omitempty"`
	XdbB64       []byte `json:"xdb,omitempty"`
}

// BuildWafFileBundle collects the live rule files. It returns nil (skip sync)
// when neither artifact exists on this node.
func BuildWafFileBundle() *WafFileBundle {
	bundle := &WafFileBundle{}
	hasContent := false

	if _, err := os.Stat(filepath.Join(crsLiveDir, "rules")); err == nil {
		data, sum, err := tarGzDir(crsLiveDir)
		if err == nil && len(data) > 0 {
			bundle.CRSTarGzB64 = data
			bundle.CRSSha256 = sum
			hasContent = true
		}
	}
	if v, err := os.ReadFile(filepath.Join(crsLiveDir, "VERSION")); err == nil {
		bundle.CRSVersion = strings.TrimSpace(string(v))
	}
	if data, err := os.ReadFile(ip2regionLivePath); err == nil {
		sum := sha256.Sum256(data)
		bundle.XdbB64 = data
		bundle.IP2RegionSha = hex.EncodeToString(sum[:])
		hasContent = true
	}
	if v, err := os.ReadFile(ip2regionLivePath + ".version"); err == nil {
		bundle.IP2RegionTag = strings.TrimSpace(string(v))
	}
	if !hasContent {
		return nil
	}
	return bundle
}

// ApplyWafFileBundle writes the bundle's files to disk when they differ from
// what is already live. It is idempotent: matching content is a no-op, so a
// re-sync without rule changes costs only a hash comparison.
func ApplyWafFileBundle(bundle *WafFileBundle) (changed bool, err error) {
	if bundle == nil {
		return false, nil
	}
	if len(bundle.CRSTarGzB64) > 0 {
		liveSum, liveErr := tarGzDirSum(crsLiveDir)
		if liveErr != nil || liveSum != bundle.CRSSha256 {
			if err := untarGzTo(bundle.CRSTarGzB64, crsLiveDir); err != nil {
				return changed, fmt.Errorf("写入同步 CRS 规则文件: %w", err)
			}
			if bundle.CRSVersion != "" {
				_ = os.WriteFile(filepath.Join(crsLiveDir, "VERSION"), []byte(bundle.CRSVersion), 0644)
			}
			changed = true
		}
	}
	if len(bundle.XdbB64) > 0 {
		liveSum := fileSha256(ip2regionLivePath)
		if liveSum != bundle.IP2RegionSha {
			tmp := ip2regionLivePath + ".sync"
			if err := os.WriteFile(tmp, bundle.XdbB64, 0644); err != nil {
				return changed, fmt.Errorf("写入同步 IP2Region 数据库: %w", err)
			}
			if err := os.Rename(tmp, ip2regionLivePath); err != nil {
				return changed, fmt.Errorf("落盘同步 IP2Region 数据库: %w", err)
			}
			if bundle.IP2RegionTag != "" {
				_ = os.WriteFile(ip2regionLivePath+".version", []byte(bundle.IP2RegionTag), 0644)
			}
			changed = true
		}
	}
	return changed, nil
}

// tarGzDir deterministically archives dir (all contents, sorted, zeroed
// metadata) and returns the bytes plus their sha256.
func tarGzDir(dir string) ([]byte, string, error) {
	var paths []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	for i := range paths {
		paths[i], _ = filepath.Rel(dir, paths[i])
	}
	sortStrings(paths)

	pr, pw := io.Pipe()
	go func() {
		gz := gzip.NewWriter(pw)
		tw := tar.NewWriter(gz)
		for _, rel := range paths {
			full := filepath.Join(dir, rel)
			data, err := os.ReadFile(full)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			hdr := &tar.Header{Name: rel, Mode: 0644, Size: int64(len(data))}
			if err := tw.WriteHeader(hdr); err != nil {
				pw.CloseWithError(err)
				return
			}
			if _, err := tw.Write(data); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		tw.Close()
		gz.Close()
		pw.Close()
	}()
	data, err := io.ReadAll(pr)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// tarGzDirSum recomputes the deterministic archive hash of the live tree.
func tarGzDirSum(dir string) (string, error) {
	_, sum, err := tarGzDir(dir)
	return sum, err
}

func untarGzTo(data []byte, destDir string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	staging := destDir + ".sync-in"
	os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0755); err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(hdr.Name)
		if filepath.IsAbs(rel) || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") || rel == ".." {
			return fmt.Errorf("同步包含非法路径 %q", hdr.Name)
		}
		if rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		target := filepath.Join(staging, rel)
		if !strings.HasPrefix(target, filepath.Clean(staging)+string(os.PathSeparator)) {
			return fmt.Errorf("同步包含非法路径 %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err := os.WriteFile(target, []byte{}, 0644); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	// Replace live tree: backup then swap (copy-based, overlayfs-safe like
	// the CRS updater itself).
	backup := destDir + ".sync-bak"
	os.RemoveAll(backup)
	if _, err := os.Stat(destDir); err == nil {
		if err := copyDir(destDir, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(staging, destDir); err != nil {
		// rename may fail across mount points; fall back to merge-copy
		if err := copyDir(staging, destDir); err != nil {
			return err
		}
		os.RemoveAll(staging)
	}
	os.RemoveAll(backup)
	return nil
}

func fileSha256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var _ = context.Background
