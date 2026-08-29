package services

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/models"
	"net/http"
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

// BuildWafFileRef computes the live rule-file hashes without file content;
// the snapshot embeds this reference so unchanged files never ride along.
func BuildWafFileRef() *models.ClusterWafFilesRef {
	ref := &models.ClusterWafFilesRef{}
	seen := false
	if _, err := os.Stat(filepath.Join(crsLiveDir, "rules")); err == nil {
		if _, sum, err := tarGzDir(crsLiveDir); err == nil && sum != "" {
			ref.CRSSha256 = sum
			seen = true
		}
	}
	if v, err := os.ReadFile(filepath.Join(crsLiveDir, "VERSION")); err == nil {
		ref.CRSVersion = strings.TrimSpace(string(v))
	}
	if sum := fileSha256(ip2regionLivePath); sum != "" {
		ref.IP2RegionSha = sum
		seen = true
	}
	if v, err := os.ReadFile(ip2regionLivePath + ".version"); err == nil {
		// 与从端同一规则推导 tag（R35-2 形状校验）：主端原文、从端置空会让
		// waf_files 节哈希两端永不对齐，从端永久节流重拉（E5 IMP-1）。
		ref.IP2RegionTag = sanitizeBundleVersion(strings.TrimSpace(string(v)))
	}
	if !seen {
		return nil
	}
	return ref
}

// BuildWafFileBundle collects the live rule files with content; served by the
// on-demand endpoint, and never embedded in snapshots.
func BuildWafFileBundle() *WafFileBundle {
	ref := BuildWafFileRef()
	if ref == nil {
		return nil
	}
	bundle := &WafFileBundle{
		CRSVersion:   ref.CRSVersion,
		CRSSha256:    ref.CRSSha256,
		IP2RegionTag: ref.IP2RegionTag,
		IP2RegionSha: ref.IP2RegionSha,
	}
	if ref.CRSSha256 != "" {
		if data, _, err := tarGzDir(crsLiveDir); err == nil && len(data) > 0 {
			bundle.CRSTarGzB64 = data
		}
	}
	if ref.IP2RegionSha != "" {
		if data, err := os.ReadFile(ip2regionLivePath); err == nil {
			bundle.XdbB64 = data
		}
	}
	return bundle
}

// wafFilesRefDiffers reports whether the slave's live files fail to match
// any artifact referenced by the snapshot.
// rewriteVersionIfMissingOrStale 保证 .version 与主节点声明的 tag 一致（R57 A-#4）：
// tag 非空且磁盘缺失或内容不符时原子补写（tmp+rename）；tag 为空是合法收敛信号
// （主端 .version 缺失/损坏/形状校验置空），本地陈旧 tag 必须一并清除，否则
// waf_files 节哈希（含标签）两端永不对齐，从端永久假漂移全量重拉；写失败必须
// 上抛——该文件参与 wafFilesSectionHash，静默丢失会让从端漂移判定永不收敛。
func rewriteVersionIfMissingOrStale(path, tag string) error {
	if tag == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if current, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(current)) == strings.TrimSpace(tag) {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(tag), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func wafFilesRefDiffers(r *models.ClusterWafFilesRef) bool {
	if r == nil {
		return false
	}
	if r.CRSSha256 != "" {
		if _, sum, err := tarGzDir(crsLiveDir); err != nil || sum != r.CRSSha256 {
			return true
		}
	}
	if r.IP2RegionSha != "" && fileSha256(ip2regionLivePath) != r.IP2RegionSha {
		return true
	}
	return false
}

// wafFilesRefMatchesBundle verifies fetched content against the reference
// so a master mid-sync file update cannot silently install unverified bytes.
func wafFilesRefMatchesBundle(r *models.ClusterWafFilesRef, b *WafFileBundle) bool {
	if r == nil || b == nil {
		return false
	}
	if r.CRSSha256 != "" && b.CRSSha256 != r.CRSSha256 {
		return false
	}
	if r.IP2RegionSha != "" && b.IP2RegionSha != r.IP2RegionSha {
		return false
	}
	return true
}

// ApplyWafFileBundle writes the bundle's files to disk when they differ from
// what is already live. It is idempotent: matching content is a no-op, so a
// re-sync without rule changes costs only a hash comparison. Per-component
// changed flags let callers report exactly which dataset was updated.
func ApplyWafFileBundle(bundle *WafFileBundle) (crsChanged, xdbChanged bool, err error) {
	if bundle == nil {
		return false, false, nil
	}
	if len(bundle.CRSTarGzB64) > 0 {
		// 声明哈希为空但携带内容：合法主节点 BuildWafFileBundle 恒成对设置，
		// 仅恶意/损坏主节点可构造——与 xdb 侧同纵深防御；untarGzTo 在
		// expectSum=="" 时跳过整树哈希校验，必须拒绝而非裸写未验证字节。
		if bundle.CRSSha256 == "" {
			return crsChanged, xdbChanged, errors.New("同步 CRS规则库缺少声明哈希，已拒绝落盘")
		}
		liveSum, liveErr := tarGzDirSum(crsLiveDir)
		if liveErr != nil || liveSum != bundle.CRSSha256 {
			if err := untarGzTo(bundle.CRSTarGzB64, crsLiveDir, bundle.CRSSha256); err != nil {
				return crsChanged, xdbChanged, fmt.Errorf("写入同步 CRS 规则文件: %w", err)
			}
			// VERSION 随 tar 包以原始字节落盘（R46-E1）：不得以 TrimSpace 后的
			// bundle.CRSVersion 覆写——上游发布包的 VERSION 自带尾换行，主端
			// CRSSha256 基于原始字节计算，覆写会让本地 tar 哈希与已应用节哈希
			// 永久分叉，wafFilesDrifted 每轮误判漂移、全量重拉永不收敛。
			crsChanged = true
		}
	}
	if len(bundle.XdbB64) > 0 {
		// 声明哈希为空但携带内容：合法主节点 BuildWafFileBundle 恒成对设置，
		// 仅恶意/损坏主节点可构造——与 CRS 侧 F-3 同纵深防御，拒绝整包而非
		// 裸写原始字节。
		if bundle.IP2RegionSha == "" {
			return crsChanged, xdbChanged, errors.New("同步 IP2Region数据库缺少声明哈希，已拒绝落盘")
		}
		liveSum := fileSha256(ip2regionLivePath)
		// R57 A-#4：xdb 未变化也要校验/补写 .version——.version 丢失或写失败
		// 会让本地 ref 的 tag 为空，wafFilesDrifted 每轮误判漂移且全量重拉
		// 走不到本分支的自愈（重拉时 sha 相同），从节点永久假警报。
		if tagErr := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", bundle.IP2RegionTag); tagErr != nil {
			return crsChanged, xdbChanged, fmt.Errorf("写入同步 IP2Region数据库版本标记: %w", tagErr)
		}
		if liveSum != bundle.IP2RegionSha {
			sum := sha256.Sum256(bundle.XdbB64)
			if got := hex.EncodeToString(sum[:]); got != bundle.IP2RegionSha {
				return crsChanged, xdbChanged, fmt.Errorf("同步 IP2Region数据库哈希不匹配（声明 %s，实际 %s），已拒绝落盘", bundle.IP2RegionSha, got)
			}
			tmp := ip2regionLivePath + ".sync"
			if err := os.WriteFile(tmp, bundle.XdbB64, 0644); err != nil {
				return crsChanged, xdbChanged, fmt.Errorf("写入同步 IP2Region数据库: %w", err)
			}
			if err := os.Rename(tmp, ip2regionLivePath); err != nil {
				return crsChanged, xdbChanged, fmt.Errorf("落盘同步 IP2Region数据库: %w", err)
			}
			if tagErr := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", bundle.IP2RegionTag); tagErr != nil {
				return crsChanged, xdbChanged, fmt.Errorf("写入同步 IP2Region数据库版本标记: %w", tagErr)
			}
			xdbChanged = true
		}
	}
	return crsChanged, xdbChanged, nil
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

// 解包上限：gzip 炸弹（压缩侧最多 64MB，可膨胀数 GB）必须在写放大发生前
// 拦截；正常 CRS 树远低于该值，超限必为损坏/篡改包（N-02）。
const maxWafSyncExtractFiles = 2000 // 2000 文件数上限

// maxWafSyncExtractBytes 256MB 解包字节上限。var 以便测试缩小预算构造
// 恰好用尽的边界包（R56 N-4），生产路径不修改。
var maxWafSyncExtractBytes int64 = 256 << 20

// untarGzTo extracts data into destDir atomically. When expectSum is
// non-empty, the re-archived staging tree must hash to it, or the sync is
// rejected before anything touches the live tree.
func untarGzTo(data []byte, destDir string, expectSum string) error {
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
	// 兜底清理：任何错误路径（解包失败/哈希校验失败/备份失败）都不得遗留
	// staging 目录到下一周期；成功路径 rename 后 staging 已不存在，RemoveAll 是空操作。
	defer os.RemoveAll(staging)
	var writtenBytes int64
	writtenFiles := 0
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
			writtenFiles++
			if writtenFiles > maxWafSyncExtractFiles {
				return fmt.Errorf("同步规则集文件数超过上限（%d 个），已拒绝落盘", maxWafSyncExtractFiles)
			}
			// 先减后比：writtenBytes 恒 ≤ maxWafSyncExtractBytes（每个被接受条目维持
			// 该不变量），减法不下溢；加法在 hdr.Size 接近 2^63-1（GNU base-256）
			// 时溢出为负会绕过上限（R55 A-#2）。
			if hdr.Size < 0 || hdr.Size > maxWafSyncExtractBytes-writtenBytes {
				return fmt.Errorf("同步规则集解包体积超过上限（%d 字节），已拒绝落盘", maxWafSyncExtractBytes)
			}
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
			written, err := io.Copy(f, tr)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			writtenBytes += written
		}
	}
	// Verify the extracted staging tree before touching the live tree.
	if expectSum != "" {
		sum, sumErr := tarGzDirSum(staging)
		if sumErr != nil {
			os.RemoveAll(staging)
			return fmt.Errorf("校验同步规则集: %w", sumErr)
		}
		if sum != expectSum {
			os.RemoveAll(staging)
			return fmt.Errorf("同步规则集哈希不匹配（声明 %s，实际 %s），已拒绝落盘", expectSum, sum)
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
		// rename 到非空目录恒失败（EEXIST/ENOTEMPTY）——destDir 非空（生产常态：
		// 镜像自带规则树或已同步过的树）时本兜底分支即主路径，而非罕见的跨挂载点
		// 情形。copyDir 只覆盖同名文件、不删除旧树中新包缺失的文件，必须先清空
		// destDir 再复制（对齐 crsinstall.go 安装前的显式 RemoveAll 语义），否则
		// CRS 更新删除/改名规则文件后从端树为旧+新合并、tarGzDirSum 永不等于
		// 声明哈希，漂移检测永不收敛（R47 A-#2）。
		if err := os.RemoveAll(destDir); err != nil {
			// R49 A-N2：backup 已就绪，清空失败同样尽力恢复，与下方 copyDir
			// 失败分支恢复面对称；恢复错误并入返回，不吞掉。
			return fmt.Errorf("清空目标规则树: %w", errors.Join(err, restoreWafTreeFromBackup(backup, destDir)))
		}
		if err := copyDir(staging, destDir); err != nil {
			// 复制中途失败时 destDir 已被清空但可能残留部分新树文件——恢复自身的
			// 错误并入返回错误，不吞掉（R48 A-F3）。
			return fmt.Errorf("安装同步规则集: %w", errors.Join(err, restoreWafTreeFromBackup(backup, destDir)))
		}
	}
	os.RemoveAll(backup)
	return nil
}

// restoreWafTreeFromBackup 尽力从 backup 恢复 destDir：先整树清空再从备份复制，
// 保证恢复结果为纯旧树而非旧+新混合树（R48 A-F3，对齐 untarGzTo 的清空语义）。
// backup 不存在（备份时刻 destDir 不存在）时无可恢复对象，按空操作收尾。
func restoreWafTreeFromBackup(backup, destDir string) error {
	if _, statErr := os.Stat(backup); statErr != nil {
		return nil
	}
	if removeErr := os.RemoveAll(destDir); removeErr != nil {
		return fmt.Errorf("清空目标规则树以恢复旧树: %w", removeErr)
	}
	if restoreErr := copyDir(backup, destDir); restoreErr != nil {
		return fmt.Errorf("从备份恢复旧树: %w", restoreErr)
	}
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

// fetchWafFiles pulls the full file bundle from the master's on-demand
// endpoint and verifies it against the snapshot reference before use.
func (s *SyncService) fetchWafFiles(ctx context.Context, ref *models.ClusterWafFilesRef) (*WafFileBundle, error) {
	var masterURL, token string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(master_url,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&masterURL, &token); err != nil {
		return nil, fmt.Errorf("读取主节点地址: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(masterURL, "/")+"/api/v1/cluster/sync/waf-files", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Cluster-Token", token)
	resp, err := s.do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取安全数据: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// body 截断至 200B 并回退到合法 UTF-8 边界：错误消息经审计详情落库
		// （无界写入），超长/非法字节 body 会膨胀审计库并产生乱码（R35-1）。
		// 复用 cluster_sync.go 的既有截断模式（:586-587）。
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		body = truncateValidUTF8Tail(body)
		return nil, fmt.Errorf("拉取安全数据失败(%d): %s", resp.StatusCode, string(body))
	}
	// C2-S2：读 limit+1 字节探测超限——裸 LimitReader 截断后 JSON 解码只会
	// 报 unexpected EOF/invalid character，把「主节点数据异常」误诊为解析
	// 问题；超限必须显式拒绝并点名上限。
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWafBundleBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取安全数据包: %w", err)
	}
	if int64(len(body)) > maxWafBundleBodyBytes {
		return nil, fmt.Errorf("安全数据包超过 %dMB 上限，已拒绝（疑似主节点数据异常）", maxWafBundleBodyBytes>>20)
	}
	var envelope struct {
		Data WafFileBundle `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("解析安全数据包: %w", err)
	}
	if !wafFilesRefMatchesBundle(ref, &envelope.Data) {
		return nil, errors.New("安全数据包哈希与快照引用不一致（主节点文件可能在同步期间变更），将在下个周期重试")
	}
	bundle := envelope.Data
	// 版本串不在 HMAC/哈希覆盖内，流氓主节点可注入超长/控制字符内容，
	// 直写审计详情与 VERSION/.version 落盘文件（R35-2）：形状校验后置空。
	bundle.CRSVersion = sanitizeBundleVersion(bundle.CRSVersion)
	bundle.IP2RegionTag = sanitizeBundleVersion(bundle.IP2RegionTag)
	return &bundle, nil
}

// maxWafBundleBodyBytes 是安全数据包（WafFileBundle JSON）响应体的硬上限：
// 正常 CRS tar.gz+xdb 远低于该值，超限必为主节点数据异常/滥用，整体拒绝
// 而非静默截断（C2-S2）。
const maxWafBundleBodyBytes int64 = 64 << 20

// maxBundleVersionLen 限制安全数据版本串长度：正常形如 v4.28.0 / v3.17.0，
// 64 字节足够容纳任何真实版本号。
const maxBundleVersionLen = 64

// sanitizeBundleVersion 校验安全数据版本串形状：非空时必须是 ≤64 字符的
// 可打印 ASCII（字母数字 . _ - +），不符合则置空并记 warn——版本串不在快照
// HMAC/哈希覆盖内，直写审计详情与落盘文件，必须防流氓主节点注入。
func sanitizeBundleVersion(v string) string {
	if v == "" {
		return ""
	}
	if len(v) > maxBundleVersionLen {
		Logf("warn", "忽略非法安全数据版本串（长度 %d 超过上限 %d），已置空", len(v), maxBundleVersionLen)
		return ""
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '+' {
			continue
		}
		Logf("warn", "忽略非法安全数据版本串 %q（含非法字符 %q），已置空", v, r)
		return ""
	}
	return v
}
