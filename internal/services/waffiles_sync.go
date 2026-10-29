package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"lazy-balancer-v2/internal/atomicfile"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// wafFileMu 是 WAF 数据文件读写互斥锁（写侧；
// 历史补读侧）：CRS 树（crsinstall 树交换 / lbbak untarGzTo 交换）、威胁库
// .iplist+.fast（threatupdate 写编译对 / lbbak 直写）、ip2region xdb
// （ip2regionupdate 安装段 / ApplyWafFileBundle 直写）四方写相位与
// BuildWafFileBundle 读相位（lbbak 导出 / 集群按需端点共用）在此串行——此前
// 无共享锁，lbbak 导入与三库更新器交错会产生混合/残缺 rules 树（部分防护静默
// 失效 fail-open）、撕裂 .iplist（缺条目名单静默残缺）与 xdb 元数据瞬时错位；
// 读侧不入锁则打出半新半旧 bundle（manifest sha256 自洽不可检）。
// 锁只包文件相位（staging 先行、网络下载与 Caddy 重载在锁外）。全局锁序：
// 导入=排空→wafFileMu→CaddyOpLock（handlers 侧 prelock 先取 WafFileLock，
// beginConfigImportWithPrelock 排空后才取 caddyOpMu）；禁止 CaddyOpLock→
// wafFileMu 的嵌套——反向嵌套即 AB-BA 死锁（任何已持 CaddyOpLock 的渲染/
// 重载路径都不得再取本锁）。
var wafFileMu sync.Mutex

// WafFileLock 返回 WAF 数据文件读写互斥锁（跨包消费：handlers 侧 lbbak 导入
// 文件相位与本包三个更新器共用同一实例；BuildWafFileBundle 读相位内部自取）。
// 叶操作、无嵌套重入。
func WafFileLock() sync.Locker { return &wafFileMu }

// withWafFileLock 在 wafFileMu 临界区内执行 fn，defer 释放：同步/导入路径位于
// gin 路由栈（gin.Recovery 只恢复 HTTP 栈，不清理互斥状态），临界区 panic 后
// 裸 Unlock 永不执行会让包级锁永久泄漏（后续重载/导入/规则库更新/同步全阻塞）。
func withWafFileLock(fn func()) {
	WafFileLock().Lock()
	defer WafFileLock().Unlock()
	fn()
}

// WafFileBundle carries the CRS rules tree and GeoIP xdb inside a cluster
// snapshot so slaves converge on the master's actual rule files, not just the
// version rows. Files are serialized as a deterministic tar.gz (sorted paths,
// no mtimes) so identical trees produce identical bytes and fingerprints.
type WafFileBundle struct {
	CRSVersion   string `json:"crs_version"`
	CRSSha256    string `json:"crs_sha256"`
	IP2RegionTag string `json:"ip2region_version"`
	IP2RegionSha string `json:"ip2region_sha256"`
	// 原始字节载荷（JSON 序列化时由 encoding/json 转 base64；lbbak 通道直接
	// 以原始字节入 tar 条目）——字段名已去 B64 后缀。
	CRSTarGz []byte `json:"crs_tar_gz,omitempty"`
	Xdb      []byte `json:"xdb,omitempty"`
	// RDB 文件化：威胁库 .fast 文件（主节点编译产物，从节点直接使用零编译）
	ThreatFiles []models.ThreatFileEntry `json:"threat_files,omitempty"`
}

// wafFileApplyError 保留底层错误文本，同时标注失败组件；多组件调用方
// 借此避免把后续 XDB 失败误报成此前已成功/已一致的 CRS 失败。
type wafFileApplyError struct {
	component string
	err       error
}

func (e *wafFileApplyError) Error() string { return e.err.Error() }
func (e *wafFileApplyError) Unwrap() error { return e.err }

func newWafFileApplyError(component string, err error) error {
	if err == nil {
		return nil
	}
	return &wafFileApplyError{component: component, err: err}
}

// WafFileApplyComponent 返回 ApplyWafFileBundle 的失败组件（crs/xdb）；
// 非组件错误或旧错误形态返回空串，调用方应采取保守归因。
func WafFileApplyComponent(err error) string {
	var applyErr *wafFileApplyError
	if errors.As(err, &applyErr) {
		return applyErr.component
	}
	return ""
}

// wafFileBundleCache 缓存最近一次物化的 WAF 数据包与按需端点的序列化响应体
// 键=引用指纹（CRS/xdb/威胁.fast 哈希 + 两个版本串）——引用
// 不变时包内容字节级相同，无需每次重建。只保留单条：最坏内存形态=一份
// CRS tar.gz + xdb + 威胁 .fast，与一次请求的瞬时峰值同量级但不再随请求数
// 叠加。缓存仅在 wafFileMu 内读写（BuildWafFileBundle/Response 两入口均持锁），
// 发布后的 bundle/字节切片只读，读者可安全持有旧代引用。
var wafFileBundleCache struct {
	key      string
	bundle   *WafFileBundle
	response []byte
	// responseValidatedAt = 上次重算引用（全树哈希）的时间。按需端点在窗口内
	// 直接复用响应体：主节点换版后 N 个从节点同周期齐拉时只做一次全树哈希，
	// 其余命中同一代（陈旧窗口 ≤2s，从节点按快照引用比对后下轮自愈）。
	responseValidatedAt time.Time
}

// wafFileBundleResponseCoalesceWindow 按需端点的引用重算合并窗口（var——测试
// 可关闭以验证失效路径）。
var wafFileBundleResponseCoalesceWindow = 2 * time.Second

// wafFileRefKey 构造稳定引用键（威胁源按名排序保证 map 迭代顺序不影响键）。
func wafFileRefKey(ref *models.ClusterWafFilesRef) string {
	names := make([]string, 0, len(ref.ThreatSha256s))
	for name := range ref.ThreatSha256s {
		names = append(names, name)
	}
	sort.Strings(names)
	var builder strings.Builder
	builder.WriteString(ref.CRSVersion)
	builder.WriteByte(0)
	builder.WriteString(ref.CRSSha256)
	builder.WriteByte(0)
	builder.WriteString(ref.IP2RegionTag)
	builder.WriteByte(0)
	builder.WriteString(ref.IP2RegionSha)
	for _, name := range names {
		builder.WriteByte(0)
		builder.WriteString(name)
		builder.WriteByte('=')
		builder.WriteString(ref.ThreatSha256s[name])
	}
	return builder.String()
}

// materializeWafFileBundle 按引用读取文件内容（调用方必须已持 wafFileMu）。
// 威胁文件按源名排序，保证同一引用的打包/序列化结果确定。
// CRS/xdb/威胁面逐项做「实测内容哈希 == 引用声明哈希」复核：引用缓存 TTL
// 窗口内的带外改写（等长同 mtime）会让缓存 ref 与实测字节跨代——不符的
// 分量不得随旧 ref 声明发出（从端按哈希门整包拒绝到 TTL 到期），降级为
// 不完整 bundle，由调用方回退全量构建自愈。
func materializeWafFileBundle(ref *models.ClusterWafFilesRef) *WafFileBundle {
	bundle := &WafFileBundle{
		CRSVersion:   ref.CRSVersion,
		CRSSha256:    ref.CRSSha256,
		IP2RegionTag: ref.IP2RegionTag,
		IP2RegionSha: ref.IP2RegionSha,
	}
	if ref.CRSSha256 != "" {
		if data, _, err := tarGzDir(crsLiveDir); err == nil && len(data) > 0 {
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) == ref.CRSSha256 {
				bundle.CRSTarGz = data
			}
		}
	}
	if ref.IP2RegionSha != "" {
		if data, err := os.ReadFile(ip2regionLivePath); err == nil {
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) == ref.IP2RegionSha {
				bundle.Xdb = data
			}
		}
	}
	names := make([]string, 0, len(ref.ThreatSha256s))
	for source := range ref.ThreatSha256s {
		names = append(names, source)
	}
	sort.Strings(names)
	for _, source := range names {
		fastPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist.fast", source))
		data, err := os.ReadFile(fastPath)
		if err != nil {
			continue
		}
		// 哈希直接对内存字节计算——避免二次读盘与 TOCTOU 窗口。
		sum := sha256.Sum256(data)
		encoded := hex.EncodeToString(sum[:])
		if encoded != ref.ThreatSha256s[source] {
			continue
		}
		bundle.ThreatFiles = append(bundle.ThreatFiles, models.ThreatFileEntry{
			Name:    source,
			Sha256:  encoded,
			Content: data,
		})
	}
	return bundle
}

// wafFileBundleComplete 判定物化结果是否覆盖引用声明的全部组件：瞬时读失败
// （打包/读取错误）不得被缓存到引用变化为止。
func wafFileBundleComplete(ref *models.ClusterWafFilesRef, bundle *WafFileBundle) bool {
	if ref.CRSSha256 != "" && len(bundle.CRSTarGz) == 0 {
		return false
	}
	if ref.IP2RegionSha != "" && len(bundle.Xdb) == 0 {
		return false
	}
	return len(bundle.ThreatFiles) == len(ref.ThreatSha256s)
}

// buildWafFileBundleLocked 返回 bundle、引用键与本次引用（调用方必须已持
// wafFileMu）。命中缓存时不重读任何文件；ref 始终是当前时刻的引用（用于
// 响应体缓存的完整性门）。
func buildWafFileBundleLocked() (*WafFileBundle, string, *models.ClusterWafFilesRef) {
	ref := buildWafFileRefLocked()
	if ref == nil {
		return nil, "", nil
	}
	key := wafFileRefKey(ref)
	if wafFileBundleCache.bundle != nil && wafFileBundleCache.key == key {
		return wafFileBundleCache.bundle, key, ref
	}
	bundle := materializeWafFileBundle(ref)
	if !wafFileBundleComplete(ref, bundle) && wafFileRefCache.valid {
		// 不完整：可能是瞬时读失败，也可能是 TTL 窗口内带外改写让缓存 ref
		// 与实测字节跨代（等长同 mtime 不变签名）。作废引用缓存并按真实
		// 内容重建一次：跨代形态当轮即自愈（响应与新引用一致），真实读失败
		// 照旧按不完整 bundle 返回、不缓存。
		invalidateWafFileRefCache()
		if rebuilt := buildWafFileRefLocked(); rebuilt != nil {
			ref = rebuilt
			key = wafFileRefKey(ref)
			bundle = materializeWafFileBundle(ref)
		}
	}
	if wafFileBundleComplete(ref, bundle) {
		wafFileBundleCache.key = key
		wafFileBundleCache.bundle = bundle
		wafFileBundleCache.response = nil
	}
	return bundle, key, ref
}

// BuildWafFileBundleResponse 返回集群按需端点的完整 API 响应体（一次序列化，
// 按引用指纹缓存）：引用不变时复用同一份字节，避免每请求 base64 重编码
// nil = 主节点无安全数据。
func BuildWafFileBundleResponse() []byte {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	if wafFileBundleCache.response != nil && time.Since(wafFileBundleCache.responseValidatedAt) < wafFileBundleResponseCoalesceWindow {
		return wafFileBundleCache.response
	}
	bundle, key, ref := buildWafFileBundleLocked()
	if bundle == nil {
		return nil
	}
	if wafFileBundleCache.response != nil && wafFileBundleCache.key == key {
		wafFileBundleCache.responseValidatedAt = time.Now()
		return wafFileBundleCache.response
	}
	body, err := json.Marshal(models.APIResponse{Code: 0, Data: bundle})
	if err != nil {
		// 该结构只含字符串/字节切片/数字，Marshal 实际不可失败；保持 fail-visible
		// 而非缓存半成品。
		Logf("error", "序列化 WAF 数据包失败: %v", err)
		return nil
	}
	// 响应体缓存也以完整性与引用键为门——主端瞬时读失败产出
	// 「声明哈希非空但缺内容」的 bundle 时，不得把异常形态缓存并在合并窗口内
	// 放大传播（从端每次都拒绝，仅浪费重试周期）。不完整时照常返回本次字节。
	if wafFileBundleCache.key == key && wafFileBundleComplete(ref, bundle) {
		wafFileBundleCache.response = body
		wafFileBundleCache.responseValidatedAt = time.Now()
	}
	return body
}

// BuildWafFileRef computes the live rule-file hashes without file content;
// the snapshot embeds this reference so unchanged files never ride along.
func BuildWafFileRef() *models.ClusterWafFilesRef {
	// 读相位统一持 wafFileMu——导出侧（本函数）与写相位（CRS 树交换/
	// VERSION 标记/xdb 落盘/威胁 .fast）串行，读者只看到旧代或新代，不发布混合代。
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	return buildWafFileRefLocked()
}

// buildWafFileRefLocked 是 BuildWafFileRef 的无锁核心（调用方必须已持
// wafFileMu；BuildWafFileBundle 与导出一侧共用，杜绝锁内自取）。
// 与 checked 变体单源——组件存在但读取/哈希
// 失败不再静默省略分量（旧行为让快照 ref 少一项：从端不拉取、主端无告警，
// 主从静默分叉），而是错误日志显式化 + 整体返回 nil。消费侧语义：
// 主端快照缺 waf_files 引用（从端跳过比对、保留现状）与从端本地漂移检测
// （wafFilesDrifted：nil → 判分叉全量重拉）均为可见/自愈方向。
func buildWafFileRefLocked() *models.ClusterWafFilesRef {
	ref, err := buildWafFileRefLockedChecked()
	if err != nil {
		Logf("error", "WAF 文件引用构建失败（集群同步按无引用处理，从端漂移检测将触发全量重拉自愈）: %v", err)
		return nil
	}
	return ref
}

// buildWafFileRefLockedChecked 与 buildWafFileRefLocked 同源，但把「组件
// 存在却读取/哈希失败」显式上报，而不是静默省略分量后宣称引用完整。
// lbbak 导出必须走本变体。
func buildWafFileRefLockedChecked() (*models.ClusterWafFilesRef, error) {
	// 调用面在稳态下极其频繁（从端每个 304 同步轮、主端每次快照重建
	// ——后者还会被节点列表轮询间接触发），而真正的全量构建要遍历 CRS 规则树
	// 打 tar.gz、整读 ip2region.xdb、逐个哈希威胁 .fast。文件相位的一切写入都
	// 经 wafFileMu 且文件系统 mtime/size 必然变化，故先用「相对路径 + 大小 +
	// mtime」廉价签名短路：签名不变即复用上次引用，签名变化才付出全量成本。
	// 签名计算只 stat 不读内容（消除十余 MB 读放大与 gzip 计算）。
	sig, sigErr := wafRefStatSignature()
	if sigErr == nil {
		wafFileRefCache.mu.Lock()
		if wafFileRefCache.valid && wafFileRefCache.sig == sig && time.Since(wafFileRefCache.validatedAt) < wafFileRefCacheTTL {
			ref := cloneWafFilesRef(wafFileRefCache.ref)
			wafFileRefCache.mu.Unlock()
			return ref, nil
		}
		wafFileRefCache.mu.Unlock()
	}
	ref, err := buildWafFileRefFullLockedChecked()
	if err != nil {
		return nil, err
	}
	if sigErr == nil {
		wafFileRefCache.mu.Lock()
		wafFileRefCache.sig = sig
		wafFileRefCache.ref = cloneWafFilesRef(ref)
		wafFileRefCache.valid = true
		wafFileRefCache.validatedAt = time.Now()
		wafFileRefCache.mu.Unlock()
	}
	return ref, nil
}

// wafFileRefCache 缓存「廉价文件签名 → 已构建引用」。命中条件=签名相等
// ∧ 距上次全量构建未超 wafFileRefCacheTTL：签名由 size/mtime/mode 派生，
// 「等长同 mtime 原地改写」（rsync -t / install -p / 备份还原保留时间戳）
// 不变签名——单靠签名会让旧 ref 与旧 bundle 无限期命中（主端发旧字节给
// 从端=静默分叉，或用旧哈希标注新字节=从端整包拒绝且不自愈）。TTL 把该
// 形态的陈旧窗口收敛到定值内（到期后全量重建读到真实内容）。
var wafFileRefCache struct {
	mu          sync.Mutex
	valid       bool
	sig         string
	ref         *models.ClusterWafFilesRef
	validatedAt time.Time
}

// wafFileRefCacheTTL 是廉价签名缓存的最长复用时间（var 供测试收窄）。
//
// 取值约束：必须显著大于默认同步周期
// （defaultSyncIntervalSeconds=60s，normalizeSyncInterval 下限 10s）——本
// 缓存的两个消费面都「按同步周期反复调用」：从端每个 304 稳态轮的
// wafFilesDrifted 与主端每次快照重建，而全量构建要整树 tar.gz+sha256、整读
// xdb、逐个哈希威胁 .fast 并全程持 wafFileMu（与 CRS 更新/导入/安全数据下发
// 串行）。原值 30s 恒小于 60s 周期 → 每个稳态 304 轮都必然过期重建，「廉价
// 签名短路」对真实节奏完全失效（每节点每 60s 一次 50–200ms 级 CPU/IO 尖峰 +
// 锁排队）。10 分钟 = 默认节奏下约每 10 轮一次内容复核。
//
// 有界性不变：带内写入（CRS 树交换/xdb 安装/威胁名单编译/lbbak 导入）必然
// 改变 size/mtime → 签名失效 → 下一轮立即重建；只有「等长 + 同 mtime」的带外
// 改写才落到 TTL 兜底，其可发现窗口上界即本值（钉测：
// TestBuildWafFileRef_steadyState304RoundsSkipFullRebuild /
// TestBuildWafFileRef_sameSizeSameMtimeRewriteRecoveredWithinBoundedWindow /
// TestWafFileRefCacheTTL_coversSeveralDefaultSyncRounds）。
var wafFileRefCacheTTL = 10 * time.Minute

// wafFileRefFullBuilds 仅用于测试钉住「签名未变不重建」（生产零消费）。
var wafFileRefFullBuilds atomic.Int64

func cloneWafFilesRef(ref *models.ClusterWafFilesRef) *models.ClusterWafFilesRef {
	if ref == nil {
		return nil
	}
	out := *ref
	if ref.ThreatSha256s != nil {
		out.ThreatSha256s = make(map[string]string, len(ref.ThreatSha256s))
		for k, v := range ref.ThreatSha256s {
			out.ThreatSha256s[k] = v
		}
	}
	return &out
}

// wafRefStatSignature 计算 WAF 引用面的廉价签名：目录取元数据（不读规则
// 内容），两个版本文件（CRS VERSION 与 ip2region .version）显式读内容入
// 签名。覆盖引用构建的全部输入（CRS 树、CRS VERSION、xdb 与 .version、
// 威胁 .fast），任一枚举/stat 失败返回错误，调用方回退到全量构建（正确性
// 优先，性能优化不得掩盖故障）。
func wafRefStatSignature() (string, error) {
	h := sha256.New()
	// 路径本身入签名：不同数据目录下同名/同尺寸/同 mtime 的树不得互相命中
	// （测试会切换 crsLiveDir，生产也可能迁移数据卷）。
	fmt.Fprintf(h, "root\x00%s\x00%s\x00%s\n", crsLiveDir, ip2regionLivePath, wafDir)
	record := func(p string, info os.FileInfo) {
		// 模式并入签名：权限变化（如 chmod 导致读失败）本身不改变 size/mtime，
		// 但会让「全量构建」从成功变为显式错误——不能因此命中旧引用。
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%s\n", p, info.Size(), info.ModTime().UnixNano(), info.Mode())
	}
	if _, err := os.Stat(crsLiveDir); err == nil {
		if err := filepath.Walk(crsLiveDir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, relErr := filepath.Rel(crsLiveDir, p)
			if relErr != nil {
				return relErr
			}
			if info.IsDir() {
				// 目录新增/删除（例如 VERSION 被建成目录→分量读失败）必须改变
				// 签名，否则会命中旧引用、把显式读失败静默掩盖。但瞬态目录
				// （.staging/.sync-in 等命中 skipWafSyncTransient 者）不进打包集
				// （writeTarEntries 剔除瞬态路径），其条目不得入签名——同步/
				// 导入暂存目录否则会让 TTL 内稳态轮反复触发无谓全树重建。
				if rel != "." && skipWafSyncTransient(rel) {
					return filepath.SkipDir
				}
				fmt.Fprintf(h, "d\x00%s\x00%s\n", rel, info.Mode())
				return nil
			}
			if skipWafSyncTransient(rel) {
				return nil
			}
			record(rel, info)
			return nil
		}); err != nil {
			return "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// rules/ 缺失时上面的树遍历仍会覆盖活树根，但 VERSION 是引用构建的独立
	// 输入：显式读取内容入签名（不依赖父目录/规则树存在），并区分「缺失」与
	// 「存在但空」，保证版本内容变化恒改变签名。
	versionPath := filepath.Join(crsLiveDir, "VERSION")
	if data, err := os.ReadFile(versionPath); err == nil {
		fmt.Fprintf(h, "crs-version\x00%d\x00%s\n", len(data), data)
	} else if errors.Is(err, os.ErrNotExist) {
		fmt.Fprint(h, "crs-version-missing\n")
	} else {
		return "", err
	}
	if info, err := os.Stat(ip2regionLivePath); err == nil {
		record(ip2regionLivePath, info)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// .version（ip2region tag）与 CRS VERSION 同口径：内容入签名——tag 参与
	// waf_files 节哈希与从端漂移判定/大屏版本展示，「等长改写且保留
	// mtime/mode」（带外 touch/镜像恢复）时不得命中旧引用。
	tagPath := ip2regionLivePath + ".version"
	if data, err := os.ReadFile(tagPath); err == nil {
		fmt.Fprintf(h, "ip2region-version\x00%d\x00%s\n", len(data), data)
	} else if errors.Is(err, os.ErrNotExist) {
		fmt.Fprint(h, "ip2region-version-missing\n")
	} else {
		return "", err
	}
	matches, err := filepath.Glob(filepath.Join(wafDir, "threat-*.iplist.fast"))
	if err != nil {
		return "", err
	}
	for _, p := range matches {
		info, err := os.Stat(p)
		if err == nil {
			record(p, info)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readWafVersionLabels 读取两个版本标签文件（CRS VERSION 与 ip2region 伴生
// .version）——引用全量构建与上报热路径 reportWafFileVersions 的单源实现，
// 杜绝两份口径漂移。语义：
//   - 文件缺失 = 对应串为空串（TrimSpace / sanitizeBundleVersion 口径不变）；
//   - 非缺失类读失败（权限/IO）显式上抛——引用构建侧据此整体失败（不发布
//     偏斜引用），上报侧自行忽略 err 按空串 best-effort。
func readWafVersionLabels() (crsVersion, ip2regionTag string, err error) {
	if v, readErr := os.ReadFile(filepath.Join(crsLiveDir, "VERSION")); readErr == nil {
		crsVersion = strings.TrimSpace(string(v))
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("read CRS version: %w", readErr)
	}
	if v, readErr := os.ReadFile(ip2regionLivePath + ".version"); readErr == nil {
		ip2regionTag = sanitizeBundleVersion(strings.TrimSpace(string(v)))
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("read IP2Region version: %w", readErr)
	}
	return crsVersion, ip2regionTag, nil
}

// buildWafFileRefFullLockedChecked 是引用的全量构建（读内容 + 哈希），仅在
// 廉价签名缺失或变化时执行。
func buildWafFileRefFullLockedChecked() (*models.ClusterWafFilesRef, error) {
	wafFileRefFullBuilds.Add(1)
	ref := &models.ClusterWafFilesRef{}
	seen := false
	rulesDir := filepath.Join(crsLiveDir, "rules")
	if _, err := os.Stat(rulesDir); err == nil {
		sum, err := tarGzDirSum(crsLiveDir)
		if err != nil {
			return nil, fmt.Errorf("hash CRS tree: %w", err)
		}
		if sum != "" {
			ref.CRSSha256 = sum
			seen = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat CRS tree: %w", err)
	}
	crsVersion, ip2regionTag, err := readWafVersionLabels()
	if err != nil {
		return nil, err
	}
	ref.CRSVersion = crsVersion
	if sum, err := sha256File(ip2regionLivePath); err == nil && sum != "" {
		ref.IP2RegionSha = sum
		seen = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("hash IP2Region database: %w", err)
	}
	ref.IP2RegionTag = ip2regionTag
	threatFast, err := scanThreatFastFilesChecked()
	if err != nil {
		return nil, err
	}
	if len(threatFast) > 0 {
		ref.ThreatSha256s = threatFast
		seen = true
	}
	if !seen {
		return nil, nil
	}
	return ref, nil
}

func scanThreatFastFilesChecked() (map[string]string, error) {
	result := make(map[string]string)
	matches, err := filepath.Glob(filepath.Join(wafDir, "threat-*.iplist.fast"))
	if err != nil {
		return nil, fmt.Errorf("scan threat files: %w", err)
	}
	for _, path := range matches {
		source := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "threat-"), ".iplist.fast")
		if source == "" || !validThreatFileName(source) {
			continue
		}
		sum, err := sha256File(path)
		if err != nil {
			return nil, fmt.Errorf("hash threat file %s: %w", source, err)
		}
		if sum != "" {
			result[source] = sum
		}
	}
	return result, nil
}

// validThreatFileName 威胁库源名白名单（与内置三源单一对应，
// 协议合法输入不变；其余一律拒绝）。
func validThreatFileName(name string) bool {
	_, ok := db.CanonicalThreatSource(name)
	return ok
}

// scanThreatFastFiles 是 scanThreatFastFilesChecked 的静默容错形态
// （ 单源——此前两份 glob+白名单+哈希实现，后续修补易漏一侧）：
// 仅 wafFilesRefDiffers 消费，任一枚举/哈希失败按「不可判定」返回空映射，
// 使漂移判定成立（全量重拉，方向安全），不向比对路径上抛错误。
func scanThreatFastFiles() map[string]string {
	result, err := scanThreatFastFilesChecked()
	if err != nil || result == nil {
		return map[string]string{}
	}
	return result
}

// BuildWafFileBundle collects the live rule files with content; served by the
// on-demand endpoint, and never embedded in snapshots.
// 本函数是 WAF 数据文件读者——两个调用方（lbbak 导出
// buildLbbakExport / 集群按需端点 GetWafFiles）都曾在无锁下读 CRS 树/xdb/
// 威胁 .fast，与写者（CRS 树交换/威胁 .iplist 写编译/xdb 安装/lbbak 导入
// 直写）交错会打出半新半旧 bundle：lbbak manifest 的 sha256 按内存字节计算
// 自洽仍通过，还原后 WAF 静默降级。读取全程在 wafFileMu 互斥段内（与写侧
// 文件相位串行）；锁内不取 CaddyOpLock（写侧重载在锁外同口径；且一旦反向
// 嵌套 CaddyOpLock→wafFileMu 即与导入锁序构成 AB-BA）。
// 引用指纹不变时直接复用已物化 bundle（见 wafFileBundleCache）。
func BuildWafFileBundle() *WafFileBundle {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	bundle, _, _ := buildWafFileBundleLocked()
	return bundle
}

// BuildWafFileBundleInLockChecked 是锁内 bundle 物化的完整性显式变体
// 返回物化是否覆盖引用声明的全部组件。lbbak 导出必须消费
// 本变体——瞬时读失败（tar 打包/xdb 读取/威胁 .fast 读取）会产出「manifest
// 自洽但缺 CRS/xdb/威胁文件」的包，恢复时静默缺安全数据；集群按需端点因从端
// 有 wafFilesRefMatchesBundle 校验而安全，lbbak 侧没有同等校验。
// 契约：调用方必须先 WafFileLock().Lock()。
func BuildWafFileBundleInLockChecked() (*WafFileBundle, bool) {
	ref, err := buildWafFileRefLockedChecked()
	if err != nil {
		Logf("error", "WAF bundle: 引用构造读取失败: %v", err)
		return nil, false
	}
	if ref == nil {
		return nil, true // 无任何 WAF 组件可导出：不构成不完整
	}
	bundle, _, _ := buildWafFileBundleLocked()
	return bundle, bundle != nil && wafFileBundleComplete(ref, bundle)
}

// wafFilesRefDiffers reports whether the slave's live files fail to match
// any artifact referenced by the snapshot.
// rewriteVersionIfMissingOrStale 保证.version 与主节点声明的 tag 一致
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
	// 单源原子落盘（tmp+fsync+父目录 fsync）。
	return writeFileAtomicSynced(path, []byte(tag), 0644)
}

// wafFilesRefVersionLabelsDiffer 是「同步开关关闭」告警专用轻量比对：CRS 只读
// VERSION、ip2region 只读 .version，威胁库逐源读取紧凑的 .fast 并比对哈希
// （16B 头 + 5B/v4 的二进制布局，量级与三库源行相当），不打包整棵规则树。
// 该告警只回答「主节点安全数据是否已更新」，主端 ref 的版本标签与威胁哈希正取
// 自同一组文件——整树 tar.gz+sha256 对此没有增量信息，且持 WafFileLock 数十至
// 数百毫秒会与三库更新器/导入文件相位争锁。开关开启时的内容级漂移检测仍走
// wafFilesRefDiffers 的哈希口径。
// 威胁段不可省：同步开关关闭时仅威胁库更新也必须产生「同步警告」审计——
// 版本标签只覆盖 CRS/xdb，第三段被引用面（threat-*.iplist.fast）由
// threatFastFilesDiffer 单源承担。stat/mtime 签名跨节点复制后必然不同
// （从端文件由 bundle 重建），会把「内容一致」误报成更新，故用内容哈希。
func wafFilesRefVersionLabelsDiffer(r *models.ClusterWafFilesRef) bool {
	if r == nil {
		return false
	}
	WafFileLock().Lock()
	defer WafFileLock().Unlock()
	if r.CRSVersion != "" {
		version := ""
		if content, err := os.ReadFile(filepath.Join(crsLiveDir, "VERSION")); err == nil {
			version = strings.TrimSpace(string(content))
		}
		if version != r.CRSVersion {
			return true
		}
	}
	if r.IP2RegionTag != "" {
		tag := ""
		if content, err := os.ReadFile(ip2regionLivePath + ".version"); err == nil {
			tag = sanitizeBundleVersion(strings.TrimSpace(string(content)))
		}
		if tag != r.IP2RegionTag {
			return true
		}
	}
	return threatFastFilesDiffer(r.ThreatSha256s)
}

// threatFastFilesDiffer 逐源比对 ref 声明的 .fast 哈希与本地磁盘：两处比对
// （内容级 wafFilesRefDiffers 与「同步开关关闭」轻量告警）共用同一份判据——
// 此前轻量路径整段漏掉威胁面，而注释仍宣称「内容级检测仍在」。
// want 为空=主端未声明威胁面（旧主端/无威胁文件），不可判定，不判分叉。
// 调用方必须持 WafFileLock。
func threatFastFilesDiffer(want map[string]string) bool {
	if len(want) == 0 {
		return false
	}
	local := scanThreatFastFiles()
	if len(local) != len(want) {
		return true
	}
	for source, sum := range want {
		if local[source] != sum {
			return true
		}
	}
	return false
}

func wafFilesRefDiffers(r *models.ClusterWafFilesRef) bool {
	if r == nil {
		return false
	}
	// 与 BuildWafFileRef 同读面必须持同一把锁——此前本函数
	// 是无锁的第二份读实现，与 swapCRSTreeFromStaging（RemoveAll(rules)→moveTree）
	// 并发时可能读到混合代/半删目录，误判漂移触发全量重拉与错误日志。
	// 调用点（cluster_apply）不持 WafFileLock，锁为叶操作，无。
	WafFileLock().Lock()
	defer WafFileLock().Unlock()
	if r.CRSSha256 != "" {
		// 流式哈希(同 BuildWafFileRef)。
		if sum, err := tarGzDirSum(crsLiveDir); err != nil || sum != r.CRSSha256 {
			return true
		}
	}
	if r.IP2RegionSha != "" {
		// 读失败按哈希不符处理（触发重拉自愈，方向安全）。
		sum, err := sha256File(ip2regionLivePath)
		if err != nil || sum != r.IP2RegionSha {
			return true
		}
	}
	// 威胁库 .fast 也属于引用面：同步开关关闭时仅威胁库更新也必须产生
	// “同步警告”审计（判据单源于 threatFastFilesDiffer，与轻量告警共用）。
	return threatFastFilesDiffer(r.ThreatSha256s)
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
	// 威胁面交叉核验——ref 逐源声明的.fast 哈希必须与 bundle 携带
	// 内容**一一对应**：缺失、不符、bundle 多出未声明条目、同名重复条目都判
	// 不匹配（与 CRS/xdb 同纵深）。只做单向子集核对时，损坏/恶意主节点可额外
	// 塞入未由引用授权的源（Apply 会逐条落盘），或用同名第二条覆盖预期名单。
	if len(b.ThreatFiles) != len(r.ThreatSha256s) {
		return false
	}
	seen := make(map[string]struct{}, len(b.ThreatFiles))
	for _, tf := range b.ThreatFiles {
		if _, dup := seen[tf.Name]; dup {
			return false
		}
		seen[tf.Name] = struct{}{}
	}
	for source, want := range r.ThreatSha256s {
		matched := false
		for _, tf := range b.ThreatFiles {
			if tf.Name == source {
				if tf.Sha256 != want {
					return false
				}
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// ApplyWafFileBundle writes the bundle's files to disk when they differ from
// what is already live. It is idempotent: matching content is a no-op, so a
// re-sync without rule changes costs only a hash comparison.
// changed flags let callers report exactly which dataset was updated.
func ApplyWafFileBundle(bundle *WafFileBundle) (crsChanged, xdbChanged, threatChanged bool, err error) {
	if bundle == nil {
		return false, false, false, nil
	}
	// 反向防御——声明哈希非空但未携带内容(主端瞬态 IO 读失败
	// 时 BuildWafFileBundle 会产出该形状):从端应用「无操作」后漂移判定
	// 永不收敛,必须拒绝(主端恢复后下轮同步自愈)。
	//
	//  边界披露（有意设计，不修）：本函数只对「bundle 携带的组件」
	// 动作——主端引用缺席某组件（ref 无 CRS 哈希 / 无 xdb / 无威胁条目）时
	// 从端既有树/库**原样保留**，不以缺席表达删除。安全语义边界：主端组件
	// 缺失时其安全链因库缺失不渲染，而从端仍按旧树全量拦截——主从拦截面
	// 分叉（从端更严）。不构成漂移死循环：wafFilesRefDiffers 只比对非空分量。
	// 若要闭合需主端显式「已删除」标记（删除数据库是不可逆高风险管理动作，
	// 不以「ref 省略」隐式传播），威胁面已有显式 prune（pruneSyncedThreatFiles）
	// 走的是独立通道，不在此列。
	if bundle.CRSSha256 != "" && len(bundle.CRSTarGz) == 0 {
		return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("crs", errors.New("同步包声明 CRS 哈希非空但未携带内容，拒绝应用该同步包"))
	}
	if bundle.IP2RegionSha != "" && len(bundle.Xdb) == 0 {
		return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("xdb", errors.New("同步包声明 IP2Region 哈希非空但未携带内容，拒绝应用该同步包"))
	}
	// 威胁库条目先全量预检（结构/哈希/路径）：任何一条被拒都在落盘前中止，
	// 兑现错误文案的「拒绝整包」语义（CRS/xdb 尚未写入，等待主端下轮自愈）。
	threatWrites, planErr := planThreatFastWrites(bundle.ThreatFiles)
	if planErr != nil {
		return crsChanged, xdbChanged, threatChanged, planErr
	}
	if len(bundle.CRSTarGz) > 0 {
		// 声明哈希为空但携带内容：合法主节点 BuildWafFileBundle 恒成对设置，
		// 仅恶意/损坏主节点可构造——与 xdb 侧同纵深防御；untarGzTo 在
		// expectSum=="" 时跳过整树哈希校验，必须拒绝而非裸写未验证字节。
		if bundle.CRSSha256 == "" {
			return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("crs", errors.New("同步 CRS规则库缺少声明哈希，已拒绝落盘"))
		}
		liveSum, liveErr := tarGzDirSum(crsLiveDir)
		if liveErr != nil || liveSum != bundle.CRSSha256 {
			if err := untarGzTo(bundle.CRSTarGz, crsLiveDir, bundle.CRSSha256); err != nil {
				// 失败路径也可能已改写 live 树：入口 .sync-bak 自愈（树被回滚）
				// 或替换段的失败恢复都会换掉规则文件，规则数缓存必须同步失效，
				// 否则面板 rule_count 与实际树长期分叉到进程重启。
				InvalidateCRSRuleCount()
				return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("crs", fmt.Errorf("写入同步 CRS 规则文件: %w", err))
			}
			// VERSION 随 tar 包以原始字节落盘：不得以 TrimSpace 后的
			// bundle.CRSVersion 覆写——上游发布包的 VERSION 自带尾换行，主端
			// CRSSha256 基于原始字节计算，覆写会让本地 tar 哈希与已应用节哈希
			// 永久分叉，wafFilesDrifted 每轮误判漂移、全量重拉永不收敛。
			crsChanged = true
			// live CRS 树被带外替换——规则数缓存（/security/crs
			// 的 rule_count）必须失效，否则集群同步/备份导入后滞留旧值到进程
			// 重启或下一次成功更新。两通道（cluster_apply / lbbak 导入）都经
			// 本函数落盘，钩子收敛于此（含 crs 已落盘但 xdb 失败的半成功路径）。
			InvalidateCRSRuleCount()
		}
	}
	if len(bundle.Xdb) > 0 {
		// 声明哈希为空但携带内容：合法主节点 BuildWafFileBundle 恒成对设置，
		// 仅恶意/损坏主节点可构造——与 CRS 侧同纵深防御，拒绝整包而非
		// 裸写原始字节。
		if bundle.IP2RegionSha == "" {
			return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("xdb", errors.New("同步 IP2Region数据库缺少声明哈希，已拒绝落盘"))
		}
		// 读失败时 liveSum 为空串，恒不等于非空声明哈希（上方已拒
		// 空声明），落入重写路径——方向安全，与威胁分支同口径。
		liveSum, _ := sha256File(ip2regionLivePath)
		if liveSum != bundle.IP2RegionSha {
			sum := sha256.Sum256(bundle.Xdb)
			if got := hex.EncodeToString(sum[:]); got != bundle.IP2RegionSha {
				return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("xdb", fmt.Errorf("同步 IP2Region数据库哈希不匹配（声明 %s，实际 %s），已拒绝落盘", bundle.IP2RegionSha, got))
			}
			// 单源原子落盘（tmp+fsync+父目录 fsync；临时文件点前缀，
			// 不会被 waf bundle 打包）。
			if err := writeFileAtomicSynced(ip2regionLivePath, bundle.Xdb, 0644); err != nil {
				return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("xdb", fmt.Errorf("落盘同步 IP2Region数据库: %w", err))
			}
			xdbChanged = true
		}
		// xdb 未变化也要校验/补写.version——.version 丢失或写失败
		// 会让本地 ref 的 tag 为空，wafFilesDrifted 每轮误判漂移且全量重拉
		// 走不到本分支的自愈（重拉时 sha 相同），从节点永久假警报。
		// 补写必须晚于内容哈希校验——先写 sidecar 再验哈希会在
		// 拒绝路径留下「新标签 + 旧库」跨代偏斜。
		if tagErr := rewriteVersionIfMissingOrStale(ip2regionLivePath+".version", bundle.IP2RegionTag); tagErr != nil {
			return crsChanged, xdbChanged, threatChanged, newWafFileApplyError("xdb", fmt.Errorf("写入同步 IP2Region数据库版本标记: %w", tagErr))
		}
	}
	// RDB 文件化：从节点写威胁库 .fast 文件（直接使用，零编译）
	// 落盘阶段分两相位：全部暂存（写 temp+fsync，live 面不变）成功后才统一
	// rename。结构/哈希/路径校验已在 planThreatFastWrites 内完成，但落盘本身
	// 仍会失败（盘满/权限/IO 错）——旧的逐条「写一条生效一条」会让前序条目在
	// 后续失败时真实生效，与错误文案承诺的「拒绝整包」矛盾，主从威胁面就此
	// 分叉到下一次成功同步。
	staged := make([]*atomicfile.Staged, 0, len(threatWrites))
	for _, tw := range threatWrites {
		f, stageErr := wafBundleStage(tw.path, tw.content, 0644)
		if stageErr != nil {
			for _, prev := range staged {
				prev.Abort()
			}
			return crsChanged, xdbChanged, threatChanged, fmt.Errorf("暂存威胁库 .fast %s: %w", tw.name, stageErr)
		}
		staged = append(staged, f)
	}
	for i, tw := range threatWrites {
		// changed 标志先置后写——后续提交失败时函数整体携 error 返回，
		// 两个调用方（cluster_apply 的 aerr 分支 / lbbak 导入）err 路径均不
		// 消费 changed 标志，无需逐 err 路径置回。
		threatChanged = true
		if err := staged[i].Commit(); err != nil {
			return crsChanged, xdbChanged, threatChanged, fmt.Errorf("写威胁库 .fast %s: %w", tw.name, err)
		}
	}
	return crsChanged, xdbChanged, threatChanged, nil
}

// threatFastWrite 一条通过全部预检、内容与本地不同的威胁库 .fast 落盘项。
type threatFastWrite struct {
	name    string
	path    string
	content []byte
}

// wafBundleStage 威胁库 .fast 批量落盘的暂存原语（默认 atomicfile.Stage：
// 写 temp+fsync，不 rename）。测试注入第二份暂存失败，断言「live 面零改动」。
var wafBundleStage = atomicfile.Stage

// planThreatFastWrites 预检威胁库条目并产出待写项：名称白名单（仅三个内置源
// 名——含路径分隔符/`..`/绝对路径的 name 会逃出 wafDir）、重复名、空内容与
// 声明哈希的组合、声明哈希与内容哈希一致、目标路径不越界；本地内容一致者跳过
// （幂等）。全部通过后才允许进入落盘阶段。
//
// 预检必须先于任何落盘：逐条「校验→写入」时后续条目被拒会留下半更新的威胁库
// ——错误文案称「已拒绝整包」，实际前序条目已经生效。同名条目重复同理：逐条
// 落盘会让后一条覆盖前一条的预期名单（最终生效内容取决于条目顺序）；核验侧已
// 按「集合相等 + 名称唯一」拦下，但本函数还有 lbbak 导入/直连调用方。
func planThreatFastWrites(files []models.ThreatFileEntry) ([]threatFastWrite, error) {
	seen := make(map[string]struct{}, len(files))
	writes := make([]threatFastWrite, 0, len(files))
	for _, tf := range files {
		if !validThreatFileName(tf.Name) {
			return nil, fmt.Errorf("同步威胁库文件名非法 %q，已拒绝整包", tf.Name)
		}
		if _, dup := seen[tf.Name]; dup {
			return nil, fmt.Errorf("同步威胁库 %s 条目重复，已拒绝整包", tf.Name)
		}
		seen[tf.Name] = struct{}{}
		if len(tf.Content) == 0 {
			// 声明哈希非空 = 主端引用声称存在该文件（0 字节文件
			// 的 sha256 也非空），但包内无内容——从端若静默跳过则永不
			// 落盘、ref 哈希永不等，每轮误判漂移全量重拉永不收敛。与缺哈希
			// 同纵深：拒绝整包（主端恢复后下轮自愈）。
			if tf.Sha256 != "" {
				return nil, fmt.Errorf("同步威胁库 %s 内容为空但声明哈希非空，已拒绝整包", tf.Name)
			}
			continue // 无声明哈希的空条目=缺席，无可应用内容
		}
		// 声明哈希为空但携带内容：合法主节点 BuildWafFileBundle 恒成对设置，
		// 仅恶意/损坏主节点可构造——与 CRS/xdb 侧同纵深防御，
		// 拒绝整包而非裸写未验证字节。
		if tf.Sha256 == "" {
			return nil, fmt.Errorf("同步威胁库 %s 缺少声明哈希，已拒绝落盘", tf.Name)
		}
		// 落盘前内容哈希校验（与 xdb 分支同形）：不符说明 bundle
		// 在主端构造或传输途中被污染，拒绝落盘而非把脏字节装进威胁库。
		sum := sha256.Sum256(tf.Content)
		if got := hex.EncodeToString(sum[:]); got != tf.Sha256 {
			return nil, fmt.Errorf("同步威胁库 %s 哈希不匹配（声明 %s，实际 %s），已拒绝落盘", tf.Name, tf.Sha256, got)
		}
		fastPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist.fast", tf.Name))
		if clean := filepath.Clean(fastPath); !strings.HasPrefix(clean, filepath.Clean(wafDir)+string(filepath.Separator)) {
			return nil, fmt.Errorf("同步威胁库目标路径越界 %q，已拒绝整包", tf.Name)
		}
		// 读哈希失败按哈希不符处理走重写路径（方向安全）；文件缺失
		// 是新从节点常态不告警，其余读失败 warn 留痕。
		if liveSum, sumErr := sha256File(fastPath); sumErr != nil {
			if !errors.Is(sumErr, os.ErrNotExist) {
				Logf("warn", "威胁库 .fast %s 本地哈希读取失败（按哈希不符重写落盘）: %v", tf.Name, sumErr)
			}
		} else if liveSum == tf.Sha256 {
			continue // 哈希一致跳过
		}
		writes = append(writes, threatFastWrite{name: tf.Name, path: fastPath, content: tf.Content})
	}
	return writes, nil
}

// skipWafSyncTransient 判断相对路径是否为不得进入 waf 同步打包的瞬态文件
// 任意层级的点前缀路径（.staging/.sync-in/隐藏标记）与任一段 *.bak/*.old
// 后缀（CRS 更新器备份残树，正常已迁往 crs.transient 兄弟目录，此处兜底旧
// 版本残留/异常路径）。混入会让主从 tar 指纹按瞬态内容计算，两端永不对齐
// → 全量重拉死循环。
//
// 后缀必须逐段判定：目录形备份树（rules.bak/x.conf）的整串 rel 不以 .bak
// 结尾，只判整串会让打包收入该子树、而清残阶段按目录段命中整棵删除——同一
// 谓词在打包/清残两处语义不对称，最终哈希门恒拒（从节点 WAF 永不收敛）。
func skipWafSyncTransient(rel string) bool {
	// 逐段判断点前缀（.staging/crs.tar.gz 这类子文件此前漏过）与
	// *.bak/*.old 后缀（目录形 rules.bak/ 与文件形 conf.bak 一并覆盖）。
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if strings.HasPrefix(part, ".") {
			return true
		}
		if strings.HasSuffix(part, ".bak") || strings.HasSuffix(part, ".old") {
			return true
		}
	}
	return false
}

// removeTransientWafSyncPaths 删除 staging 树内的瞬态命名路径（与
// skipWafSyncTransient 同一谓词）：解包已拒绝包内瞬态条目，本函数只处理上一轮
// 清理失败残留——不剔除则它们会随整树落 live，既不受声明哈希约束、也不参与
// 后续漂移判定。
//
// 遍历失败（只读/权限异常的预置残骸）按「无法判定」跳过：残留目录本身会让
// 随后的整树哈希/复制失败（同步以错误收场），此处不得把错误提前改写成
// 「清理瞬态残留」而掩盖真实失败形态。
func removeTransientWafSyncPaths(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if !skipWafSyncTransient(filepath.ToSlash(rel)) {
			return nil
		}
		if d.IsDir() {
			if rmErr := os.RemoveAll(path); rmErr != nil {
				return rmErr
			}
			return filepath.SkipDir
		}
		return os.Remove(path)
	})
}

// tarGzDir deterministically archives dir (all contents, sorted, zeroed
// metadata) and returns the bytes plus their sha256.
func tarGzDir(dir string) ([]byte, string, error) {
	pr, pw := io.Pipe()
	go func() {
		gz := gzip.NewWriter(pw)
		tw := tar.NewWriter(gz)
		// 写侧改调共享 writeTarEntries(与 tarGzDirSum
		// 构造性一致)——此前内联拷贝靠双份代码维持字节级奇偶,单侧改动会
		// 静默破坏 bundle/ref 哈希校验且无自愈。
		if err := writeTarEntries(dir, tw); err != nil {
			tw.Close()
			gz.Close()
			pw.CloseWithError(err)
			return
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
// 流式哈希——与 tarGzDir 同一归档构造(同一 pipe 写
// 侧抽为共享闭包),但不经 io.ReadAll 物化整个 gzip 归档,边读边 sha,
// 消除每次快照重建(=每次 cluster_version 递增)数 MB 级堆分配。
func tarGzDirSum(dir string) (string, error) {
	writeArchive := func(pw *io.PipeWriter) {
		gz := gzip.NewWriter(pw)
		tw := tar.NewWriter(gz)
		// 写侧错误必须经 CloseWithError 传播——此前
		// 截断归档照常算哈希返回 err=nil(读侧只认 CloseWithError)。
		if err := writeTarEntries(dir, tw); err != nil {
			tw.Close()
			gz.Close()
			pw.CloseWithError(err)
			return
		}
		tw.Close()
		gz.Close()
		pw.Close()
	}
	pr, pw := io.Pipe()
	go writeArchive(pw)
	h := sha256.New()
	if _, err := io.Copy(h, pr); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeTarEntries 把 dir 下正式文件按排序后相对路径写入 tar(与 tarGzDir
// 同一构造, 抽共享);任一文件读写失败经返回 error 上抛。
func writeTarEntries(dir string, tw *tar.Writer) error {
	var paths []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if rel, relErr := filepath.Rel(dir, p); relErr == nil && skipWafSyncTransient(rel) {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return err
	}
	for i := range paths {
		paths[i], _ = filepath.Rel(dir, paths[i])
	}
	sort.Strings(paths)
	for _, rel := range paths {
		full := filepath.Join(dir, rel)
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, Mode: 0644, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// 解包上限：gzip 炸弹（压缩侧最多 64MB，可膨胀数 GB）必须在写放大发生前
// 拦截；正常 CRS 树远低于该值，超限必为损坏/篡改包。
const maxWafSyncExtractFiles = 2000 // 2000 文件数上限

// maxWafSyncExtractDirs 是解包目录条目数上限。tar 目录头固定 512B，64MB
// 压缩包可携带十余万条目录条目——无门时会在 staging 建出同等数量目录
// （元数据/inode 写放大）并让失败路径的 RemoveAll 遍历删除；正常 CRS 树目录
// 数远低于文件数，故取 2× 文件上限。
const maxWafSyncExtractDirs = 2 * maxWafSyncExtractFiles

// maxWafSyncExtractBytes 256MB 解包字节上限。var 以便测试缩小预算构造
// 恰好用尽的边界包，生产路径不修改。
var maxWafSyncExtractBytes int64 = 256 << 20

// untarGzTo extracts data into destDir atomically. When expectSum is
// non-empty, the re-archived staging tree must hash to it, or the sync is
// rejected before anything touches the live tree.
func untarGzTo(data []byte, destDir string, expectSum string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	staging := destDir + ".sync-in"
	backup := destDir + ".sync-bak"
	// 清理动作的错误不得静默（旧实现裸调用丢弃错误，只读/权限异常下残骸会
	// 累积）。此处只告警不放弃本轮：残留若与本轮解包合并，非瞬态内容会被
	// 整树哈希门拒绝，瞬态命名残留在落 live 前由 removeTransientWafSyncPaths
	// 剔除（解包本身已拒绝包内瞬态条目）——真正需要保持的是「残留可观测」，
	// 而不是以放弃一轮同步为代价。
	if err := os.RemoveAll(staging); err != nil {
		Logf("warn", "waf sync: 清理同步暂存目录 %s 失败（瞬态残留落 live 前会被剔除，非瞬态残留触发哈希门拒绝）: %v", staging, err)
	}
	// 入口残留自愈：成功路径在末尾删除 .sync-bak，故备份在场即上一次 apply
	// 没有走完（SIGKILL/掉电落在「备份→替换 live」窗口）。此时 live 可能缺失、
	// 为空，也可能是「非空的部分新树」——只看 live 空/缺失会漏掉后者：本轮
	// 随后把部分树覆盖成备份，好旧树被永久丢弃，失败恢复也只能恢复到部分树。
	// 判据：备份在场且（live 缺失/为空，或带声明哈希而 live 哈希不符/不可读）
	// → 按备份恢复旧树。声明哈希相符=上轮已完成、仅末尾清理失败，直接丢弃
	// 备份，不得把已同步的新树回滚成旧树。恢复成功后清备份，避免下一轮把健康
	// 树再次回滚（无声明哈希的调用方（测试/独立调用）保留「非空 live 不覆盖」
	// 的旧口径）。
	if _, statErr := os.Stat(backup); statErr == nil {
		// 完整性门：备份本身也可能是残缺的（拷贝中途 ENOSPC/EIO 留下的半份
		// 旧树）。残缺备份一律按「无备份」处理——用它写回 live 等于把健康旧树
		// 换成半份旧树，恢复方向反了。保留现场不动（下方替换段的陈旧备份清理
		// 会覆盖它），本轮照常 apply，成功即自愈。
		if !crsRulesTreeIntact(filepath.Join(backup, "rules")) {
			Logf("warn", "waf sync: 残留备份 %s 不完整（缺 %s 或 .conf 文件），拒绝以其恢复 live 树，按无备份继续本轮 apply", backup, crsRulesProbeFile)
		} else {
			restoreNeeded := wafTreeEmptyOrMissing(destDir)
			liveMatchesDeclared := false
			if !restoreNeeded && expectSum != "" {
				if sum, sumErr := tarGzDirSum(destDir); sumErr == nil && sum == expectSum {
					liveMatchesDeclared = true
				} else {
					restoreNeeded = true
				}
			}
			if restoreNeeded {
				// 恢复同样整树清空+复制 live——必须处于树交换窗口内（旧树恢复期间
				// live 可能为空/部分）。
				if rErr := withTreeSwapWindow(func() error {
					return restoreWafTreeFromBackup(backup, destDir)
				}); rErr != nil {
					return fmt.Errorf("按上次同步备份恢复崩溃窗口的规则树: %w", rErr)
				}
				if rmErr := os.RemoveAll(backup); rmErr != nil {
					Logf("warn", "waf sync: 恢复旧树后清理备份 %s 失败（下轮入口会再次判定）: %v", backup, rmErr)
				}
				Logf("warn", "waf sync: 上次同步中断残留备份（live 可能为空/部分新树），已按备份 %s 恢复旧树后继续本轮 apply", backup)
			} else if liveMatchesDeclared {
				if rmErr := os.RemoveAll(backup); rmErr != nil {
					Logf("warn", "waf sync: live 规则树已与声明哈希一致，但清理残留备份 %s 失败: %v", backup, rmErr)
				}
				Logf("warn", "waf sync: 上次同步已完成（live 哈希与声明一致），清理残留备份 %s 后继续本轮 apply", backup)
			}
		}
	}
	if err := os.MkdirAll(staging, 0755); err != nil {
		return err
	}
	// 兜底清理：任何错误路径（解包失败/哈希校验失败/备份失败）都不得遗留
	// staging 目录到下一周期；成功路径 rename 后 staging 已不存在，RemoveAll
	// 是空操作。清理失败只告警（入口已能自愈残留，不值得掩盖原始错误）。
	defer func() {
		if err := os.RemoveAll(staging); err != nil {
			Logf("warn", "waf sync: 清理同步暂存目录 %s 失败（下轮入口重试）: %v", staging, err)
		}
	}()
	var writtenBytes int64
	writtenFiles := 0
	dirEntries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// 目录条目在路径归一之前计数：带 "/" 结尾的名字会被下方 continue
		// 跳过（父目录由文件的 MkdirAll 创建），但恶意包仍可用不带 "/" 的
		// TypeDir 条目触发逐条 MkdirAll——写放大必须在落盘前拦截。
		if hdr.Typeflag == tar.TypeDir {
			dirEntries++
			if dirEntries > maxWafSyncExtractDirs {
				return fmt.Errorf("同步规则集目录条目数超过上限（%d 个），已拒绝落盘", maxWafSyncExtractDirs)
			}
		}
		rel := filepath.ToSlash(hdr.Name)
		if filepath.IsAbs(rel) || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") || rel == ".." {
			return fmt.Errorf("同步包含非法路径 %q", hdr.Name)
		}
		// 瞬态命名（点前缀任意段、*.bak/*.old）与打包侧同一谓词拒绝：打包/整树
		// 哈希/漂移判定都跳过这些路径，若允许解包写入，它们会进入 live 树却
		// 不参与声明哈希与漂移检测（完整性门覆盖集 ≠ 打包集）。coraza 的
		// Include glob 会匹配点前缀 .conf，等于绕开哈希门注入规则。
		if skipWafSyncTransient(rel) {
			return fmt.Errorf("同步包含瞬态路径 %q（点前缀/.bak/.old 不参与规则树同步），已拒绝落盘", hdr.Name)
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
			// 时溢出为负会绕过上限。
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
	// 失败路径的 staging 清理由入口 defer 负责（清理失败只告警）。
	// 先剔除瞬态残留：解包已拒绝包内瞬态条目，但上一轮 RemoveAll 失败留下的
	// 点前缀/*.bak/*.old 文件会被整树搬到 live——它们不参与 tarGzDir/hash 口径
	// （增量过滤），却在 live 里可被 Include glob 匹配。剔除后保证
	// 「哈希覆盖集 == 打包集 == live 集」。
	if err := removeTransientWafSyncPaths(staging); err != nil {
		return fmt.Errorf("清理同步暂存目录的瞬态残留: %w", err)
	}
	if expectSum != "" {
		sum, sumErr := tarGzDirSum(staging)
		if sumErr != nil {
			return fmt.Errorf("校验同步规则集: %w", sumErr)
		}
		if sum != expectSum {
			return fmt.Errorf("同步规则集哈希不匹配（声明 %s，实际 %s），已拒绝落盘", expectSum, sum)
		}
	}
	// Replace live tree: backup then swap (copy-based, overlayfs-safe like
	// the CRS updater itself).
	// 替换段（rename 尝试 / RemoveAll(destDir)+copyDir / 失败恢复）必须处于
	// CRS 树交换窗口内：这段会短暂移除 live 规则树或留下部分新树，渲染侧不持
	// wafFileMu（锁序禁止反取），只能靠窗口标记拒绝生成无安全链/弱规则集配置。
	// 备份拷贝本身不动 live，故窗口从替换前一刻开始（解包可能数秒，不进窗口）。
	leaveSwapWindow := enterCRSTreeSwapWindow()
	defer leaveSwapWindow()
	// 陈旧备份必须清掉：清理失败即放弃本轮，否则下方 copyDir(destDir, backup)
	// 会把旧残骸合并进备份，失败恢复时把陈旧文件带回 live 树（破坏「纯旧树」
	// 不变量）。
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("清理上次同步备份 %s: %w", backup, err)
	}
	_, destStatErr := os.Stat(destDir)
	destExisted := destStatErr == nil
	if destExisted {
		// 备份构造事务化（复用 CRS 更新器的 tmp 完整构建 → rename 语义）：
		// 拷贝中途失败（ENOSPC/EIO/EACCES）只会在 .sync-bak.tmp 留残树并被
		// 清理，绝不会留下「半份 .sync-bak」——下一轮入口会把它当权威旧树
		// 写回 live，把健康树换成半份旧树。失败时 live 原样保全。
		if err := copyDirTransactional(destDir, backup); err != nil {
			return fmt.Errorf("备份当前规则树 %s: %w", backup, err)
		}
	}
	if err := osRename(staging, destDir); err != nil {
		// rename 到非空目录恒失败（EEXIST/ENOTEMPTY）——destDir 非空（生产常态：
		// 镜像自带规则树或已同步过的树）时本兜底分支即主路径，而非罕见的跨挂载点
		// 情形。copyDir 只覆盖同名文件、不删除旧树中新包缺失的文件，必须先清空
		// destDir 再复制（对齐 crsinstall.go 安装前的显式 RemoveAll 语义），否则
		// CRS 更新删除/改名规则文件后从端树为旧+新合并、tarGzDirSum 永不等于
		// 声明哈希，漂移检测永不收敛。
		if err := os.RemoveAll(destDir); err != nil {
			// backup 已就绪，清空失败同样尽力恢复，与下方 copyDir
			// 失败分支恢复面对称；恢复错误并入返回，不吞掉。
			return fmt.Errorf("清空目标规则树: %w", errors.Join(err, restoreWafTreeFromBackup(backup, destDir)))
		}
		if err := copyDir(staging, destDir); err != nil {
			// 复制中途失败时 destDir 已被清空但可能残留部分新树文件——恢复自身的
			// 错误并入返回错误，不吞掉。首装（destDir 原本不存在）
			// 无备份可恢复，必须把部分新树整树删除回到「不存在」终态。
			restoreErr := restoreWafTreeFromBackup(backup, destDir)
			if !destExisted {
				restoreErr = errors.Join(restoreErr, os.RemoveAll(destDir))
			}
			return fmt.Errorf("安装同步规则集: %w", errors.Join(err, restoreErr))
		}
	}
	if err := os.RemoveAll(backup); err != nil {
		Logf("warn", "waf sync: 清理同步备份 %s 失败（新树已生效，残留下次入口覆盖）: %v", backup, err)
	}
	return nil
}

// wafTreeEmptyOrMissing 报告目录缺失或为空——「清空 live 后复制」崩溃窗口
// 的形态判据（untarGzTo 入口据此决定是否按 .sync-bak 恢复旧树）。
func wafTreeEmptyOrMissing(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err != nil || len(entries) == 0
}

// restoreWafTreeFromBackup 尽力从 backup 恢复 destDir：先整树清空再从备份复制，
// 保证恢复结果为纯旧树而非旧+新混合树（对齐 untarGzTo 的清空语义）。
// backup 不存在（备份时刻 destDir 不存在）时无可恢复对象，按空操作收尾；
// backup 残缺（拷贝中途失败遗留）时拒绝恢复并返回错误——先验完整性再删 live，
// 不得用半份备份覆盖 live（清空后才发现备份不可用会让 live 停在残缺态）。
func restoreWafTreeFromBackup(backup, destDir string) error {
	if _, statErr := os.Stat(backup); statErr != nil {
		return nil
	}
	if !crsRulesTreeIntact(filepath.Join(backup, "rules")) {
		return fmt.Errorf("从备份恢复旧树: 备份 %s 不完整（缺 %s 或 .conf 文件），已拒绝以残缺树覆盖 live", backup, crsRulesProbeFile)
	}
	if removeErr := os.RemoveAll(destDir); removeErr != nil {
		return fmt.Errorf("清空目标规则树以恢复旧树: %w", removeErr)
	}
	if restoreErr := copyDir(backup, destDir); restoreErr != nil {
		return fmt.Errorf("从备份恢复旧树: %w", restoreErr)
	}
	return nil
}

// fetchWafFiles pulls the full file bundle from the master's on-demand
// endpoint and verifies it against the snapshot reference before use.
func (s *SyncService) fetchWafFiles(ctx context.Context, ref *models.ClusterWafFilesRef) (*WafFileBundle, error) {
	// 64MB 规则包与快照同一条慢链路风险：客户端无总超时，本次拉取（含
	// 读 body 与解包前的上限探测）由独立截止兜底，避免无限悬挂。
	callCtx, cancel := newClusterTransferContext(ctx)
	defer cancel()
	var masterURL, token string
	if err := s.db.QueryRowContext(callCtx, `SELECT COALESCE(master_url,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&masterURL, &token); err != nil {
		return nil, fmt.Errorf("读取主节点地址: %w", err)
	}
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, strings.TrimRight(masterURL, "/")+"/api/v1/cluster/sync/waf-files", nil)
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
		// （无界写入），超长/非法字节 body 会膨胀审计库并产生乱码。
		// 复用 cluster_sync.go 的既有截断模式（:586-587）。
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		body = truncateValidUTF8Tail(body)
		return nil, fmt.Errorf("拉取安全数据失败(%d): %s", resp.StatusCode, string(body))
	}
	// 读 limit+1 字节探测超限——裸 LimitReader 截断后 JSON 解码只会
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
	// 直写审计详情与 VERSION/.version 落盘文件：形状校验后置空。
	bundle.CRSVersion = sanitizeBundleVersion(bundle.CRSVersion)
	bundle.IP2RegionTag = sanitizeBundleVersion(bundle.IP2RegionTag)
	return &bundle, nil
}

// maxWafBundleBodyBytes 是安全数据包（WafFileBundle JSON）响应体的硬上限：
// 正常 CRS tar.gz+xdb 远低于该值，超限必为主节点数据异常/滥用，整体拒绝
// 而非静默截断。
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

// SanitizeBundleVersion 是 sanitizeBundleVersion 的导出包装
// 备份导入(lbbak)路径与集群同步路径共用同一版本串形状校验——备份文件
// 同样是外部输入,超长/控制字符版本串不得直写 .version 伴生文件与审计详情。
func SanitizeBundleVersion(v string) string {
	return sanitizeBundleVersion(v)
}

// invalidateWafFileRefCache 清空「廉价签名 → 引用」缓存。活动路径整体切换后
// 必须调用：签名虽含两个绝对路径，但「同路径等长同 mtime 改写」与 mtime 精度
// 退化（秒级 FS）形态下新旧夹具可能命中同一签名，把上一夹具的 ref 带进下一个
// 用例（假绿/假红）。与 wafFileBundleCache 的隔离口径对齐。
func invalidateWafFileRefCache() {
	wafFileRefCache.mu.Lock()
	wafFileRefCache.valid = false
	wafFileRefCache.sig = ""
	wafFileRefCache.ref = nil
	wafFileRefCache.validatedAt = time.Time{}
	wafFileRefCache.mu.Unlock()
}

// OverrideWafLivePathsForTest 重定向 CRS/IP2Region 活动文件路径,仅测试使用
// (生产路径为容器内 /app/waf/crs 与 ip2regionLivePath;handlers 层打包/回放
// 测试无法访问包内 var,经此注入临时目录)。
// 切换（含还原）时同步失效 wafFileRefCache：缓存键含路径但不含内容，
// 跨夹具复用会给出假绿/假红（见 invalidateWafFileRefCache）。
func OverrideWafLivePathsForTest(crsDir, xdbPath string) (restore func()) {
	oldCrs, oldXdb := crsLiveDir, ip2regionLivePath
	crsLiveDir, ip2regionLivePath = crsDir, xdbPath
	invalidateWafFileRefCache()
	return func() {
		crsLiveDir, ip2regionLivePath = oldCrs, oldXdb
		invalidateWafFileRefCache()
	}
}
