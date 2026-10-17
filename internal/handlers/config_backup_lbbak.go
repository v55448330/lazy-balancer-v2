package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// v2.3.0 lbbak 备份格式(用户裁定):规则库数据库分类含 CRS/IP2Region 数据
// 文件本体,纯 JSON base64 不适合承载(14MB+ 膨胀)——导出为 tar.gz:
//
//	manifest.json      {"format":"lbbak","checksum":{entry:sha256}}
//	config.json        现有 V2 备份结构原样
//	waf/crs.tar.gz     CRS 规则目录打包(原始 tar.gz 字节)
//	waf/ip2region.xdb  xdb 原始字节
//
// 完整性:manifest 逐条目 sha256,导入先验后用;版本记录行在 config.json
// 的表区内,文件在 waf/ 下——分类原子,导入后记录与文件恒一致。
// v2.3.0 起导出恒为 lbbak(writeLbbakResponse 以 application/gzip 下发,
// apidocs.go 登记);waf 文件条目仅在勾选「安全防护」分类时随包附带,未勾选
// 时仅 config.json+manifest。旧式纯 JSON 备份的导入路径保持不变(向后兼容)。

type lbbakManifest struct {
	Format   string            `json:"format"`
	Checksum map[string]string `json:"checksum"`
}

const (
	lbbakEntryManifest     = "manifest.json"
	lbbakEntryConfig       = "config.json"
	lbbakEntryCRS          = "waf/crs.tar.gz"
	lbbakEntryXdb          = "waf/ip2region.xdb"
	lbbakEntryThreatPrefix = "threat/"
)

// buildLbbakPayload 组包:backupJSON 为已序列化的 V2 备份;bundle 为活动文件
// (nil 时 waf 条目缺席——全新安装未更新过规则库的形态)。
func buildLbbakPayload(backupJSON []byte, bundle *services.WafFileBundle) ([]byte, error) {
	entries := map[string][]byte{
		lbbakEntryConfig: backupJSON,
	}
	if bundle != nil {
		if len(bundle.CRSTarGz) > 0 {
			entries[lbbakEntryCRS] = bundle.CRSTarGz
		}
		if len(bundle.Xdb) > 0 {
			entries[lbbakEntryXdb] = bundle.Xdb
		}
	}
	// RDB: 威胁库 .iplist 源文件
	if bundle != nil {
		for _, tf := range bundle.ThreatFiles {
			if data := services.ReadThreatIplistBySource(tf.Name); len(data) > 0 {
				entries[lbbakEntryThreatPrefix+tf.Name+".iplist"] = data
			}
		}
	}
	manifest := lbbakManifest{Format: "lbbak", Checksum: map[string]string{}}
	for name, data := range entries {
		if name == lbbakEntryManifest {
			continue
		}
		sum := sha256.Sum256(data)
		manifest.Checksum[name] = hex.EncodeToString(sum[:])
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	entries[lbbakEntryManifest] = manifestJSON

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	// 固定顺序:manifest 首位便于流式校验
	for _, name := range []string{lbbakEntryManifest, lbbakEntryConfig, lbbakEntryCRS, lbbakEntryXdb} {
		data, exists := entries[name]
		if !exists {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	// RDB: 威胁库 .iplist 条目(源名排序保证产物确定性)
	threatNames := make([]string, 0, len(entries))
	for name := range entries {
		if strings.HasPrefix(name, lbbakEntryThreatPrefix) {
			threatNames = append(threatNames, name)
		}
	}
	sort.Strings(threatNames)
	for _, name := range threatNames {
		data := entries[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// parseLbbak 解包并逐条目校验 sha256;返回 config.json 原始字节与 waf 文件。
type lbbakPayload struct {
	ConfigJSON []byte
	CRSTarGz   []byte
	Xdb        []byte
	CRSSha256  string
	XdbSha256  string
	// RDB 文件化：威胁库 .iplist 源文件（源名→内容）
	ThreatIplists map[string][]byte
	// F-B1（第 66 轮审计）：tar 内存在但 manifest 未登记 checksum 的
	// threat/*.iplist 条目——内容未经完整性校验。老备份兼容照常落盘，
	// 调用方在响应/审计侧告警。
	UnregisteredThreatEntries []string
}

// 解压放大防护(BE-C1-1):请求体上限只约束压缩字节(48MB,gzip 最高 ~1032:1
// 膨胀),条目数与总解压字节必须在读入内存前拦截——对齐仓内 untarGzTo 的
// maxWafSyncExtract* 同款标准。var 供测试收窄构造边界。
var (
	maxLbbakTotalBytes int64 = 256 << 20
	maxLbbakEntryCount       = 64
)

func parseLbbak(raw []byte) (*lbbakPayload, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("lbbak 不是有效的 gzip/tar 包: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	entries := map[string][]byte{}
	entryCount := 0
	var totalBytes int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取 lbbak tar 条目: %w", err)
		}
		entryCount++
		if entryCount > maxLbbakEntryCount {
			return nil, fmt.Errorf("lbbak 条目数超过上限 %d(合法备份条目数随威胁源数变化（上限 64）)", maxLbbakEntryCount)
		}
		totalBytes += hdr.Size
		if totalBytes > maxLbbakTotalBytes {
			return nil, fmt.Errorf("lbbak 解压总字节超过上限 %dMB", maxLbbakTotalBytes>>20)
		}
		if hdr.Size > 64<<20 {
			return nil, fmt.Errorf("lbbak 条目 %s 超过 64MB", hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
		if err != nil {
			return nil, fmt.Errorf("读取 lbbak 条目 %s: %w", hdr.Name, err)
		}
		if int64(len(data)) != hdr.Size {
			return nil, fmt.Errorf("lbbak 条目 %s 不完整", hdr.Name)
		}
		entries[hdr.Name] = data
	}
	manifestRaw, ok := entries[lbbakEntryManifest]
	if !ok {
		return nil, errors.New("lbbak 缺少 manifest.json")
	}
	var manifest lbbakManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("lbbak manifest 解析失败: %w", err)
	}
	if manifest.Format != "lbbak" {
		return nil, fmt.Errorf("未知的备份格式 %q", manifest.Format)
	}
	for name, sum := range manifest.Checksum {
		data, exists := entries[name]
		if !exists {
			return nil, fmt.Errorf("备份缺少条目 %s(完整性校验失败)", name)
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != sum {
			return nil, fmt.Errorf("条目 %s 校验和不一致,备份可能已损坏", name)
		}
	}
	payload := &lbbakPayload{ConfigJSON: entries[lbbakEntryConfig]}
	if payload.ConfigJSON == nil {
		return nil, errors.New("lbbak 缺少 config.json")
	}
	if data, exists := entries[lbbakEntryCRS]; exists {
		payload.CRSTarGz = data
		payload.CRSSha256 = manifest.Checksum[lbbakEntryCRS]
	}
	if data, exists := entries[lbbakEntryXdb]; exists {
		payload.Xdb = data
		payload.XdbSha256 = manifest.Checksum[lbbakEntryXdb]
	}
	// RDB: 提取威胁库 .iplist 源文件
	manifestRegistered := func(name string) bool {
		_, ok := manifest.Checksum[name]
		return ok
	}
	for name, data := range entries {
		if !strings.HasPrefix(name, lbbakEntryThreatPrefix) || !strings.HasSuffix(name, ".iplist") {
			continue
		}
		source := strings.TrimSuffix(strings.TrimPrefix(name, lbbakEntryThreatPrefix), ".iplist")
		if source == "" || strings.Contains(source, "/") {
			return nil, fmt.Errorf("lbbak 威胁库条目名非法: %s", name)
		}
		// F-B1：manifest 未登记的条目未经 sha256 校验（合法导出恒登记全部
		// 条目）——老备份兼容照常携带，登记进告警面由调用方在响应/审计提示。
		if !manifestRegistered(name) {
			payload.UnregisteredThreatEntries = append(payload.UnregisteredThreatEntries, name)
		}
		if payload.ThreatIplists == nil {
			payload.ThreatIplists = map[string][]byte{}
		}
		payload.ThreatIplists[source] = data
	}
	if len(payload.UnregisteredThreatEntries) > 0 {
		sort.Strings(payload.UnregisteredThreatEntries)
	}
	return payload, nil
}

// lbbakWafApplyResult 逐文件落盘结果（L06-02/03/08）：此前失败仅返回单条
// warning 且仍 commit，版本记录与文件分裂；现按文件/威胁源逐个记账，调用方
// 据此在事务内丢弃未落盘文件的版本记录并把逐源失败并入 responseWarnings。
type lbbakWafApplyResult struct {
	Warnings            []string
	FilesLanded         bool
	CRSApplied          bool
	FailedCRS           bool
	FailedXdb           bool
	FailedThreatSources []string
}

func (result *lbbakWafApplyResult) warn(c *gin.Context, action, message string) {
	result.Warnings = append(result.Warnings, message)
	recordAudit(c, action+"警告", "配置备份", message)
}

// validateLbbakXdbPayload 把待落盘 xdb 写到临时文件后用运行时同一条装载路径
// 验证（L06-03）：manifest sha256 只证明字节未损坏，不证明可装载。
func validateLbbakXdbPayload(data []byte) error {
	tmp, err := os.CreateTemp("", "lbbak-xdb-*.xdb")
	if err != nil {
		return err
	}
	path := tmp.Name()
	defer os.Remove(path)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return services.ValidateIP2RegionFile(path)
}

// applyLbbakWafFiles 落盘 waf 文件(sha 比对幂等);与集群同步落盘同构。
// R39-12:ip2regionTag 从备份表区传入——空 tag 会让 ApplyWafFileBundle 删除
// .version 伴生文件,破坏「文件与版本记录同批」不变量。
// R39-13/L06-02/03/08:逐文件结果返回（不再是单一 warning）——落盘失败的
// CRS/xdb 由调用方在事务内丢弃对应版本表、威胁库逐源失败并入响应告警；
// xdb 落盘前必须通过装载验证（坏文件拒绝并保留本地文件）。
// L6-66-02：本函数是 WAF 数据文件写者（CRS 树交换/xdb/威胁 .iplist+.fast），
// 全文件相位持 services wafFileMu——与三库更新器串行（调用方已在
// caddyOpMu 内，wafFileMu 为叶锁不反向嵌套）。
func applyLbbakWafFiles(c *gin.Context, action string, payload *lbbakPayload, ip2regionTag string) lbbakWafApplyResult {
	var result lbbakWafApplyResult
	if payload.CRSTarGz == nil && payload.Xdb == nil && len(payload.ThreatIplists) == 0 {
		return result
	}
	services.WafFileLock().Lock()
	defer services.WafFileLock().Unlock()
	threatFailed := map[string]struct{}{}
	bundle := &services.WafFileBundle{IP2RegionTag: ip2regionTag}
	if payload.CRSTarGz != nil {
		bundle.CRSSha256 = payload.CRSSha256
		bundle.CRSTarGz = payload.CRSTarGz
	}
	if payload.Xdb != nil {
		// L06-03：可装载性验证先于落盘——坏 xdb 拒绝该条目并保留本地文件，
		// 版本记录由调用方同批丢弃（文件与记录恒一致）。
		if err := validateLbbakXdbPayload(payload.Xdb); err != nil {
			services.Logf("error", "lbbak 导入: IP2Region 数据文件无法装载，已拒绝落盘: %v", err)
			result.FailedXdb = true
			result.warn(c, action, "IP2Region 数据文件无法装载（"+err.Error()+"）——已拒绝该文件并保留本地文件；IP2Region 版本记录已丢弃（记录与文件须同批）")
		} else {
			bundle.IP2RegionSha = payload.XdbSha256
			bundle.Xdb = payload.Xdb
		}
	}
	// RDB: 威胁库 .iplist 落盘 + 编译 .fast（先于 CRS/Xdb 处理，失败仅警告不阻断）
	for source, data := range payload.ThreatIplists {
		if _, failed := threatFailed[source]; failed {
			continue
		}
		iplistPath := filepath.Join(services.WafDir(), "threat-"+source+".iplist")
		fail := func(stage string, err error) {
			threatFailed[source] = struct{}{}
			result.FailedThreatSources = append(result.FailedThreatSources, source)
			services.Logf("error", "lbbak 导入威胁库 %s: %s: %v", source, stage, err)
			result.warn(c, action, "威胁库 "+source+" "+stage+": "+err.Error()+"——该源保留本地文件与记录")
		}
		if err := os.MkdirAll(filepath.Dir(iplistPath), 0755); err != nil {
			fail("mkdir 失败", err)
			continue
		}
		if err := os.WriteFile(iplistPath, data, 0644); err != nil {
			fail("落盘失败", err)
			continue
		}
		if err := services.CompileFromIplistFile(iplistPath); err != nil {
			fail("编译失败", err)
			continue
		}
	}
	crsChanged, xdbChanged := false, false
	if _, _, _, err := services.ApplyWafFileBundle(bundle); err != nil {
		services.Logf("error", "lbbak 导入落盘规则库文件失败: %v", err)
		// 落盘失败：对应版本表必须由调用方丢弃（记录与文件同批语义）。
		if payload.CRSTarGz != nil {
			result.FailedCRS = true
		}
		if payload.Xdb != nil && !result.FailedXdb {
			result.FailedXdb = true
		}
		if result.FailedCRS {
			result.warn(c, action, "CRS 规则库文件落盘失败: "+err.Error()+"——CRS 版本记录已丢弃（记录与文件须同批）")
		}
		if !result.FailedCRS && result.FailedXdb {
			result.warn(c, action, "规则库文件落盘失败: "+err.Error()+"——IP2Region 版本记录已丢弃（记录与文件须同批）")
		}
		return result
	}
	// ApplyWafFileBundle 内部已判定变更；此处以「有携带即视为可能落盘」
	// 保守口径（变更判定不外泄——filesLanded 用于失败分裂警告，宁可多报）
	crsChanged = payload.CRSTarGz != nil
	xdbChanged = payload.Xdb != nil && !result.FailedXdb
	result.FilesLanded = true
	if crsChanged || xdbChanged {
		recordAudit(c, action, "安全数据", services.FormatAuditDetail("规则库数据库(随备份还原/导入)", services.AuditResultPart("success")))
		// 完整更新流程(与自动更新器同款分阶段流水,来源=lbbak 备份)
		if xdbChanged {
			if err := services.Reload(); err != nil {
				services.Logf("error", "lbbak 导入后 ip2region 内存缓存热换失败(下次重启生效): %v", err)
				// L06-03：热换失败必须对用户可见（磁盘与内存分裂，重启才收敛）。
				result.warn(c, action, "IP2Region 内存缓存热换失败（重启后生效）: "+err.Error())
			}
			services.RebuildRegionTreeCacheForSync()
		}
	}
	result.CRSApplied = crsChanged
	return result
}

// isLbbakBytes 按魔数识别 tar.gz 备份(gzip 0x1f 0x8b)。
func isLbbakBytes(body []byte) bool {
	return len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b
}

// writeLbbakResponse 导出响应(tar.gz 流)。
func writeLbbakResponse(c *gin.Context, payload []byte) {
	c.Header("Cache-Control", "no-store, private")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Disposition", "attachment; filename=lazy-balancer-backup-"+currentTimeFilename()+".lbbak")
	c.Data(http.StatusOK, "application/gzip", payload)
}

func currentTimeFilename() string {
	return time.Now().Format("20060102-150405")
}

// A40-2-F2:原 validateLbbakForImport 死包装(全仓零调用点)已删除——validate
// 端点直接使用 parseLbbak。
