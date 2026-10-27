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

	"lazy-balancer-v2/internal/db"
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

// validateLbbakExportEntries 在导出前套用 parseLbbak 的条目数、单条目与总解压
// 上限，禁止生成一个面板自身无法还原的 lbbak。遍历不分配第二份条目内容。
func validateLbbakExportEntries(entries map[string][]byte) error {
	if len(entries) > maxLbbakEntryCount {
		return fmt.Errorf("备份条目数超过可还原上限 %d", maxLbbakEntryCount)
	}
	var total int64
	for name, data := range entries {
		if int64(len(data)) > maxLbbakEntryBytes {
			return fmt.Errorf("备份条目 %s 超过可还原上限 %dMB", name, maxLbbakEntryBytes>>20)
		}
		total += int64(len(data))
		if total > maxLbbakTotalBytes {
			return fmt.Errorf("备份解压总字节超过可还原上限 %dMB", maxLbbakTotalBytes>>20)
		}
	}
	return nil
}

// snapshotLbbakThreatIplists 在 WafFileLock 内读取导出所需威胁名单原文，
// 之后组包/哈希/压缩可在锁外消费内存快照，避免长持锁。
func snapshotLbbakThreatIplists(bundle *services.WafFileBundle) (map[string][]byte, error) {
	if bundle == nil {
		return nil, nil
	}
	threatIplists := make(map[string][]byte, len(bundle.ThreatFiles))
	for _, tf := range bundle.ThreatFiles {
		data, err := services.ReadThreatIplistBySource(tf.Name)
		if err != nil {
			// 可 stat 但不可读/解析失败：静默缺件会让还原删除本地旧文件
			// 导出必须显式失败。
			return nil, fmt.Errorf("读取威胁名单 %s: %w", tf.Name, err)
		}
		threatIplists[tf.Name] = data
	}
	return threatIplists, nil
}

// 原 buildLbbakPayload（threatSnapshot 缺省的
// 组包快捷入口）生产零调用——生产导出一律 buildLbbakPayloadWithThreatIplists
// 传入 WafFileLock 内的内存快照。测试专用入口已移入 _test.go，避免生产文件
// 承载第二调用链。
func buildLbbakPayloadWithThreatIplists(backupJSON []byte, bundle *services.WafFileBundle, threatSnapshot map[string][]byte) ([]byte, error) {
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
	// RDB: 威胁库 .iplist 源文件。名单原文一律由调用方在 WafFileLock 内快照后
	// 传入；此处在锁外直读会与「先 WAF 锁、后组包」的锁序契约相反，且缺件
	// 静默少条目会让还原删除本地名单（运行态少拦）。
	if bundle != nil {
		for _, tf := range bundle.ThreatFiles {
			data, ok := threatSnapshot[tf.Name]
			if !ok {
				return nil, fmt.Errorf("威胁名单 %s 缺少内存快照（导出必须携带全部威胁文件原文）", tf.Name)
			}
			if len(data) > 0 {
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
	if err := validateLbbakExportEntries(entries); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	// 固定顺序:manifest 首位——产物字节确定性（同内容同序列），便于对账/
	// 复现；解析侧 parseLbbak 先读全部条目再逐条校验，并非流式校验。
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
	if int64(buf.Len()) > maxConfigImportBytes {
		return nil, fmt.Errorf("备份压缩包超过可还原上限 %dMB", maxConfigImportBytes>>20)
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
	// tar 内存在但 manifest 未登记 checksum 的
	// threat/*.iplist 条目——内容未经完整性校验。老备份兼容照常落盘，
	// 调用方在响应/审计侧告警。
	UnregisteredThreatEntries []string
}

// 解压放大防护:请求体上限只约束压缩字节(128MB,gzip 最高 ~1032:1
// 膨胀),条目数与总解压字节必须在读入内存前拦截——对齐仓内 untarGzTo 的
// maxWafSyncExtract* 同款标准。var 供测试收窄构造边界。
// 单条目上限提为 maxLbbakEntryBytes 单源——导出
// 预检（validateLbbakExportEntries）与解包（parseLbbak）共用同一上限，避免
// 两处字面量漂移让面板导出「自身无法还原」的包。
var (
	maxLbbakTotalBytes int64 = 256 << 20
	maxLbbakEntryBytes int64 = 64 << 20
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
		if hdr.Size > maxLbbakEntryBytes {
			return nil, fmt.Errorf("lbbak 条目 %s 超过 %dMB", hdr.Name, maxLbbakEntryBytes>>20)
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
	// manifest 逐条目 sha256 是 lbbak 的完整性承诺——
	// config.json / CRS / xdb 必须在 manifest 中登记后才可使用；此前只校验
	// 「已登记的条目」，手造 {"checksum":{}} 可让这三类核心载荷未经任何摘要
	// 校验即落库。威胁.iplist 的未登记形态保留既有兼容告警。
	for _, required := range []string{lbbakEntryConfig, lbbakEntryCRS, lbbakEntryXdb} {
		if _, exists := entries[required]; !exists {
			continue
		}
		if _, registered := manifest.Checksum[required]; !registered {
			return nil, fmt.Errorf("manifest 未登记条目 %s 的校验和(完整性校验缺失)", required)
		}
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
		if _, ok := db.CanonicalThreatSource(source); !ok {
			return nil, fmt.Errorf("lbbak 威胁库条目名非法: %s", name)
		}
		// manifest 未登记的条目未经 sha256 校验（合法导出恒登记全部
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

// reconcileImportedThreatFiles 威胁名单文件与还原后源表收敛
// 导出只为非空源写 .iplist 条目，而导入源表是全量替换——备份中「空/缺席」的源
// 不会覆盖本地旧文件，运行时 WAF 仍按旧名单拦截（DB 与执行面分叉）。此处按
// 导入后的源集合删除多余/空源文件；调用方必须已持 WafFileLock。
func reconcileImportedThreatFiles(tables map[string][]map[string]any, payload *lbbakPayload, failedSources []string) ([]string, bool) {
	rows, carried := tables["security_threat_sources"]
	if !carried || payload == nil {
		return nil, false // 表缺席=保留本地现状
	}
	failed := make(map[string]bool, len(failedSources))
	for _, source := range failedSources {
		failed[source] = true
	}
	kept := make(map[string]bool, len(rows))
	var warnings []string
	changed := false
	removePair := func(source, reason string) {
		for _, path := range []string{
			filepath.Join(services.WafDir(), "threat-"+source+".iplist"),
			filepath.Join(services.WafDir(), "threat-"+source+".iplist.fast"),
		} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				warnings = append(warnings, "删除威胁库 "+source+" 本地文件失败: "+err.Error())
			} else if err == nil {
				changed = true
			}
		}
		warnings = append(warnings, "威胁库 "+source+" "+reason)
	}
	for _, row := range rows {
		name := backupString(row["name"])
		if name == "" {
			continue
		}
		kept[name] = true
		if _, hasFile := payload.ThreatIplists[name]; hasFile || failed[name] {
			continue // 随包文件已落盘（失败源保留本地文件与记录）
		}
		// 导出侧只为已存在文件写条目，
		// 因此「备份未携带该源文件」有两种含义——上次下载成功但名单为空（备份
		// 记录 version 非空/update_status=success），或导出节点从未成功下载过该
		// 源（version 为空/idle）。两种形态都必须删除本地旧文件：DB 行已按备份
		// 全量替换，保留文件会让运行时 WAF 按旧名单拦截而 DB/UI 显示空
		// 的「记录与执行面恒一致」不变量）。差别只在留痕：未下载形态若
		// update_enabled=0 不会自动重取，必须给出可执行提示，不能笼统说「在备份
		// 中为空」。
		if backupString(row["update_status"]) == "success" || backupString(row["version"]) != "" {
			removePair(name, "在备份中为空（上次下载成功但无条目），已删除本地旧名单文件（记录按备份）")
			continue
		}
		removePair(name, "备份未携带该源文件（导出节点尚未成功下载），已删除本地旧名单文件——如该源需继续生效，请启用更新后手动触发一次威胁库更新")
	}
	// 源表全量替换后不再存在的源：本地残留文件同样删除。
	entries, err := os.ReadDir(services.WafDir())
	if err != nil {
		warnings = append(warnings, "扫描威胁库目录失败: "+err.Error())
		return warnings, changed
	}
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
		if source == "" || kept[source] || failed[source] {
			continue
		}
		if err := os.Remove(filepath.Join(services.WafDir(), name)); err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, "删除威胁库 "+source+" 本地文件失败: "+err.Error())
		} else if err == nil {
			changed = true
		}
	}
	return warnings, changed
}

// lbbakWafApplyResult 逐文件落盘结果：此前失败仅返回单条
// warning 且仍 commit，版本记录与文件分裂；现按文件/威胁源逐个记账，调用方
// 据此在事务内丢弃未落盘文件的版本记录并把逐源失败并入 responseWarnings。
type lbbakWafApplyResult struct {
	Warnings            []string
	FilesLanded         bool
	SecurityDataApplied bool
	FailedCRS           bool
	FailedXdb           bool
	FailedThreatSources []string
}

func (result *lbbakWafApplyResult) warn(c *gin.Context, action, message string) {
	result.Warnings = append(result.Warnings, message)
	recordAudit(c, action+"警告", "配置备份", message)
}

// validateLbbakXdbPayload 把待落盘 xdb 写到临时文件后用运行时同一条装载路径
// 验证：manifest sha256 只证明字节未损坏，不证明可装载。
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

// applyLbbakWafFilesInLock 落盘 waf 文件(sha 比对幂等);与集群同步落盘同构。
// ip2regionTag 从备份表区传入——空 tag 会让 ApplyWafFileBundle 删除
// .version 伴生文件,破坏「文件与版本记录同批」不变量。
// 逐文件结果返回（不再是单一 warning）——落盘失败的
// CRS/xdb 由调用方在事务内丢弃对应版本表、威胁库逐源失败并入响应告警；
// xdb 落盘前必须通过装载验证（坏文件拒绝并保留本地文件）。
// applyLbbakWafFilesInLock 在有 WAF 文件时要求调用方已持
// services.WafFileLock（导入核心在开启 DB 事务前取锁，与 CRS/威胁库更新器
// 的 WAF→DB 锁序一致，消除 DB tx→wafFileMu 的 AB-BA 反转）；不自锁，避免重入。
func applyLbbakWafFilesInLock(c *gin.Context, action string, payload *lbbakPayload, ip2regionTag string) lbbakWafApplyResult {
	var result lbbakWafApplyResult
	if payload.CRSTarGz == nil && payload.Xdb == nil && len(payload.ThreatIplists) == 0 {
		return result
	}
	threatFailed := map[string]struct{}{}
	threatLanded := false
	bundle := &services.WafFileBundle{IP2RegionTag: ip2regionTag}
	if payload.CRSTarGz != nil {
		bundle.CRSSha256 = payload.CRSSha256
		bundle.CRSTarGz = payload.CRSTarGz
	}
	if payload.Xdb != nil {
		// 可装载性验证先于落盘——坏 xdb 拒绝该条目并保留本地文件，
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
		if err := services.WriteThreatIplistCompiled(iplistPath, data); err != nil {
			fail("落盘/编译失败", err)
			continue
		}
		threatLanded = true
	}
	crsChanged, xdbChanged, _, err := services.ApplyWafFileBundle(bundle)
	result.FilesLanded = crsChanged || xdbChanged || threatLanded
	if err != nil {
		services.Logf("error", "lbbak 导入落盘规则库文件失败: %v", err)
		component := services.WafFileApplyComponent(err)
		switch component {
		case "crs":
			// CRS 阶段失败时 XDB 尚未执行；两者记录都不能指向备份版本。
			result.FailedCRS = payload.CRSTarGz != nil
			result.FailedXdb = payload.Xdb != nil
		case "xdb":
			// CRS 阶段已经完整返回：changed=false 仅表示 live 已一致，绝非失败。
			result.FailedXdb = true
		default:
			// 未知错误形态保守维持旧文件/记录同批语义。
			result.FailedCRS = payload.CRSTarGz != nil
			result.FailedXdb = payload.Xdb != nil
		}
		if result.FailedCRS {
			result.warn(c, action, "CRS 规则库文件落盘失败: "+err.Error()+"——CRS 版本记录已丢弃（记录与文件须同批）")
		}
		if result.FailedXdb {
			result.warn(c, action, "IP2Region 数据文件未成功应用: "+err.Error()+"——IP2Region 版本记录已丢弃（记录与文件须同批）")
		}
		if component == "xdb" && crsChanged {
			result.warn(c, action, "CRS 规则库文件已落盘并保留版本记录；仅 IP2Region 应用失败")
		}
		return result
	}
	crsApplied := payload.CRSTarGz != nil
	xdbApplied := payload.Xdb != nil && !result.FailedXdb
	if crsApplied || xdbApplied {
		result.SecurityDataApplied = true
		// 完整更新流程(与自动更新器同款分阶段流水,来源=lbbak 备份)
		if xdbApplied {
			if err := services.Reload(); err != nil {
				services.Logf("error", "lbbak 导入后 ip2region 内存缓存热换失败(下次重启生效): %v", err)
				// 热换失败必须对用户可见（磁盘与内存分裂，重启才收敛）。
				result.warn(c, action, "IP2Region 内存缓存热换失败（重启后生效）: "+err.Error())
			}
			services.RebuildRegionTreeCacheForSync()
		}
	}
	return result
}

// lbbakWafFileSnapshot 是 lbbak 导入落盘前的 WAF 文件快照。
//
// 导入必须在数据库事务提交之前把 CRS 整树/ip2region.xdb/威胁名单写到磁盘
// （commit 内的 Caddy 应用要读到新规则树）。导入失败或事务回滚时数据库回到
// 导入前状态，而文件不会自动回退——版本记录与文件分叉（记录指向旧库、磁盘
// 是新库，或反之）。快照在首次写入之前把将被修改的路径复制到临时目录，
// 回滚时逐项覆盖回导入前字节；导入成功即丢弃。
type lbbakWafFileSnapshot struct {
	// root 是临时快照根；空串=未创建或已丢弃。
	root string
	// CRS 整树：ApplyWafFileBundle 整树替换（含删除新包缺失的旧文件），
	// 因此只记录导入前是否存在，整树副本在 root/crs。
	crs        bool
	crsExisted bool
	// xdb 及其 .version 伴生标记：落盘会改写两者。存在但非普通文件（目录/
	// 设备等）时无法快照——ApplyWafFileBundle 对同形态的写入自身会显式
	// 失败，文件不会被替换，故记入告警并跳过回退，不中止导入。
	xdb                   bool
	xdbExisted            bool
	xdbSnapshotted        bool
	xdbVersionExists      bool
	xdbVersionSnapshotted bool
	// warnings 是快照阶段的显性说明（不可快照的现场等），随回退结论透出。
	warnings []string
	// 威胁名单 threat-<source>.iplist 与其 .fast：导入会写入成功源，并删除
	// 空/缺席/已删源的本地旧文件（落盘失败源保留本地）。回滚必须同时覆盖
	// 「旧文件被改」与「本次新增文件要删」两侧。
	threatNames map[string]struct{}
}

// newLbbakWafFileSnapshotDir 创建快照临时目录（测试注入已知目录）。
var newLbbakWafFileSnapshotDir = func() (string, error) {
	return os.MkdirTemp("", "lbbak-waf-snapshot-")
}

// snapshotLbbakWafTargets 在任何文件写入之前快照本次导入可能修改的 WAF 路径；
// 调用方必须已持 WafFileLock。payload 为 nil 表示本次导入不落 lbbak WAF 文件，
// threatFiles 标记威胁名单收敛是否会发生。返回 nil 表示无需回退（未写任何
// 文件）。快照失败必须中止导入——此时零写入，fail-closed 无副作用。
func snapshotLbbakWafTargets(payload *lbbakPayload, threatFiles bool) (*lbbakWafFileSnapshot, error) {
	snapshot := &lbbakWafFileSnapshot{
		crs:         payload != nil && payload.CRSTarGz != nil,
		xdb:         payload != nil && payload.Xdb != nil,
		threatNames: nil,
	}
	if threatFiles {
		snapshot.threatNames = map[string]struct{}{}
	}
	if !snapshot.crs && !snapshot.xdb && !threatFiles {
		return nil, nil
	}
	root, err := newLbbakWafFileSnapshotDir()
	if err != nil {
		return nil, fmt.Errorf("创建规则库文件快照目录: %w", err)
	}
	snapshot.root = root
	fail := func(err error) (*lbbakWafFileSnapshot, error) {
		snapshot.discard()
		return nil, err
	}
	if snapshot.crs {
		liveCRS := services.CRSLiveDir()
		switch _, statErr := os.Stat(liveCRS); {
		case statErr == nil:
			snapshot.crsExisted = true
			if err := copyWafTree(liveCRS, filepath.Join(root, "crs")); err != nil {
				return fail(fmt.Errorf("快照 CRS 规则树: %w", err))
			}
		case !errors.Is(statErr, os.ErrNotExist):
			return fail(fmt.Errorf("检查 CRS 规则树: %w", statErr))
		}
	}
	if snapshot.xdb {
		liveXdb := services.IP2RegionLivePath()
		existed, snapshotted, err := copyWafFileIfExists(liveXdb, filepath.Join(root, "ip2region.xdb"))
		if err != nil {
			return fail(fmt.Errorf("快照 IP2Region 数据文件: %w", err))
		}
		snapshot.xdbExisted, snapshot.xdbSnapshotted = existed, snapshotted
		if existed && !snapshotted {
			snapshot.warnings = append(snapshot.warnings, "导入前 IP2Region 数据文件路径不是普通文件，未纳入回退（该路径的写入本身会失败）")
		}
		versionExisted, versionSnapshotted, err := copyWafFileIfExists(liveXdb+".version", filepath.Join(root, "ip2region.xdb.version"))
		if err != nil {
			return fail(fmt.Errorf("快照 IP2Region 版本标记: %w", err))
		}
		snapshot.xdbVersionExists, snapshot.xdbVersionSnapshotted = versionExisted, versionSnapshotted
		if versionExisted && !versionSnapshotted {
			snapshot.warnings = append(snapshot.warnings, "导入前 IP2Region 版本标记路径不是普通文件，未纳入回退")
		}
	}
	if snapshot.threatNames != nil {
		wafDir := services.WafDir()
		names, notDir, err := listLbbakThreatFiles(wafDir)
		if err != nil {
			return fail(fmt.Errorf("扫描威胁名单目录: %w", err))
		}
		if notDir {
			snapshot.warnings = append(snapshot.warnings, "威胁名单目录路径不是目录，威胁名单未纳入回退（该路径下的写入本身会失败）")
		}
		if len(names) > 0 {
			if err := os.MkdirAll(filepath.Join(root, "threat"), 0o700); err != nil {
				return fail(fmt.Errorf("创建威胁名单快照目录: %w", err))
			}
		}
		for _, name := range names {
			if err := copyWafFilePlain(filepath.Join(wafDir, name), filepath.Join(root, "threat", name)); err != nil {
				return fail(fmt.Errorf("快照威胁名单 %s: %w", name, err))
			}
			snapshot.threatNames[name] = struct{}{}
		}
	}
	return snapshot, nil
}

// restore 把快照逐项覆盖回 WAF 活动路径。调用方必须已持 WafFileLock，且与
// 落盘同处 caddyOpMu 临界区（导入 abort 路径满足）。逐项尝试不因首错放弃
// （恢复面越完整越好）；err 非 nil=文件回退失败（文件与数据库可能分叉），
// warnings 承载「文件已回退但运行时内存面须重启收敛」等说明。
func (snapshot *lbbakWafFileSnapshot) restore() (warnings []string, err error) {
	if snapshot == nil || snapshot.root == "" {
		return nil, nil
	}
	var errs []error
	if snapshot.crs {
		// 先整树清空再复制快照：ApplyWafFileBundle 是整树替换语义（新包
		// 缺失的旧文件已被删），只覆盖同名文件会留下导入产物。
		liveCRS := services.CRSLiveDir()
		if err := os.RemoveAll(liveCRS); err != nil {
			errs = append(errs, fmt.Errorf("清空 CRS 规则树: %w", err))
		} else if snapshot.crsExisted {
			if err := copyWafTree(filepath.Join(snapshot.root, "crs"), liveCRS); err != nil {
				errs = append(errs, fmt.Errorf("恢复 CRS 规则树: %w", err))
			}
		}
		services.InvalidateCRSRuleCount()
	}
	if snapshot.xdb {
		liveXdb := services.IP2RegionLivePath()
		errs = append(errs,
			restoreWafFileFromSnapshot(filepath.Join(snapshot.root, "ip2region.xdb"), liveXdb, snapshot.xdbExisted, snapshot.xdbSnapshotted),
			restoreWafFileFromSnapshot(filepath.Join(snapshot.root, "ip2region.xdb.version"), liveXdb+".version", snapshot.xdbVersionExists, snapshot.xdbVersionSnapshotted),
		)
		// 落盘时已热换内存缓存；文件回退后必须同批回退内存，否则磁盘与
		// 运行时分裂（重启才收敛）。
		switch {
		case snapshot.xdbExisted && !snapshot.xdbSnapshotted:
			// 现场不可快照（非普通文件）：导入对该路径的写入本身失败，文件
			// 未被替换，内存也未被热换——无需回退，快照阶段已留告警。
		case !snapshot.xdbExisted:
			// 导入前无数据库：磁盘已回到「不存在」，但运行时无法卸载已装载
			// 的库——只能显性告知重启收敛，不能当作静默成功。
			warnings = append(warnings, "IP2Region 数据文件已回退为导入前的不存在状态——运行时内存缓存无法卸载导入的数据库，重启后与磁盘收敛")
		default:
			if err := services.Reload(); err != nil {
				errs = append(errs, fmt.Errorf("回退后热换 IP2Region 内存缓存失败（重启后生效）: %w", err))
			} else {
				services.RebuildRegionTreeCacheForSync()
			}
		}
	}
	if snapshot.threatNames != nil {
		wafDir := services.WafDir()
		current, notDir, err := listLbbakThreatFiles(wafDir)
		if err != nil {
			errs = append(errs, fmt.Errorf("扫描威胁名单目录: %w", err))
		}
		if notDir {
			// 路径不是目录：导入对该路径的写入本身失败，无导入产物可删、
			// 也无处写回快照；快照阶段已留告警。
			return warnings, errors.Join(errs...)
		}
		for _, name := range current {
			if _, existed := snapshot.threatNames[name]; existed {
				continue
			}
			// 本次导入新建的名单文件在导入前不存在——回滚即删除。
			if err := os.Remove(filepath.Join(wafDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("删除导入新增的威胁名单 %s: %w", name, err))
			}
		}
		for name := range snapshot.threatNames {
			// 快照内的威胁名单恒为普通文件（快照时复制成功才入集合）。
			errs = append(errs, restoreWafFileFromSnapshot(filepath.Join(snapshot.root, "threat", name), filepath.Join(wafDir, name), true, true))
		}
	}
	return warnings, errors.Join(errs...)
}

// discard 丢弃快照（导入成功后调用）。清理失败不改导入结论，仅留 warn。
func (snapshot *lbbakWafFileSnapshot) discard() {
	if snapshot == nil || snapshot.root == "" {
		return
	}
	root := snapshot.root
	snapshot.root = ""
	if err := os.RemoveAll(root); err != nil {
		services.Logf("warn", "lbbak 导入: 清理规则库文件快照失败（可手工删除 %s）: %v", root, err)
	}
}

// lbbakWafRollbackWarning 生成失败响应里的文件面提示（三态判决，结论不得超出
// 可断言范围）：
//   - 确定回滚 + 文件已回退成功 → 明确告知文件与数据库一致；
//   - 确定回滚 + 回退失败/未回退 → 显性告知文件与版本记录可能分裂（含原因）；
//   - 数据库提交结果不确定（Commit 报错）→ 文件保持导入后状态（不回退）：既
//     不断言一致也不断言分裂，给人工核对与收敛指引。
//
// 空串=无需提示（文件未落盘）。
func lbbakWafRollbackWarning(filesLanded, restoreAttempted bool, restoreErr error, commitIndeterminate bool) string {
	if !filesLanded {
		return ""
	}
	if commitIndeterminate {
		return "规则库文件已按备份落盘且保持导入后状态（未回退）——数据库提交结果不确定：若提交实际成功则文件与数据库一致，若实际未提交则文件与版本记录分叉，请核对规则库页版本后重新导入或触发规则库更新收敛"
	}
	switch {
	case restoreAttempted && restoreErr != nil:
		return "规则库文件已按备份落盘，数据库已回滚，但规则库文件回退失败: " + restoreErr.Error() + "——文件与版本记录可能分裂，请重新导入或触发规则库更新以收敛"
	case restoreAttempted:
		return "规则库文件已按备份落盘，数据库已回滚——规则库文件已回退到导入前状态（文件与版本记录一致）"
	}
	return "规则库文件已按备份落盘，但数据库已回滚——文件与版本记录可能分裂，请重新导入或触发规则库更新以收敛"
}

// listLbbakThreatFiles 列出 WAF 目录内的威胁名单文件（threat-*.iplist 与其
// .fast），与 reconcileImportedThreatFiles 同一前缀口径。目录不存在=无文件。
// notDir=true 表示该路径不是目录（损坏部署/夹具把 WAF 路径建成文件）：调用方
// 按「无文件可快照/收敛」降级并显式告警——该路径下的写入本身必然失败，不能
// 因此中止导入。
func listLbbakThreatFiles(dir string) (names []string, notDir bool, err error) {
	entries, readErr := os.ReadDir(dir)
	if readErr == nil {
		names = make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "threat-") {
				continue
			}
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		return names, false, nil
	}
	if errors.Is(readErr, os.ErrNotExist) {
		return nil, false, nil
	}
	// 目录可 stat 但读失败=真实错误（权限/IO）；路径本身不是目录（含中间
	// 组件是文件）按不可操作降级。
	if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
		return nil, false, readErr
	}
	return nil, true, nil
}

// restoreWafFileFromSnapshot 把快照字节原子写回 dst。existed=false 表示导入前
// 该路径不存在（恢复即删除导入产物）；existed=true 且 snapshotted=false 表示
// 导入前现场不是普通文件、未纳入快照（跳过，快照阶段已留告警）。
func restoreWafFileFromSnapshot(src, dst string, existed, snapshotted bool) error {
	if !existed {
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("删除导入新增文件 %s: %w", dst, err)
		}
		return nil
	}
	if !snapshotted {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("读取快照 %s: %w", src, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".lbbak-waf-restore-*")
	if err != nil {
		return fmt.Errorf("写回 %s: %w", dst, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写回 %s: %w", dst, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写回 %s: %w", dst, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("写回 %s: %w", dst, err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return fmt.Errorf("写回 %s: %w", dst, err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("恢复文件 %s: %w", dst, err)
	}
	return nil
}

// copyWafFileIfExists 复制普通文件，返回（是否存在、是否成功快照）。
// 存在但不是普通文件（目录/设备等）不是错误：调用方记告警并在回退时跳过——
// ApplyWafFileBundle 对同形态的写入自身会显式失败，文件不会被替换。
func copyWafFileIfExists(src, dst string) (existed, snapshotted bool, err error) {
	info, err := os.Stat(src)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if !info.Mode().IsRegular() {
		return true, false, nil
	}
	return true, true, copyWafFilePlain(src, dst)
}

// copyWafFilePlain 复制普通文件内容与权限位。
func copyWafFilePlain(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

// copyWafTree 递归复制目录树（普通文件与目录）。符号链接按目标字节复制
// （os.Stat 跟随，与 services.copyDir 同口径——CRS 树可能被部署成链接形态）；
// 设备/管道等不可快照形态显式失败而非静默丢文件。
func copyWafTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s 不是目录", src)
	}
	if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		// os.Stat 跟随符号链接：CRS 树内容可能被部署成链接形态，复制的是
		// 目标字节（与 services.copyDir 同口径）；设备/管道等不可快照形态
		// 显式失败而不是静默丢文件。
		entryInfo, err := os.Stat(srcPath)
		if err != nil {
			return err
		}
		switch {
		case entryInfo.IsDir():
			if err := copyWafTree(srcPath, dstPath); err != nil {
				return err
			}
		case entryInfo.Mode().IsRegular():
			if err := copyWafFilePlain(srcPath, dstPath); err != nil {
				return err
			}
		default:
			return fmt.Errorf("规则库快照不支持的文件类型: %s", srcPath)
		}
	}
	return nil
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

// 原 validateLbbakForImport 死包装(全仓零调用点)已删除——validate
// 端点直接使用 parseLbbak。
