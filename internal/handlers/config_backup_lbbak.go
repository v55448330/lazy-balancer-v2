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
	lbbakEntryManifest = "manifest.json"
	lbbakEntryConfig   = "config.json"
	lbbakEntryCRS      = "waf/crs.tar.gz"
	lbbakEntryXdb      = "waf/ip2region.xdb"
)

// buildLbbakPayload 组包:backupJSON 为已序列化的 V2 备份;bundle 为活动文件
// (nil 时 waf 条目缺席——全新安装未更新过规则库的形态)。
func buildLbbakPayload(backupJSON []byte, bundle *services.WafFileBundle) ([]byte, error) {
	entries := map[string][]byte{
		lbbakEntryConfig: backupJSON,
	}
	if bundle != nil {
		if len(bundle.CRSTarGzB64) > 0 {
			entries[lbbakEntryCRS] = bundle.CRSTarGzB64
		}
		if len(bundle.XdbB64) > 0 {
			entries[lbbakEntryXdb] = bundle.XdbB64
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
			return nil, fmt.Errorf("lbbak 条目数超过上限 %d(合法备份恒为 4 条)", maxLbbakEntryCount)
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
	return payload, nil
}

// applyLbbakWafFiles 落盘 waf 文件(sha 比对幂等);与集群同步落盘同构。
// R39-12:ip2regionTag 从备份表区传入——空 tag 会让 ApplyWafFileBundle 删除
// .version 伴生文件,破坏「文件与版本记录同批」不变量。
// R39-13:落盘失败返回警告文本(调用方注入响应 warnings),不再仅审计静默。
func applyLbbakWafFiles(c *gin.Context, payload *lbbakPayload, ip2regionTag string) string {
	if payload.CRSTarGz == nil && payload.Xdb == nil {
		return ""
	}
	bundle := &services.WafFileBundle{IP2RegionTag: ip2regionTag}
	if payload.CRSTarGz != nil {
		bundle.CRSSha256 = payload.CRSSha256
		bundle.CRSTarGzB64 = payload.CRSTarGz
	}
	if payload.Xdb != nil {
		bundle.IP2RegionSha = payload.XdbSha256
		bundle.XdbB64 = payload.Xdb
	}
	if crsChanged, xdbChanged, err := services.ApplyWafFileBundle(bundle); err != nil {
		services.Logf("error", "lbbak 导入落盘规则库文件失败: %v", err)
		recordAudit(c, "导入警告", "配置备份", "规则库文件落盘失败: "+err.Error())
		return "规则库文件落盘失败: " + err.Error()
	} else if crsChanged || xdbChanged {
		recordAudit(c, "导入", "安全数据", services.FormatAuditDetail("规则库数据库(随备份导入)", services.AuditResultPart("success")))
		// 完整更新流程(与自动更新器同款分阶段流水,来源=lbbak 备份)
		if xdbChanged {
			services.AppendIP2RegionUpdateLog("INFO", "installing", "校验并落盘备份内 IP2Region数据库")
			if err := services.Reload(); err != nil {
				services.Logf("error", "lbbak 导入后 ip2region 内存缓存热换失败(下次重启生效): %v", err)
			}
			services.RebuildRegionTreeCacheForSync()
			services.AppendIP2RegionUpdateLog("INFO", "success", "ip2region 已随备份导入更新")
		}
		if crsChanged {
			services.AppendCRSUpdateLog("INFO", "installing", "校验并落盘备份内 CRS 规则")
			services.AppendCRSUpdateLog("INFO", "reloading", "重载 Caddy 配置")
			services.AppendCRSUpdateLog("INFO", "success", "CRS 已随备份导入更新")
		}
	}
	return ""
}

// isLbbakRequest 按魔数识别 tar.gz 备份(gzip 0x1f 0x8b)。
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
