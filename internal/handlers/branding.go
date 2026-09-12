package handlers

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type brandingConfig struct {
	AppName     string `json:"app_name"`
	FooterText  string `json:"footer_text"`
	LandingText string `json:"landing_text"`
	Version     string `json:"version,omitempty"`
}

// defaultFooterText is the product footer rendered when branding.json is
// absent or its footer_text is empty; the GitHub link is appended only in
// this default rendering — a configured footer_text is rendered verbatim.
const defaultFooterText = "Lazy Balancer V2 · Copyright © 2026 XiaoBao"

// StartupBrandingLog 启动时(2026-09-11 裁定)在操作日志与系统日志记录品牌
// 配置载入状态:逐字段标注自定义值/默认,主从同路径(从节点文件=同步内容)。
func StartupBrandingLog(dataDir string) {
	cfg := loadBrandingConfig(dataDir)
	field := func(label, value, def string) string {
		if value == "" || value == def {
			return label + "：默认"
		}
		return label + "：自定义「" + value + "」"
	}
	detail := services.FormatAuditDetail(
		field("产品名", cfg.AppName, defaultBranding.AppName),
		field("页脚", cfg.FooterText, ""),
		field("空主机头文案", cfg.LandingText, ""),
		field("版本覆盖", cfg.Version, ""),
	)
	services.Logf("info", "启动：品牌配置载入完成（%s）", detail)
	services.RecordAuditLog("system", "载入", "品牌配置", detail, "")
}

// SyncDefaultLandingText 把 branding.json 的 landing_text(空/缺失回退
// services.DefaultLandingText)注入 services 的默认站点渲染。返回值表示
// 文案是否发生变化(调用方据此触发 Caddy 重渲染)。与 SeedDefaultBlockPage
// 同生命周期:boot 时 main 调用 + GetBranding 每次请求幂等同步。
func SyncDefaultLandingText(dataDir string) (bool, error) {
	cfg := loadBrandingConfig(dataDir)
	text := cfg.LandingText
	if text == "" {
		text = services.DefaultLandingText
	}
	if text == services.DefaultLandingBody() {
		return false, nil
	}
	services.SetDefaultLandingBody(text)
	return true, nil
}

var defaultBranding = brandingConfig{
	AppName:    "Lazy Balancer",
	FooterText: defaultFooterText,
}

// brandingStore 是进程内品牌配置的唯一快照:boot 后所有消费方从内存读取
// (标题/登录标题/页脚经 GET /branding;拦截页经 SeedDefaultBlockPage;
// 空主机头文案经 SyncDefaultLandingText;系统信息/备份导入同源)。每次
// 访问仅 stat 一次文件,mtime+size 变化才重读重解析——保留「修改即时
// 生效」语义的同时,稳态成本从每 GetBranding 请求 3 次全文读+JSON 解析
// 降为 3 次 stat。dataDir 入键:跨目录(测试隔离)不共享缓存。
var brandingStore = struct {
	mu      sync.RWMutex
	loaded  bool
	dataDir string
	cfg     brandingConfig
	modTime time.Time
	size    int64
}{}

// loadBrandingConfig returns the in-memory branding snapshot, transparently
// reloading when the file's mtime/size changed (or dataDir switched).
// Absent file or empty fields mean "use the default for that field";
// non-empty fields are rendered verbatim (never merged with defaults).
func loadBrandingConfig(dataDir string) brandingConfig {
	path := filepath.Join(dataDir, "branding.json")
	st, stErr := os.Stat(path)
	unchanged := func() bool {
		return brandingStore.loaded && brandingStore.dataDir == dataDir &&
			stErr == nil && st.Size() == brandingStore.size && st.ModTime().Equal(brandingStore.modTime)
	}
	brandingStore.mu.RLock()
	if unchanged() {
		cfg := brandingStore.cfg
		brandingStore.mu.RUnlock()
		return cfg
	}
	brandingStore.mu.RUnlock()

	brandingStore.mu.Lock()
	defer brandingStore.mu.Unlock()
	if unchanged() { // double-check:并发竞争下的另一个加载者已完成
		return brandingStore.cfg
	}
	prevLoaded := brandingStore.loaded
	prev := brandingStore.cfg
	cfg, ok := readBrandingFile(path)
	if !ok && prevLoaded && brandingStore.dataDir == dataDir {
		// 半截写/删除窗口(2026-09-11 裁定,限同一 dataDir):保内存上一份
		// 有效配置,不更新 stat 标记——文件恢复完整后下次访问立即重读收敛;
		// 跨目录的前值不属于本文件,不保(测试隔离即依赖此语义);boot 无
		// 前值时 ok=false 的 cfg(默认)照常入库。
		log.Printf("branding: 文件暂不可解析(半截写/缺失),保留上一份有效配置: %s", path)
		return prev
	}
	if prevLoaded && cfg != prev {
		// 热重载留痕(2026-09-11 裁定):仅实际变更记,内容未变(touch)与
		// boot 首载不记。系统日志+操作日志同口径。
		detail := brandingReloadDetail(prev, cfg)
		services.Logf("info", "品牌配置已热重载（%s）", detail)
		services.RecordAuditLog("system", "重载", "品牌配置", detail, "")
	}
	brandingStore.cfg = cfg
	brandingStore.loaded = true
	brandingStore.dataDir = dataDir
	if stErr == nil {
		brandingStore.modTime = st.ModTime()
		brandingStore.size = st.Size()
	} else {
		brandingStore.modTime = time.Time{}
		brandingStore.size = -1
	}
	return cfg
}

// brandingReloadDetail 生成热重载审计的逐字段旧→新摘要(仅列变化字段)。
func brandingReloadDetail(prev, next brandingConfig) string {
	field := func(label, o, n string) string {
		if o == n {
			return ""
		}
		show := func(v string) string {
			if v == "" {
				return "默认"
			}
			return "「" + v + "」"
		}
		return label + "：" + show(o) + "→" + show(n)
	}
	parts := []string{
		field("产品名", prev.AppName, next.AppName),
		field("页脚", prev.FooterText, next.FooterText),
		field("空主机头文案", prev.LandingText, next.LandingText),
		field("版本覆盖", prev.Version, next.Version),
	}
	filtered := parts[:0]
	for _, p := range parts {
		if p != "" {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == 0 {
		return "内容无实际变化"
	}
	return services.FormatAuditDetail(filtered...)
}

// readBrandingFile reads and parses branding.json with field-level fallback
// (2026-09-11 裁定):整体 JSON 非法 → 全字段默认;单字段类型错(如数字)
// → 仅该字段回退默认,其余字段正常生效。字段空值/null 由消费方按
// 「该字段用默认」语义处理。
// ok=false 表示文件缺失/不可读/整体 JSON 非法(调用方:boot 用默认 cfg,
// 热重载保旧值);字段级类型错不改变 ok=true(该字段回退默认,既有裁定)。
func readBrandingFile(path string) (brandingConfig, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("loadBrandingConfig: failed to read branding file %s, using defaults: %v", path, err)
		}
		return brandingConfig{AppName: defaultBranding.AppName}, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("loadBrandingConfig: invalid branding file %s, using defaults: %v", path, err)
		return brandingConfig{AppName: defaultBranding.AppName}, false
	}
	var cfg brandingConfig
	stringField := func(field string) string {
		val, ok := raw[field]
		if !ok {
			return ""
		}
		var s string
		if err := json.Unmarshal(val, &s); err != nil {
			log.Printf("loadBrandingConfig: field %s has invalid type in %s (want string), using default", field, path)
			return ""
		}
		return s
	}
	cfg.AppName = stringField("app_name")
	cfg.FooterText = stringField("footer_text")
	cfg.LandingText = stringField("landing_text")
	cfg.Version = stringField("version")
	if cfg.AppName == "" {
		cfg.AppName = defaultBranding.AppName
	}
	return cfg, true
}

// EnsureBrandingFile 启动时(Caddy 载入前)确保 branding.json 字段齐备
// (2026-09-11 裁定):
//   - 文件不存在 → 创建全字段模板(值全空,空值=用默认)
//   - 缺字段 → 补齐缺失字段(值为空),已有值与未知键原样保留
//   - 齐全 → 零写入(mtime 不动)
//   - 畸形 JSON → 不动(保守:不破坏用户数据;运行时按字段级回退并日志告警)
func EnsureBrandingFile(dataDir string) error {
	path := filepath.Join(dataDir, "branding.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		out, err := json.MarshalIndent(map[string]string{
			"app_name":     "",
			"footer_text":  "",
			"landing_text": "",
			"version":      "",
		}, "", "  ")
		if err != nil {
			return fmt.Errorf("序列化品牌配置模板: %w", err)
		}
		if err := os.WriteFile(path, out, 0644); err != nil {
			return fmt.Errorf("写入品牌配置模板: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("检查品牌配置文件: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// 畸形 JSON:不动文件,运行时字段级回退(readBrandingFile 已日志)
		return nil
	}
	changed := false
	for _, field := range []string{"app_name", "footer_text", "landing_text", "version"} {
		if _, ok := raw[field]; !ok {
			raw[field] = json.RawMessage(`""`)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化补齐后的品牌配置: %w", err)
	}
	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("写入补齐后的品牌配置: %w", err)
	}
	return nil
}

type brandingResponse struct {
	AppName            string `json:"app_name"`
	FooterText         string `json:"footer_text"`
	LandingText        string `json:"landing_text"`
	Version            string `json:"version"`
	FooterUsesDefault  bool   `json:"footer_uses_default"`
	LandingUsesDefault bool   `json:"landing_uses_default"`
}

func (h *Handlers) GetBranding(c *gin.Context) {
	cfg := loadBrandingConfig(h.cfg.DataDir)
	resp := brandingResponse{
		AppName:            cfg.AppName,
		FooterText:         cfg.FooterText,
		LandingText:        cfg.LandingText,
		FooterUsesDefault:  cfg.FooterText == "",
		LandingUsesDefault: cfg.LandingText == "",
	}
	if cfg.Version == "" {
		cfg.Version = h.cfg.Version
	}
	resp.Version = cfg.Version
	if resp.FooterUsesDefault {
		resp.FooterText = defaultFooterText
	}
	if resp.LandingUsesDefault {
		resp.LandingText = services.DefaultLandingText
	}
	// landing_text 变化时同步注入 services 渲染并触发 Caddy 重应用
	// (与 SeedDefaultBlockPage 同模式:主节点限定、异步、幂等)。
	needApply := false
	if changed, _ := SyncDefaultLandingText(h.cfg.DataDir); changed {
		needApply = true
	}
	if changed, _ := SeedDefaultBlockPage(h.cfg.DataDir); changed {
		needApply = true
	}
	// 品牌镜像(2026-09-11):文件变化时刷新 global_config.branding_json,
	// 触发器 bump cluster_version → 快照流向从节点。镜像变化本身不需要本地
	// Caddy 重载(本地渲染变化已由上方 Sync/Seed 的 needApply 覆盖)。
	if _, err := services.RefreshBrandingMirror(h.cfg.DataDir); err != nil {
		log.Printf("branding 镜像刷新失败: %v", err)
	}
	if needApply {
		go func() {
			var isMaster bool
			if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && !isMaster {
				return
			}
			if err := h.applyCaddyConfigE(); err != nil {
				log.Printf("branding 触发的 Caddy 配置应用失败: %v", err)
			}
		}()
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// renderDefaultBlockPage is the single renderer shared by GetDefaultBlockPage
// and SeedDefaultBlockPage so both produce the identical branded page.
func renderDefaultBlockPage(cfg brandingConfig) string {
	appName := html.EscapeString(cfg.AppName)
	footer := fmt.Sprintf(`Powered by <span class="name">%s</span>`, appName)
	if cfg.FooterText != "" {
		footer += "<br>" + blockPageFooterHTML(cfg.FooterText)
	} else {
		footer += "<br>" + html.EscapeString(defaultFooterText) + ` · <a href="https://github.com/v55448330/lazy-balancer-v2" target="_blank" rel="noopener noreferrer">GitHub</a>`
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied — %s</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f9fafb; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.card { background: #fff; border-radius: 12px; padding: 48px 40px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,.08); max-width: none; width: auto; margin: 0 4%%; flex: 1; }
.icon { font-size: 48px; margin-bottom: 16px; }
h1 { font-size: 24px; color: #1f2937; margin-bottom: 12px; }
p { font-size: 14px; color: #6b7280; line-height: 1.6; margin-bottom: 8px; }
.footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; }
.footer .name { font-weight: 600; color: #4b5563; }
.footer a { color: inherit; text-decoration: underline; text-decoration-color: #d1d5db; }
.footer a:hover { color: #4b5563; }
</style>
</head>
<body>
<div class="card">
<div class="icon">🚫</div>
<h1>Access Denied</h1>
<p>Your request has been blocked by the security policy.</p>
<p>If you believe this is an error, please contact the administrator.</p>
<div class="footer">%s</div>
</div>
</body>
</html>`, appName, footer)
}

// blockPageFooterHTML escapes the footer text and linkifies bare http(s) URLs,
// keeping user-controlled branding content inert in the block page.
func blockPageFooterHTML(text string) string {
	esc := strings.ReplaceAll(text, "&", "&amp;")
	esc = strings.ReplaceAll(esc, "<", "&lt;")
	esc = strings.ReplaceAll(esc, ">", "&gt;")
	esc = strings.ReplaceAll(esc, "\"", "&#34;")
	return urlLinkRe.ReplaceAllString(esc, `<a href="$0" target="_blank" rel="noopener noreferrer">$0</a>`)
}

var urlLinkRe = regexp.MustCompile(`https?://(?:[^\s"'&]|&amp;)+`)

// SeedDefaultBlockPage re-renders the default block page row (is_default=1) from
// branding.json. Idempotent: an unchanged render writes nothing (updated_at is
// not churned); custom pages are never touched.
func SeedDefaultBlockPage(dataDir string) (bool, error) {
	if db.DB == nil {
		return false, nil
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && !isMaster {
		// The default block page content is owned by the master and arrives on
		// slaves via cluster sync; branding.json is node-local, so re-rendering
		// here would overwrite the synced content with local defaults.
		return false, nil
	}
	content := renderDefaultBlockPage(loadBrandingConfig(dataDir))
	result, err := db.DB.Exec(`UPDATE security_block_pages SET content=?, updated_at=datetime('now') WHERE is_default=1 AND content != ?`, content, content)
	if err != nil {
		return false, fmt.Errorf("更新默认拦截页面内容: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

func (h *Handlers) GetDefaultBlockPage(c *gin.Context) {
	cfg := loadBrandingConfig(h.cfg.DataDir)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(renderDefaultBlockPage(cfg)))
}
