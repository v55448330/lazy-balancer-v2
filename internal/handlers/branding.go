package handlers

import (
	"encoding/json"
	"fmt"
	"html"
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
		services.Logf("info", "branding: 文件暂不可解析(半截写/缺失),保留上一份有效配置: %s", path)
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
	// R18-P5③:filtered 恒非空(调用点 cfg!=prev 蕴含 4 字段至少一个不等,
	// parts 全覆盖)——原「内容无实际变化」防御分支不可达已删;若未来加第
	// 5 字段须同步 parts,否则此处返回空 detail(编译期无守卫)。
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
			services.Logf("error", "loadBrandingConfig: failed to read branding file %s, using defaults: %v", path, err)
		}
		return brandingConfig{AppName: defaultBranding.AppName}, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		services.Logf("error", "loadBrandingConfig: invalid branding file %s, using defaults: %v", path, err)
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
			services.Logf("error", "loadBrandingConfig: field %s has invalid type in %s (want string), using default", field, path)
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
		services.Logf("error", "branding 镜像刷新失败: %v", err)
	}
	if needApply {
		go func() {
			var isMaster bool
			if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && !isMaster {
				return
			}
			if err := h.applyCaddyConfigE(); err != nil {
				services.Logf("error", "branding 触发的 Caddy 配置应用失败: %v", err)
			}
		}()
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// renderDefaultBlockPage renders the branded default block page; consumed by
// SeedDefaultBlockPage(种子默认拦截页)与预览路径。
func renderDefaultBlockPage(cfg brandingConfig) string {
	appName := html.EscapeString(cfg.AppName)
	footer := fmt.Sprintf(`Powered by <span class="name">%s</span>`, appName)
	if cfg.FooterText != "" {
		footer += "<br>" + blockPageFooterHTML(cfg.FooterText)
	} else {
		footer += "<br>" + html.EscapeString(defaultFooterText) + ` · <a href="https://github.com/v55448330/lazy-balancer-v2" target="_blank" rel="noopener noreferrer">GitHub</a>`
	}
	return renderBlockPageShell(cfg, blockPageSpecs["default"])
}

// renderBuiltinBlockPage 渲染内置备选拦截页（ratelimit/maintenance，2026-09-25
// 用户裁定：仅作模板供手动选用，无自动绑定）；未知变体返回空串——调用方拼写
// 漂移不得渲染出无语义页面。
func renderBuiltinBlockPage(cfg brandingConfig, variant string) string {
	spec, ok := blockPageSpecs[variant]
	if !ok {
		return ""
	}
	return renderBlockPageShell(cfg, spec)
}

// blockPageSpec 是内置拦截页的视觉/文案规格：三页共用同一浅色 v3 壳
// （2026-09-25 用户裁定），仅主题色/图标/胶囊/文案不同。
type blockPageSpec struct {
	accent     string // 发丝线主色 / 胶囊圆点
	accentSoft string // 发丝线两侧过渡色
	ringFrom   string // 徽章环渐变起（兼作胶囊底色）
	ringTo     string // 徽章环渐变止
	ringBorder string
	haloBorder string
	chipText   string
	chipBorder string
	iconSVG    string // 内联 SVG（stroke 已含主题色）
	chip       string
	title      string
	line1      string
	line2      string
}

var blockPageSpecs = map[string]blockPageSpec{
	"default": {
		accent: "#ef4444", accentSoft: "#f87171", ringFrom: "#fef2f2", ringTo: "#fee2e2",
		ringBorder: "#fecaca", haloBorder: "#fecdd3", chipText: "#b91c1c", chipBorder: "#fecaca",
		iconSVG: `<svg viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3z"/><line x1="9.5" y1="9.5" x2="14.5" y2="14.5"/><line x1="14.5" y1="9.5" x2="9.5" y2="14.5"/></svg>`,
		chip:    "403 Forbidden", title: "Access Denied",
		line1: `Your request has been blocked by the <strong>security policy</strong>.`,
		line2: "If you believe this is an error, please contact the administrator.",
	},
	"ratelimit": {
		accent: "#f59e0b", accentSoft: "#fbbf24", ringFrom: "#fffbeb", ringTo: "#fef3c7",
		ringBorder: "#fde68a", haloBorder: "#fcd34d", chipText: "#b45309", chipBorder: "#fde68a",
		iconSVG: `<svg viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15a8 8 0 1 1 16 0"/><path d="M12 15l4.5-4.5"/><circle cx="12" cy="15" r="1.4" fill="#d97706" stroke="none"/></svg>`,
		chip:    "429 Too Many Requests", title: "Too Many Requests",
		line1: "You have sent too many requests in a short time.",
		line2: "Please wait a moment and try again.",
	},
	"maintenance": {
		accent: "#3b82f6", accentSoft: "#60a5fa", ringFrom: "#eff6ff", ringTo: "#dbeafe",
		ringBorder: "#bfdbfe", haloBorder: "#93c5fd", chipText: "#1d4ed8", chipBorder: "#bfdbfe",
		iconSVG: `<svg viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4.2 4.2 0 0 0-5.8 5.8L4.6 16.4a1.5 1.5 0 0 0 0 2.1l.9.9a1.5 1.5 0 0 0 2.1 0l4.3-4.3a4.2 4.2 0 0 0 5.8-5.8l-2.6 2.6-2.1-2.1 2.6-2.6z"/></svg>`,
		chip:    "System Maintenance", title: "Under Maintenance",
		line1: "The service is temporarily unavailable while we perform maintenance.",
		line2: "Please check back soon.",
	},
}

// renderBlockPageShell 渲染浅色 v3 壳（2026-09-25 用户裁定：限宽 min(560px) 居中
// 卡片/渐变发丝线/双层环徽章/状态胶囊/环境光斑），单文件零外链——拦截即返回，
// 不得依赖外部资源。
func renderBlockPageShell(cfg brandingConfig, spec blockPageSpec) string {
	appName := html.EscapeString(cfg.AppName)
	footer := fmt.Sprintf(`Powered by <span class="name">%s</span>`, appName)
	if cfg.FooterText != "" {
		footer += "<br>" + blockPageFooterHTML(cfg.FooterText)
	} else {
		footer += "<br>" + html.EscapeString(defaultFooterText) + ` · <a href="https://github.com/v55448330/lazy-balancer-v2" target="_blank" rel="noopener noreferrer">GitHub</a>`
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s — %s</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(165deg, #f8fafc 0%%, #f1f5f9 45%%, #eef2f7 100%%); position: relative; overflow: hidden; }
.blob { position: absolute; border-radius: 50%%; filter: blur(70px); }
.blob-a { width: 380px; height: 380px; background: rgba(59,130,246,.10); top: -120px; right: -80px; }
.blob-b { width: 320px; height: 320px; background: rgba(244,63,94,.08); bottom: -110px; left: -70px; }
.card { position: relative; background: #fff; border-radius: 22px; padding: 52px 48px 34px; text-align: center; width: min(560px, calc(100vw - 40px)); box-shadow: 0 1px 2px rgba(16,24,40,.05), 0 12px 32px -8px rgba(16,24,40,.12), 0 32px 64px -16px rgba(16,24,40,.10); }
.card::before { content: ""; position: absolute; top: 0; left: 24px; right: 24px; height: 3px; border-radius: 0 0 4px 4px; background: linear-gradient(90deg, transparent, %s 18%%, %s 50%%, %s 82%%, transparent); }
.badge { position: relative; width: 84px; height: 84px; margin: 0 auto 20px; }
.badge-ring { position: absolute; inset: 0; border-radius: 24px; background: linear-gradient(145deg, %s, %s); border: 1px solid %s; box-shadow: 0 4px 12px -2px rgba(16,24,40,.12); }
.badge-halo { position: absolute; inset: -12px; border-radius: 32px; border: 1px dashed %s; }
.badge svg { position: absolute; inset: 0; margin: auto; width: 38px; height: 38px; }
.chip { display: inline-flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 600; letter-spacing: .6px; color: %s; background: %s; border: 1px solid %s; border-radius: 999px; padding: 5px 14px; margin-bottom: 16px; }
.chip::before { content: ""; width: 6px; height: 6px; border-radius: 50%%; background: %s; }
h1 { font-size: 28px; font-weight: 700; color: #0f172a; letter-spacing: .2px; margin-bottom: 14px; }
p { font-size: 14px; color: #64748b; line-height: 1.75; margin-bottom: 6px; }
p strong { color: #334155; font-weight: 600; }
.divider { margin: 26px auto 0; padding-top: 18px; width: 75%%; border-top: 1px solid #f1f5f9; font-size: 12px; color: #94a3b8; }
.divider .name { font-weight: 600; color: #475569; }
.divider a { color: inherit; text-decoration: underline; text-decoration-color: #cbd5e1; text-underline-offset: 2px; }
.divider a:hover { color: #475569; }
</style>
</head>
<body>
<div class="blob blob-a"></div>
<div class="blob blob-b"></div>
<div class="card">
<div class="badge">
<div class="badge-halo"></div>
<div class="badge-ring"></div>
%s
</div>
<div class="chip">%s</div>
<h1>%s</h1>
<p>%s</p>
<p>%s</p>
<div class="divider">%s</div>
</div>
</body>
</html>`, spec.title, appName,
		spec.accentSoft, spec.accent, spec.accentSoft,
		spec.ringFrom, spec.ringTo, spec.ringBorder, spec.haloBorder,
		spec.chipText, spec.ringFrom, spec.chipBorder, spec.accent,
		spec.iconSVG, spec.chip, spec.title, spec.line1, spec.line2, footer)
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
// branding.json，并对内置备选页（id 9001 限流/9002 维护，2026-09-25 用户裁定）
// 播种+自愈——内容漂移或 is_builtin 标志丢失（备份导入/带外改库形态）均归位
// 库存。Idempotent: an unchanged render writes nothing (updated_at is
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
	cfg := loadBrandingConfig(dataDir)
	content := renderDefaultBlockPage(cfg)
	result, err := db.DB.Exec(`UPDATE security_block_pages SET content=?, updated_at=datetime('now') WHERE is_default=1 AND content != ?`, content, content)
	if err != nil {
		return false, fmt.Errorf("更新默认拦截页面内容: %w", err)
	}
	n, _ := result.RowsAffected()
	changed := n > 0
	// 内置备选页：INSERT OR IGNORE 播种（新库/被删形态），漂移行重写归位——
	// 标志修复与内容库存同事完成，仅漂移时写（updated_at 不抖动）。
	for _, bp := range []struct {
		id      int
		name    string
		desc    string
		variant string
	}{
		{9001, "限流拦截页面", "系统内置 429 限流拦截页面（备选，手动选用后生效）", "ratelimit"},
		{9002, "系统维护页面", "系统内置维护页面（备选，手动选用后生效）", "maintenance"},
	} {
		stock := renderBuiltinBlockPage(cfg, bp.variant)
		if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, is_builtin, created_at, updated_at) VALUES (?, ?, ?, ?, FALSE, TRUE, datetime('now'), datetime('now'))`, bp.id, bp.name, bp.desc, stock); err != nil {
			return changed, fmt.Errorf("播种内置拦截页面 %d: %w", bp.id, err)
		}
		res, err := db.DB.Exec(`UPDATE security_block_pages SET name=?, description=?, content=?, is_builtin=1, updated_at=datetime('now') WHERE id=? AND (name != ? OR description != ? OR content != ? OR COALESCE(is_builtin,0) != 1)`,
			bp.name, bp.desc, stock, bp.id, bp.name, bp.desc, stock)
		if err != nil {
			return changed, fmt.Errorf("修复内置拦截页面 %d: %w", bp.id, err)
		}
		bn, _ := res.RowsAffected()
		changed = changed || bn > 0
	}
	return changed, nil
}
