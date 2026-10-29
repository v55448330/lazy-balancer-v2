package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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
	mu     sync.RWMutex
	loaded bool
	// stamp 是内存快照对应的文件形态（唯一变化判据，见 brandingFileStamp）。
	stamp brandingFileStamp
	cfg   brandingConfig
	// failedProbeAt 失败探测缓存时间戳：GetBranding 是公开无鉴权
	// 端点，文件缺失/半截写时每请求一次重读+日志是放大面——同一失败形态
	// 60s 内只探测/留痕一次（stat 成功但不可解析的形态由下方记录观测形态
	// 收敛：文件真正变化才重读）。
	failedProbeAt time.Time
}{}

// brandingFileStamp 是 branding.json 的唯一变化判据（dataDir + mtime + size）。
// 两处消费方共用它——内存快照热重载（brandingStore）与幂等同步门
// （brandingSyncGate）——此前各写一套 stat/指纹实现：改一侧判据另一侧不跟随，
// 且没有测试能发现（届时会出现「面板已显示新值、拦截页/落地文案未同步」）。
// statBrandingFile 是包内唯一 stat 点（守卫：TestBrandingFileChangeDetection_singleStatSource）。
type brandingFileStamp struct {
	dataDir string
	modTime time.Time
	size    int64
	statOK  bool
}

// statBrandingFile 观测 branding.json 当前形态（dataDir 入键：跨目录不共享缓存）。
func statBrandingFile(dataDir string) brandingFileStamp {
	stamp := brandingFileStamp{dataDir: dataDir}
	info, err := os.Stat(filepath.Join(dataDir, "branding.json"))
	if err != nil {
		return stamp
	}
	stamp.statOK = true
	stamp.modTime = info.ModTime()
	stamp.size = info.Size()
	return stamp
}

// sameOnDisk 报告两份观测是否指向同一份未变化的文件（跨 dataDir 恒 false；
// stat 失败的观测不参与比较——它没有可比对的文件形态）。
func (s brandingFileStamp) sameOnDisk(other brandingFileStamp) bool {
	return s.statOK && other.statOK && s.dataDir == other.dataDir &&
		s.size == other.size && s.modTime.Equal(other.modTime)
}

// fingerprint 返回内容指纹（dataDir+mtime+size）；stat 失败返回空串
// （调用方跳过本轮，下次重试）。
func (s brandingFileStamp) fingerprint() string {
	if !s.statOK {
		return ""
	}
	return fmt.Sprintf("%s\x00%d.%d", s.dataDir, s.modTime.UnixNano(), s.size)
}

// brandingFailureProbeWindow 失败探测/日志的限流窗口。
const brandingFailureProbeWindow = time.Minute

// loadBrandingConfig returns the in-memory branding snapshot, transparently
// reloading when the file's mtime/size changed (or dataDir switched).
// Absent file or empty fields mean "use the default for that field";
// non-empty fields are rendered verbatim (never merged with defaults).
func loadBrandingConfig(dataDir string) brandingConfig {
	path := filepath.Join(dataDir, "branding.json")
	stamp := statBrandingFile(dataDir)
	unchanged := func() bool {
		return brandingStore.loaded && brandingStore.stamp.sameOnDisk(stamp)
	}
	brandingStore.mu.RLock()
	if unchanged() {
		cfg := brandingStore.cfg
		brandingStore.mu.RUnlock()
		return cfg
	}
	// stat 失败（文件缺失/不可读）且近期已探测过失败 → 直接返回
	// last-known-good，不再每请求重读+记日志；文件恢复（stat 成功）即走
	// 慢路径立即收敛。
	if !stamp.statOK && brandingStore.loaded && brandingStore.stamp.dataDir == dataDir &&
		!brandingStore.failedProbeAt.IsZero() && time.Since(brandingStore.failedProbeAt) < brandingFailureProbeWindow {
		cfg := brandingStore.cfg
		brandingStore.mu.RUnlock()
		return cfg
	}
	brandingStore.mu.RUnlock()

	brandingStore.mu.Lock()
	if unchanged() { // double-check:并发竞争下的另一个加载者已完成
		brandingStore.mu.Unlock()
		return brandingStore.cfg
	}
	prevLoaded := brandingStore.loaded
	prev := brandingStore.cfg
	cfg, ok, readErr := readBrandingFile(path)
	if !ok && prevLoaded && brandingStore.stamp.dataDir == dataDir {
		// 半截写/删除窗口(2026-09-11 裁定,限同一 dataDir):保内存上一份
		// 有效配置;跨目录的前值不属于本文件,不保(测试隔离即依赖此语义);
		// boot 无前值时 ok=false 的 cfg(默认)照常入库。
		// stat 成功但不可解析时必须记录这次观测到的形态:文件内容没再变化就
		// 不该每请求重读全文+重解析（公开无鉴权端点，每请求 3 次 loadBrandingConfig）；
		// 文件真正修复时 mtime/size 变化，unchanged() 立刻失效并重读收敛。
		// stat 失败的形态没有可比对的形态，仍靠 failedProbeAt 窗口限流。
		if stamp.statOK {
			brandingStore.stamp = stamp
		}
		// 失败日志 60s 限流（公开端点每请求一条是放大面；lookup 失败
		// 原因仅窗口内记一次，同一形态重复无新增信息）。
		if brandingStore.failedProbeAt.IsZero() || time.Since(brandingStore.failedProbeAt) >= brandingFailureProbeWindow {
			brandingStore.failedProbeAt = time.Now()
			if readErr != nil {
				services.Logf("warn", "branding: 文件暂不可解析(半截写/缺失),保留上一份有效配置: %s: %v", path, readErr)
			} else {
				services.Logf("warn", "branding: 文件暂不可解析(半截写/缺失),保留上一份有效配置: %s", path)
			}
		}
		brandingStore.mu.Unlock()
		return prev
	}
	if !ok && readErr != nil && !prevLoaded {
		// boot 首载（无前值）：一次性留痕（不是每请求路径）。
		services.Logf("error", "branding: 载入品牌配置失败，使用默认值: %s: %v", path, readErr)
	}
	// 热重载留痕(2026-09-11 裁定):仅实际变更记,内容未变(touch)与
	// boot 首载不记。系统日志+操作日志同口径。
	// 留痕本身（尤其审计的同步 INSERT）必须在解锁后执行：本函数是进程级
	// 单写锁，锁内做 DB 写会让公开 GET /branding 在审计库慢写时阻塞全部
	// branding 读者（/system/info、拦截页播种同族）。锁内只做
	// stat+读文件+解析+替换快照，锁外写留痕。
	reloadDetail := ""
	if prevLoaded && cfg != prev {
		reloadDetail = brandingReloadDetail(prev, cfg)
	}
	brandingStore.cfg = cfg
	brandingStore.loaded = true
	brandingStore.stamp = stamp
	if ok {
		// 成功读取即清失败探测标记：下一轮失败重新计时/留痕。
		brandingStore.failedProbeAt = time.Time{}
	}
	brandingStore.mu.Unlock()

	if reloadDetail != "" {
		if brandingReloadAuditHook != nil {
			brandingReloadAuditHook()
		}
		services.Logf("info", "品牌配置已热重载（%s）", reloadDetail)
		services.RecordAuditLog("system", "重载", "品牌配置", reloadDetail, "")
	}
	return cfg
}

// brandingReloadAuditHook 测试屏障（生产恒 nil）：在热重载留痕（锁外）开始
// 处触发，供并发测试证明审计写不持有 brandingStore 写锁。
var brandingReloadAuditHook func()

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
	// filtered 恒非空(调用点 cfg!=prev 蕴含 4 字段至少一个不等,
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
// 失败原因经 readErr 上抛，由调用方按 60s 窗口限流留痕（原此处
// 每请求 error 日志——公开 GetBranding 端点的日志放大面）。
func readBrandingFile(path string) (brandingConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return brandingConfig{AppName: defaultBranding.AppName}, false, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return brandingConfig{AppName: defaultBranding.AppName}, false, err
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
	return cfg, true, nil
}

// EnsureBrandingFile 启动时(Caddy 载入前)确保 branding.json 字段齐备
// (2026-09-11 裁定):
//   - 文件不存在 → 创建全字段模板(值全空,空值=用默认)
//   - 缺字段 → 补齐缺失字段(值为空),已有值与未知键原样保留
//   - 齐全 → 零写入(mtime 不动)
//   - 畸形 JSON → 不动(保守:不破坏用户数据;运行时按字段级回退并日志告警)
//
// 落盘统一走 services.MaterializeBranding 原子写（tmp+fsync+rename+父目录
// fsync，此前 os.WriteFile 直写，进程崩溃可留半截 branding.json）。
//
// 注意：本函数只保证文件字段齐备。写入分支经 services.MaterializeBranding
// 落盘时顺带按内容注入 landing 文案；但「文件已齐备」分支零写入、零注入——
// 调用方不得假定本函数已完成 landing 注入，须随后调用
// SyncDefaultLandingText / SeedDefaultBlockPage（启动装配
// cmd/server/main.go 即该顺序）。单点调用者漏掉这两步就会出现「文件齐备但
// 默认站点文案未生效」。
func EnsureBrandingFile(dataDir string) error {
	path := filepath.Join(dataDir, "branding.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if _, err := services.MaterializeBranding(dataDir, ""); err != nil {
			return fmt.Errorf("写入品牌配置模板: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("检查品牌配置文件: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// 畸形 JSON:不动文件,运行时字段级回退（error 由 loadBrandingConfig
		// 首载时记录——本函数自身不做字段级解析，不产生日志）。
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
	if _, err := services.MaterializeBranding(dataDir, string(out)); err != nil {
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

// brandingSyncGate 60s 采样门：GetBranding 是公开
// 无鉴权端点，幂等同步/种子/镜像每请求 ~7 条 SQL 是残余放大面——boot+首请求
// 已完成播种，门内跳过仅推迟带外变更 ≤60s 可见。branding.json 为手工编辑/
// 集群同步文件，无管理面写路径（因此无需写侧主动失效）；内容热重载由 stat
// 即时检测，仅幂等同步（landing 注入/拦截页种子/镜像）受本 60s 门约束。
// 指纹取自 statBrandingFile（与 brandingStore 同一判据，见 brandingFileStamp）。
var (
	brandingSyncMu          sync.Mutex
	brandingSyncLast        time.Time
	brandingSyncDataDir     string
	brandingSyncFingerprint string
)

// brandingSyncGateAllow 判定本轮是否需要跑幂等写副作用（landing 注入/拦截页
// 种子/镜像刷新）。两道门串联：
//  1. 内容指纹门：branding.json 未变化即完全跳过——稳态下匿名 GET /branding
//     零写（旧实现仅 60s 时间门，每分钟仍无条件跑一轮 ~7 条 SQL，多副本时每个
//     副本各跑一份）；
//  2. 60s 采样门：指纹变化后最多每 60s 处理一次（连续编辑合并；手工编辑最坏
//     延迟 60s 可见，与该端点的既有语义一致）。
//
// 写入仍保持幂等：指纹只记「本轮已处理」，失败时由调用方 brandingSyncMarkFailed
// 清空，下一轮（≥60s）重试。
func brandingSyncGateAllow(dataDir string) bool {
	fingerprint := statBrandingFile(dataDir).fingerprint()
	if fingerprint == "" {
		return false
	}
	brandingSyncMu.Lock()
	defer brandingSyncMu.Unlock()
	// dataDir 入键（与 brandingStore 的 dataDir 键控同构）：同进程切换数据目录
	// （测试隔离/多实例形态）时，前一个目录的指纹与 60s 采样窗不得吞掉新目录
	// 的首轮同步。
	if dataDir != brandingSyncDataDir {
		brandingSyncDataDir = dataDir
		brandingSyncLast = time.Time{}
		brandingSyncFingerprint = ""
	}
	if fingerprint == brandingSyncFingerprint {
		return false
	}
	if !brandingSyncLast.IsZero() && time.Since(brandingSyncLast) < time.Minute {
		return false
	}
	brandingSyncLast = time.Now()
	brandingSyncFingerprint = fingerprint
	return true
}

// brandingSyncMarkFailed 清空已处理指纹：本轮写副作用失败时不得把失败当成
// 「已处理」固化（否则文件不再变化就不再重试）。
func brandingSyncMarkFailed() {
	brandingSyncMu.Lock()
	brandingSyncFingerprint = ""
	brandingSyncMu.Unlock()
}

// brandingApplyPending 记录「幂等同步已把库内渲染输入改掉，但 Caddy 应用尚未
// 成功」的待办。同步本身幂等且已落库，重试轮 Sync/Seed 会返回 changed=false，
// 即 needApply=false——只靠 needApply 判定时应用失败的重试永远不会发生。
// 应用成功后清位；从节点不在本地应用，同样清位（不记待办、不反复重试）。
var brandingApplyPending atomic.Bool

// brandingApplyAfterSync 在幂等同步/播种/镜像已完成且有渲染输入变化时，主节点
// 限定地重应用 Caddy 配置（异步，与 SeedDefaultBlockPage 同模式）。应用侧失败
// 必须清指纹并记待办（见 brandingSyncMarkFailed）：本轮放行时指纹已记为
// 「已处理」，不释放则失败被固化成终态——Caddy 继续跑旧文案/旧拦截页，直到
// 有人手工重载或再次改文件。清指纹只放开指纹门，60s 采样窗仍在，公开端点不会
// 被刷成每请求 /load。从节点正常跳过不是失败，不清指纹也不记待办。
func (h *Handlers) brandingApplyAfterSync() {
	isMaster, roleErr := services.RoleOf(context.Background(), db.DB)
	if roleErr != nil {
		// 角色读失败不得按主节点继续写
		// ——公开 GET 触发的异步重应用在从节点上会造成本地 /load 漂移。
		services.Logf("warn", "branding：读取节点角色失败，跳过本地 Caddy 重应用: %v", roleErr)
		brandingApplyPending.Store(true)
		brandingSyncMarkFailed()
		return
	}
	if !isMaster {
		brandingApplyPending.Store(false)
		return
	}
	if err := h.applyCaddyConfigE(); err != nil {
		services.Logf("error", "branding 触发的 Caddy 配置应用失败: %v", err)
		brandingApplyPending.Store(true)
		brandingSyncMarkFailed()
		return
	}
	brandingApplyPending.Store(false)
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
	// 编辑最坏延迟 60s 可见。原始依据：幂等同步在 boot+首请求已完成，稳态
	// 每请求 ~7 条 SQL 是公开无鉴权端点的残余放大面；门内跳过同步/种子/镜像
	// （branding.json 为手工编辑的文档化用法，无管理写路径，带外手工编辑
	// 最坏经门内采样延迟 60s 可见，与上方门语义一致）。
	// 配置导入窗口内跳过本轮同步/播种/镜像：三者都写 global_config 与
	// security_block_pages（导入的全量替代表），事务持写锁时会排队至
	// busy_timeout(30s) 后失败，且结果会被导入覆盖。指纹不消费，窗口结束后
	// 下一次访问按原门控（≥60s 采样）重试。
	if !configImportBusy() && brandingSyncGateAllow(h.cfg.DataDir) {
		needApply := false
		syncFailed := false
		if changed, err := SyncDefaultLandingText(h.cfg.DataDir); err != nil {
			services.Logf("warn", "branding landing 同步失败: %v", err)
			syncFailed = true
		} else if changed {
			needApply = true
		}
		if changed, err := SeedDefaultBlockPage(h.cfg.DataDir); err != nil {
			services.Logf("warn", "branding 默认拦截页播种失败: %v", err)
			syncFailed = true
		} else if changed {
			needApply = true
		}
		// 品牌镜像(2026-09-11):文件变化时刷新 global_config.branding_json,
		// 触发器 bump cluster_version → 快照流向从节点。镜像变化本身不需要本地
		// Caddy 重载(本地渲染变化已由上方 Sync/Seed 的 needApply 覆盖)。
		if _, err := services.RefreshBrandingMirror(h.cfg.DataDir); err != nil {
			services.Logf("error", "branding 镜像刷新失败: %v", err)
			syncFailed = true
		}
		if syncFailed {
			brandingSyncMarkFailed()
		}
		// 待办应用（上一轮 /load 失败后尚未成功）：同步已落库，重试轮
		// needApply=false，必须靠待办标记继续尝试重应用，否则运行配置停在旧
		// 文案/旧拦截页。窗口由 60s 采样门约束，公开端点不会被刷成每请求 /load。
		if needApply || brandingApplyPending.Load() {
			if needApply {
				brandingApplyPending.Store(true)
			}
			go h.brandingApplyAfterSync()
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// renderDefaultBlockPage renders the branded default block page; consumed by
// SeedDefaultBlockPage(种子默认拦截页)与配置备份导入的默认页提升路径
// (config_backup.go)。
func renderDefaultBlockPage(cfg brandingConfig) string {
	// 页脚由 renderBlockPageShell 内部按同一 cfg 构建
	// 此处曾有逐字重复的死计算，已删）。
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
.card { position: relative; background: #fff; border-radius: 0; padding: 52px 48px 34px; text-align: center; width: min(560px, calc(100vw - 40px)); box-shadow: 0 1px 2px rgba(16,24,40,.05), 0 12px 32px -8px rgba(16,24,40,.12), 0 32px 64px -16px rgba(16,24,40,.10); }
.card::before { content: ""; position: absolute; top: 0; left: 24px; right: 24px; height: 3px; border-radius: 0; background: linear-gradient(90deg, transparent, %s 18%%, %s 50%%, %s 82%%, transparent); }
.badge { position: relative; width: 84px; height: 84px; margin: 0 auto 20px; }
.badge-ring { position: absolute; inset: 0; border-radius: 0; background: linear-gradient(145deg, %s, %s); border: 1px solid %s; box-shadow: 0 4px 12px -2px rgba(16,24,40,.12); }
.badge-halo { position: absolute; inset: -12px; border-radius: 0; border: 1px dashed %s; }
.badge svg { position: absolute; inset: 0; margin: auto; width: 38px; height: 38px; }
.chip { display: inline-flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 600; letter-spacing: .6px; color: %s; background: %s; border: 1px solid %s; border-radius: 0; padding: 5px 14px; margin-bottom: 16px; }
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

type builtinBlockPageIdentity struct {
	id      int
	name    string
	desc    string
	variant string
}

var builtinBlockPageIdentities = []builtinBlockPageIdentity{
	{9001, "限流拦截页面", "系统内置 429 限流拦截页面（备选，手动选用后生效）", "ratelimit"},
	{9002, "系统维护页面", "系统内置维护页面（备选，手动选用后生效）", "maintenance"},
}

// SeedDefaultBlockPage re-renders the default block page row (is_default=1) from
// branding.json，并对内置备选页（id 9001 限流/9002 维护，2026-09-25 用户裁定）
// 播种+自愈——内容漂移或 is_builtin 标志丢失（备份导入/带外改库形态）均归位
// 库存。Idempotent: an unchanged render writes nothing (updated_at is
// not churned); custom pages are never touched.
func SeedDefaultBlockPage(dataDir string) (bool, error) {
	if db.DB == nil {
		return false, nil
	}
	isMaster, roleErr := services.RoleOf(context.Background(), db.DB)
	if roleErr != nil {
		// 角色不可判定时跳过写——本函数会
		// 写同步表 security_block_pages，从节点瞬时读错会让本地渲染覆盖主端
		// 同步内容。与下方「owned by master」语义一致。
		services.Logf("warn", "branding：读取节点角色失败，跳过默认拦截页播种: %v", roleErr)
		return false, fmt.Errorf("读取节点角色: %w", roleErr)
	}
	if !isMaster {
		// The default block page content is owned by the master and arrives on
		// slaves via cluster sync; branding.json is node-local, so re-rendering
		// here would overwrite the synced content with local defaults.
		return false, nil
	}
	cfg := loadBrandingConfig(dataDir)
	content := renderDefaultBlockPage(cfg)
	// 默认页恒 html（带外改库漂移自愈；白名单类型不影响——
	// 渲染处空值回退与写侧白名单把守，此处仅归位默认页）。
	result, err := db.DB.Exec(`UPDATE security_block_pages SET content=?, content_type=?, updated_at=datetime('now') WHERE is_default=1 AND (COALESCE(content,'') != ? OR COALESCE(content_type,'') != ?) /* content=NULL 行 != ? 为 NULL 不命中——COALESCE 同 content_type 侧 */`, content, models.DefaultBlockPageContentType, content, models.DefaultBlockPageContentType)
	if err != nil {
		return false, fmt.Errorf("更新默认拦截页面内容: %w", err)
	}
	n, _ := result.RowsAffected()
	changed := n > 0
	// 内置备选页：INSERT OR IGNORE 播种（新库/被删形态），漂移行重写归位——
	// 标志修复与内容库存同事完成，仅漂移时写（updated_at 不抖动）。
	for _, bp := range builtinBlockPageIdentities {
		stock := renderBuiltinBlockPage(cfg, bp.variant)
		if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, is_builtin, created_at, updated_at) VALUES (?, ?, ?, ?, FALSE, TRUE, datetime('now'), datetime('now'))`, bp.id, bp.name, bp.desc, stock); err != nil {
			return changed, fmt.Errorf("播种内置拦截页面 %d: %w", bp.id, err)
		}
		// name/description/content 裸!= 对 NULL 不命中（带外改库
		// 置 NULL 正是本函数自称要自愈的形态）——COALESCE 同:510 默认页
		// 修复口径（name 列 NOT NULL，一并包仅为统一口径）。
		// UPDATE 增身份守卫——INSERT OR IGNORE 因 id 冲突未插入时，无守卫的
		// UPDATE 会按 id 改写「占用了内置 id 的自定义页」。身份判据=is_builtin=1
		// （正常行）或 name=库存名（备份导入/带外改库丢了标志但仍是内置页——既有
		// 自愈用例要求该形态归位）。其余（自定义页占 id）一律跳过并 warn。
		res, err := db.DB.Exec(`UPDATE security_block_pages SET name=?, description=?, content=?, content_type=?, is_builtin=1, updated_at=datetime('now') WHERE id=? AND (COALESCE(is_builtin,0)=1 OR name=?) AND (COALESCE(name,'') != ? OR COALESCE(description,'') != ? OR COALESCE(content,'') != ? OR COALESCE(content_type,'') != ? OR COALESCE(is_builtin,0) != 1)`,
			bp.name, bp.desc, stock, models.DefaultBlockPageContentType, bp.id, bp.name, bp.name, bp.desc, stock, models.DefaultBlockPageContentType)
		if err != nil {
			return changed, fmt.Errorf("修复内置拦截页面 %d: %w", bp.id, err)
		}
		bn, _ := res.RowsAffected()
		changed = changed || bn > 0
		if bn == 0 {
			// 未命中且该 id 被非内置行（名称亦非库存名）占用 → 明确告警并跳过
			// （自定义页永不改写）。
			var occupied int
			if err := db.DB.QueryRow(`SELECT COALESCE(is_builtin,0) FROM security_block_pages WHERE id=? AND name<>?`, bp.id, bp.name).Scan(&occupied); err == nil && occupied != 1 {
				services.Logf("warn", "内置拦截页面 %d（%s）的 ID 已被自定义页面占用，跳过播种（不改写自定义页）", bp.id, bp.name)
			}
		}
	}
	return changed, nil
}
