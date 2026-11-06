package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"lazy-balancer-v2/internal/db"
)

// RefreshBrandingMirror 把主节点 branding.json 原文镜像到
// global_config.branding_json(2026-09-11 裁定)。内容变化才写——触发器
// (branding_json 已入 OF 列表)bump cluster_version,快照缓存随之失效,
// 变更自然流向从节点;内容不变零写入零版本扰动。文件缺失镜像为空串。
// 仅主节点生效(WHERE is_master=1,与触发器 WHEN 同守卫)。
// 调用点:GetBranding(文件变化检测路径)等经全局 db.DB 的既有调用方。
func RefreshBrandingMirror(dataDir string) (changed bool, err error) {
	return RefreshBrandingMirrorDB(db.DB, dataDir)
}

// RefreshBrandingMirrorDB 是 RefreshBrandingMirror 的显式库句柄形态
// 快照入口必须写本服务的 s.db，而不是全局
// db.DB——测试/多库构造下两者不同源，镜像可能落到非本服务的库。
// 同时把「先读后写」短路落在这里：每次从节点轮询（含纯 304 轮）都会调用
// 本函数，内容未变时不再向主库发一条 UPDATE 写语句（N 从节点 = N 次/分钟
// 写事务此前无谓放大）。
func RefreshBrandingMirrorDB(database *sql.DB, dataDir string) (changed bool, err error) {
	if database == nil {
		return false, nil
	}
	// 空 dataDir 会把 CWD 下同名文件镜像进
	// global_config.branding_json 并随快照下发——与写入侧
	// applySnapshotBrandingChecked/MaterializeBranding 同款守卫。
	if dataDir == "" {
		return false, nil
	}
	content := ""
	if raw, rerr := os.ReadFile(filepath.Join(dataDir, "branding.json")); rerr == nil {
		content = string(raw)
		// 半截写守卫(2026-09-11 裁定):非法 JSON 不镜像——坏内容永不
		// 经集群通道流向从节点;文件恢复完整后下次轮询自然收敛。
		// 必须是 JSON 对象：null/数组/数字语法合法但从端物化会拒绝，
		// 造成每次 apply 失败与补偿重拉。
		if content != "" {
			var object map[string]any
			if err := json.Unmarshal([]byte(content), &object); err != nil || object == nil {
				// 该函数在每个从节点的每次 Pull（默认 60s）都会执行：主节点
				// 品牌文件处于半截写/损坏态期间，N 个从节点会产生 N 条/分钟
				// 同一条 warn，淹没取证面。按状态转换限频（首报 warn、恢复
				// 一条 info、持续损坏静默），与同包坏快照行/节点健康解析同族。
				if level := logStateTransition("cluster-branding-mirror-invalid", true); level != "" {
					Logf(level, "品牌配置文件不是有效对象(半截写?),跳过镜像: %s", dataDir)
				}
				return false, nil
			}
			if level := logStateTransition("cluster-branding-mirror-invalid", false); level != "" {
				Logf(level, "品牌配置文件已恢复为有效对象，继续镜像: %s", dataDir)
			}
		}
	} else if !os.IsNotExist(rerr) {
		return false, fmt.Errorf("读取品牌配置文件: %w", rerr)
	}
	// 先读后写短路：与 UPDATE 的 is_master=1 守卫同语义（非主节点无行，
	// 直接返回「未变更」）。读失败且非「无行」时按不可判定继续走写入——
	// 保持旧行为（写入自身会暴露真实失败面），不把读故障伪装成未变更。
	var current string
	if qerr := database.QueryRow(`SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1 AND COALESCE(is_master,1)=1`).Scan(&current); qerr == nil {
		if current == content {
			return false, nil
		}
	} else if errors.Is(qerr, sql.ErrNoRows) {
		return false, nil
	}
	result, err := database.Exec(
		`UPDATE global_config SET branding_json=? WHERE id=1 AND COALESCE(is_master,1)=1 AND COALESCE(branding_json,'')<>?`,
		content, content)
	if err != nil {
		return false, fmt.Errorf("镜像品牌配置: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("读取品牌配置镜像写入结果: %w", err)
	}
	return n > 0, nil
}

// emptyBrandingTemplate 与 handlers.EnsureBrandingFile 缺失再生的全空模板
// 逐字节一致(同 map 同 MarshalIndent 参数,键序按字典序稳定)。模板形态的
// 属主在 handlers 侧(启动期 main.go 调用 EnsureBrandingFile),services
// 反向 import 成环无法复用,此处复刻并锚定——字段增减须双侧同步。
var emptyBrandingTemplate = func() string {
	out, _ := json.MarshalIndent(map[string]string{
		"app_name":     "",
		"footer_text":  "",
		"landing_text": "",
		"version":      "",
	}, "", "  ")
	return string(out)
}()

// MaterializeBranding 把 branding_json 镜像值写回其事实源文件，并立即成对
// 注入内存单源（landing 文案 + TCP 拦截提示品牌）。空内容按集群同步既有
// 语义收敛为全空模板。
// 返回值 changed 报告是否需要触发下游重渲染：实际写入文件为 true；文件
// 内容一致但内存 TCP 提示品牌与文件口径分叉（导入/从端 applySnapshot/
// 自愈三入口都经本函数落盘，「内容一致」短路分支此前只注入 landing，
// 内存品牌滞留旧值永不收敛）时同样并入 true——提示文案渲染期烘焙进
// Caddy 配置，/load 触发链路依赖 changed=true 才会重渲染。内容与品牌
// 双双一致时为 false 且零 mtime 扰动——调用方据此区分「写了」与
// 「没写」，避免内容未变仍落一条品牌同步审计。
func MaterializeBranding(dataDir, content string) (changed bool, err error) {
	if dataDir == "" {
		return false, fmt.Errorf("品牌配置目录为空")
	}
	if content != "" {
		var object map[string]json.RawMessage
		if err := json.Unmarshal([]byte(content), &object); err != nil || object == nil {
			return false, fmt.Errorf("品牌配置不是有效 JSON 对象")
		}
	}
	if content == "" {
		content = emptyBrandingTemplate
	}
	path := filepath.Join(dataDir, "branding.json")
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		// 内容一致仍成对注入：三入口在真实落盘分支之外只有本短路通道，
		// 缺注入则内存品牌滞留旧值。品牌变化并入 changed（见函数注释）。
		return injectBrandingsFromBranding(content), nil
	}
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	// 单源原子落盘（同目录唯一临时文件 → chmod → 写入 → fsync → close →
	// rename → 父目录 fsync）：本函数曾逐项复刻同包 writeFileAtomicSynced，
	// 掉电一致性修复必须改两处、遗漏即品牌文件与备份/完整性文件耐久性分裂。
	if err := writeFileAtomicSynced(path, []byte(content), mode); err != nil {
		return false, fmt.Errorf("原子写入品牌配置文件: %w", err)
	}
	injectBrandingsFromBranding(content)
	return true, nil
}

// applySnapshotBranding 在 global_config 节应用后(事务已提交、Caddy 重载前)
// 把快照携带的 branding.json 写入本地文件并注入 landing 渲染。有差异才写
// (幂等,零 mtime 扰动);内存快照(若有)由 handlers 侧 loadBrandingConfig
// 的 stat 检测在下一次访问时自动重载;landing 立即注入保证随后的 Caddy
// 重载渲染新文案。BrandingJSON 为空=主节点无品牌文件(三分类合并后 users 节
// 恒同步+schema v3 强制,旧语义「开关关闭/旧主节点」消失）:重置为
// 全空模板收敛默认品牌——不直接删除,loadBrandingConfig 对缺失文件保内存
// 上一份旧值(2026-09-11 半截写窗口裁定),删除会让从端 /branding 长期陈旧。
// 返回值 changed=本轮是否实际写入文件（内容一致时为 false）。
func applySnapshotBranding(dataDir, content string) (bool, error) {
	if dataDir == "" {
		return false, nil
	}
	reset := content == ""
	changed, err := MaterializeBranding(dataDir, content)
	if err != nil {
		Logf("error", "同步品牌配置落盘失败: %v", err)
		// 失败审计由调用方（applySnapshotBrandingChecked）经 SyncService 的
		// 失败节流写入：品牌落盘失败会在 304 补偿重拉/标记重试
		// 下每轮重达此处，未节流的操作审计会按退避轮次洪泛。
		return false, err
	}
	if !changed {
		// 内容一致（branding_json 未变）：控制面未发生品牌变更，不得写
		// 「已同步生效/已重置为默认」审计——否则 users/basic_settings 节任意
		// 变更都会在从端产生误导性品牌审计。
		return false, nil
	}
	if reset {
		RecordAuditLog("system", "同步", "集群同步", "品牌配置已重置为默认（主节点无品牌文件）", "")
	} else {
		RecordAuditLog("system", "同步", "集群同步", "品牌配置已同步生效", "")
	}
	return true, nil
}

// ReconcileBrandingFile 核对本地 branding.json 与 global_config.branding_json
// 镜像，不一致（缺失/损坏/陈旧）时按镜像重写并注入 landing——零 Caddy 重载
// 从节点稳态 304 下 applySnapshot 不运行，品牌文件没有物化
// 通道：文件被删除或损坏后会永久停留默认品牌，直到 users 节发生任意变更。
// 返回是否发生重写；内容一致时为 false（零 mtime 扰动）。
func ReconcileBrandingFile(dataDir string) (bool, error) {
	return ReconcileBrandingFileDB(db.DB, dataDir)
}

// ReconcileBrandingFileDB 是 ReconcileBrandingFile 的显式库句柄形态
// 集群同步路径读本服务 s.db 的镜像列，与写入侧同源。
func ReconcileBrandingFileDB(database *sql.DB, dataDir string) (bool, error) {
	if database == nil || dataDir == "" {
		return false, nil
	}
	var content string
	if err := database.QueryRow("SELECT COALESCE(branding_json,'') FROM global_config WHERE id=1").Scan(&content); err != nil {
		return false, fmt.Errorf("读取品牌配置镜像: %w", err)
	}
	expected := content
	if expected == "" {
		// 与 applySnapshotBranding 同语义：镜像为空收敛为全空模板。
		expected = emptyBrandingTemplate
	}
	path := filepath.Join(dataDir, "branding.json")
	if actual, err := os.ReadFile(path); err == nil && string(actual) == expected {
		return false, nil
	}
	if _, err := MaterializeBranding(dataDir, content); err != nil {
		return false, err
	}
	return true, nil
}

// injectLandingFromBranding 从 branding JSON 原文提取 landing_text 并注入
// services 渲染(空/缺失/畸形回退默认,与 handlers.loadBrandingConfig 同语义)。
func injectLandingFromBranding(content string) {
	text := extractBrandingStringField(content, "landing_text")
	if text == "" {
		text = DefaultLandingText
	}
	SetDefaultLandingBody(text)
}

// injectBrandingsFromBranding 从 branding JSON 原文成对注入内存单源：
// TCP 拦截提示品牌（normalizeTCPNoticeBrand 归一，与 handlers
// SyncDefaultLandingText 同款口径，两处注入幂等）+ landing 文案。
// 返回品牌注入值是否发生变化——MaterializeBranding 据此把内存品牌变化
// 并入 changed（提示文案渲染期烘焙进 Caddy 配置，重载触发链依赖 changed）。
func injectBrandingsFromBranding(content string) (brandChanged bool) {
	before := TCPBlockNoticeBrand()
	SetTCPBlockNoticeBrand(normalizeTCPNoticeBrand(extractBrandingStringField(content, "app_name")))
	injectLandingFromBranding(content)
	return TCPBlockNoticeBrand() != before
}

// extractBrandingStringField 从 JSON 原文按字段名提取字符串值;任何解析
// 失败回退空串。值经 json.Unmarshal 值级解析(与主节点 loadBrandingConfig
// 同语义——含 \uXXXX/\n 等全部转义形态）。
func extractBrandingStringField(content, field string) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return ""
	}
	val, ok := raw[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return "" // 非字符串/畸形值按空处理(消费方回退默认)
	}
	return s
}
