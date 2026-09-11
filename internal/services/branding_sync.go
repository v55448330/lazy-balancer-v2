package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// RefreshBrandingMirror 把主节点 branding.json 原文镜像到
// global_config.branding_json(2026-09-11 裁定)。内容变化才写——触发器
// (branding_json 已入 OF 列表)bump cluster_version,快照缓存随之失效,
// 变更自然流向从节点;内容不变零写入零版本扰动。文件缺失镜像为空串。
// 仅主节点生效(WHERE is_master=1,与触发器 WHEN 同守卫)。
// 调用点:快照服务入口(每同步周期)与 GetBranding(文件变化检测路径)。
func RefreshBrandingMirror(dataDir string) (changed bool, err error) {
	if db.DB == nil {
		return false, nil
	}
	content := ""
	if raw, rerr := os.ReadFile(filepath.Join(dataDir, "branding.json")); rerr == nil {
		content = string(raw)
	} else if !os.IsNotExist(rerr) {
		return false, fmt.Errorf("读取品牌配置文件: %w", rerr)
	}
	result, err := db.DB.Exec(
		`UPDATE global_config SET branding_json=? WHERE id=1 AND COALESCE(is_master,1)=1 AND COALESCE(branding_json,'')<>?`,
		content, content)
	if err != nil {
		return false, fmt.Errorf("镜像品牌配置: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// applySnapshotBranding 在 global_config 节应用后(事务已提交、Caddy 重载前)
// 把快照携带的 branding.json 写入本地文件并注入 landing 渲染。有差异才写
// (幂等,零 mtime 扰动);内存快照(若有)由 handlers 侧 loadBrandingConfig
// 的 stat 检测在下一次访问时自动重载;landing 立即注入保证随后的 Caddy
// 重载渲染新文案。BrandingJSON 为空(开关关闭/旧主节点)不动本地文件。
func applySnapshotBranding(dataDir, content string) {
	if content == "" || dataDir == "" {
		return
	}
	path := filepath.Join(dataDir, "branding.json")
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		// 内容一致:仍同步注入 landing(防进程内注入态丢失,如主重启后)。
		injectLandingFromBranding(content)
		return
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		Logf("error", "同步品牌配置落盘失败: %v", err)
		RecordAuditLog("system", "同步失败", "集群同步", fmt.Sprintf("品牌配置落盘失败: %v", err), "")
		return
	}
	injectLandingFromBranding(content)
	RecordAuditLog("system", "同步", "集群同步", "品牌配置已同步生效", "")
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

// extractBrandingStringField 从 JSON 原文按字段名提取字符串值;任何解析
// 失败回退空串。独立于 handlers 的 brandingConfig(避免包依赖环)。
func extractBrandingStringField(content, field string) string {
	// 轻量提取:找 "field":"value" 形态(branding.json 是平面字符串结构,
	// 不含嵌套对象/转义复杂度,经 EnsureBrandingFile 归一后形态稳定)。
	key := `"` + field + `"`
	idx := indexAll(content, key)
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(key):]
	// 跳过空白与冒号
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == ':' || rest[i] == '\n' || rest[i] == '\t' || rest[i] == '\r') {
		i++
	}
	if i >= len(rest) || rest[i] != '"' {
		return ""
	}
	rest = rest[i+1:]
	end := -1
	escaped := false
	for j := 0; j < len(rest); j++ {
		if escaped {
			escaped = false
			continue
		}
		if rest[j] == '\\' {
			escaped = true
			continue
		}
		if rest[j] == '"' {
			end = j
			break
		}
	}
	if end < 0 {
		return ""
	}
	return unescapeJSONString(rest[:end])
}

func indexAll(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func unescapeJSONString(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				out = append(out, '\n')
			case 't':
				out = append(out, '\t')
			case 'r':
				out = append(out, '\r')
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			case '/':
				out = append(out, '/')
			default:
				out = append(out, s[i])
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// SnapshotForTest 暴露缓存旁路快照供测试断言(生产路径经 Snapshot)。
func (s *ClusterService) SnapshotForTest(ctx context.Context) (models.ClusterSnapshot, error) {
	return s.clusterSnapshotBypassingCache(ctx)
}

