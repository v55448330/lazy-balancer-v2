package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// LogStorageInfo 描述一类日志的体量与治理状态。
// SizeBytes 为当前活跃文件/库的大小；RotatedBytes 为轮转副本合计（DB 类为 0）。
// 大小型日志（达到 LimitBytes 即轮转）提供 LimitBytes 与 KeepCount；
// 时间型清理（每日按保留期删除）提供 RetentionNote。
type LogStorageInfo struct {
	Key           string `json:"key"`
	Name          string `json:"name"`
	SizeBytes     int64  `json:"size_bytes"`
	RotatedBytes  int64  `json:"rotated_bytes"`
	LimitBytes    *int64 `json:"limit_bytes,omitempty"`
	KeepCount     int    `json:"keep_count"`
	Rows          *int64 `json:"rows,omitempty"`
	RetentionNote string `json:"retention_note,omitempty"`
	ConfigSource  string `json:"config_source"`
}

// dirBytes 返回 path 的活跃文件大小与 .1..9 轮转副本合计。
func dirBytes(path string) (int64, int64) {
	var active, rotated int64
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		active = st.Size()
	}
	for i := 1; i <= 9; i++ {
		if st, err := os.Stat(path + "." + strconv.Itoa(i)); err == nil {
			rotated += st.Size()
		}
	}
	return active, rotated
}

// sanitizeRuleID 与写入侧 sanitizePathComponent / sanitizeRuleLogName 同口径，
// 只保留 caddy_id 字母表 [A-Za-z0-9_-]，其余字符剔除。
func sanitizeRuleID(value string) string {
	out := make([]rune, 0, len(value))
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		}
	}
	return string(out)
}

func globalConfigInt(column string, fallback int64) int64 {
	var v int64
	if err := db.DB.QueryRow("SELECT COALESCE("+column+",?) FROM global_config WHERE id=1", fallback).Scan(&v); err != nil {
		return fallback
	}
	return v
}

func sizeLimitMB(column string, def int64) *int64 {
	limit := globalConfigInt(column, def) * 1024 * 1024
	return &limit
}

// logPaths resolves the two distinct log roots GetLogStats probes:
//   - fixedDir is the hardcoded writer directory (/app/logs) shared by the five
//     hardcoded-writer log families — caddy 四份日志（caddy.log/caddy-tls.log/
//     caddy-server.log/caddy-proxy.log）、crs-update.log、ip2region-update.log、
//     certjob-*.log、rules/*.log。这些写入端写死 /app/logs，与 LOG_FILE 无关，
//     故其路径拼接必须固定用 /app/logs；若跟随 LogFile 目录推导，自定义
//     LOG_FILE 时这些日志会全部显示 0B。
//   - runtimePath is the runtime log path, which follows LogFile
//     （空 → /app/logs/lazy-balancer.log）。
func logPaths(cfg *config.Config) (fixedDir, runtimePath string) {
	fixedDir = "/app/logs"
	runtimePath = "/app/logs/lazy-balancer.log"
	if cfg == nil {
		return fixedDir, runtimePath
	}
	if cfg.LogFile != "" {
		runtimePath = cfg.LogFile
	}
	return fixedDir, runtimePath
}

// GetLogStats 返回全部日志存储的体量与治理信息，供各日志页显示
// 「当前大小 / 阈值（保留 N 份）」与清理策略说明。caddy_id 参数可将
// 证书任务/规则访问两项收窄到单规则。
func (h *Handlers) GetLogStats(c *gin.Context) {
	fixedLogsDir, runtimePath := logPaths(h.cfg)
	dataDir := "/app/data"
	if h.cfg != nil && h.cfg.DataDir != "" {
		dataDir = h.cfg.DataDir
	}

	// S-7（2026-09-06 裁定）：指标历史保留期与操作/运行/安全事件同用「日志保留」
	//（audit_retention_months）——提示文案补齐指标历史，三链对齐。
	retentionNote := "每日自动清理（操作/运行/安全事件/指标历史），保留 " + strconv.FormatInt(globalConfigInt("audit_retention_months", 3), 10) + " 个月"
	caddyLimit := sizeLimitMB("caddy_log_size_mb", 100)

	infos := []LogStorageInfo{
		{Key: "audit", Name: "操作日志", KeepCount: 0, RetentionNote: retentionNote, ConfigSource: "基础设置 · 日志保留"},
		{Key: "security_events", Name: "安全事件", KeepCount: 0, RetentionNote: retentionNote + "（上限 100000 条）", ConfigSource: "基础设置 · 日志保留"},
		{Key: "certjob", Name: "证书任务日志", LimitBytes: sizeLimitMB("cert_job_log_size_mb", 10), KeepCount: 5, ConfigSource: "基础设置 · 任务日志大小"},
		{Key: "crs_update", Name: "CRS 更新日志", LimitBytes: sizeLimitMB("cert_job_log_size_mb", 10), KeepCount: 5, ConfigSource: "基础设置 · 任务日志大小"},
		{Key: "ip2region_update", Name: "IP 库更新日志", LimitBytes: sizeLimitMB("cert_job_log_size_mb", 10), KeepCount: 5, ConfigSource: "基础设置 · 任务日志大小"},
		{Key: "runtime", Name: "运行日志", LimitBytes: sizeLimitMB("runtime_log_size_mb", 100), KeepCount: 5, RetentionNote: "轮转副本 " + retentionNote, ConfigSource: "基础设置 · 运行日志大小"},
		{Key: "caddy", Name: "Caddy 运行日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "rule_access", Name: "规则访问日志", LimitBytes: caddyLimit, KeepCount: 5, ConfigSource: "Caddy 全局配置 · 日志大小"},
		{Key: "coraza_audit", Name: "Coraza 审计日志", LimitBytes: sizeLimitMB("audit_log_size_mb", 10), KeepCount: 5, ConfigSource: "基础设置 · 审计日志大小"},
	}
	byKey := func(key string) *LogStorageInfo {
		for i := range infos {
			if infos[i].Key == key {
				return &infos[i]
			}
		}
		return nil
	}

	// DB 体量按库文件大小近似；行数供 UI 显示条目规模
	if db.AuditDB != nil {
		var n int64
		if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&n); err == nil {
			byKey("audit").Rows = &n
		}
	}
	if db.MetricsDB != nil {
		var n int64
		if err := db.MetricsDB.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&n); err == nil {
			byKey("security_events").Rows = &n
		}
	}
	if st, err := os.Stat(filepath.Join(dataDir, "lazy-balancer-audit.db")); err == nil {
		byKey("audit").SizeBytes = st.Size()
	}
	if st, err := os.Stat(filepath.Join(dataDir, "lazy-balancer-metrics.db")); err == nil {
		byKey("security_events").SizeBytes = st.Size()
	}

	if info := byKey("runtime"); info != nil {
		info.SizeBytes, info.RotatedBytes = dirBytes(runtimePath)
	}
	if info := byKey("caddy"); info != nil {
		var active, rotated int64
		for _, name := range []string{"caddy.log", "caddy-tls.log", "caddy-server.log", "caddy-proxy.log"} {
			a, r := dirBytes(filepath.Join(fixedLogsDir, name))
			active += a
			rotated += r
		}
		info.SizeBytes, info.RotatedBytes = active, rotated
	}
	if info := byKey("coraza_audit"); info != nil {
		info.SizeBytes, info.RotatedBytes = dirBytes(filepath.Join("/app/waf", "audit", "audit.log"))
	}
	if info := byKey("crs_update"); info != nil {
		info.SizeBytes, info.RotatedBytes = dirBytes(filepath.Join(fixedLogsDir, "crs-update.log"))
	}
	if info := byKey("ip2region_update"); info != nil {
		info.SizeBytes, info.RotatedBytes = dirBytes(filepath.Join(fixedLogsDir, "ip2region-update.log"))
	}

	ruleID := strings.TrimSpace(c.Query("caddy_id"))
	if ruleID != "" {
		// caddy_id 仅允许 caddy_id 字母表（[A-Za-z0-9_-]）；读者侧与写入侧
		// sanitizePathComponent/sanitizeRuleLogName 同口径校验，非法值（如路径穿越）
		// 直接 400，绝不参与 filepath.Join 拼接。
		if sanitized := sanitizeRuleID(ruleID); sanitized != ruleID {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的规则 ID"})
			return
		}
	}
	if info := byKey("certjob"); info != nil {
		if ruleID != "" {
			info.SizeBytes, info.RotatedBytes = dirBytes(filepath.Join(fixedLogsDir, "certjob-"+ruleID+".log"))
			info.Name = "证书任务日志 #" + ruleID
		} else if entries, err := os.ReadDir(fixedLogsDir); err == nil {
			var active, rotated int64
			for _, e := range entries {
				if e.IsDir() || !strings.HasPrefix(e.Name(), "certjob-") || !strings.HasSuffix(e.Name(), ".log") {
					continue
				}
				a, r := dirBytes(filepath.Join(fixedLogsDir, e.Name()))
				active += a
				rotated += r
			}
			info.SizeBytes, info.RotatedBytes = active, rotated
		}
	}
	if info := byKey("rule_access"); info != nil {
		if ruleID != "" {
			info.SizeBytes, info.RotatedBytes = dirBytes(filepath.Join(fixedLogsDir, "rules", ruleID+".log"))
			info.Name = "访问日志 #" + ruleID
		} else if entries, err := os.ReadDir(filepath.Join(fixedLogsDir, "rules")); err == nil {
			var active, rotated int64
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
					continue
				}
				a, r := dirBytes(filepath.Join(fixedLogsDir, "rules", e.Name()))
				active += a
				rotated += r
			}
			info.SizeBytes, info.RotatedBytes = active, rotated
		}
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]interface{}{"logs": infos}})
}
