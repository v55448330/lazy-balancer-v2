package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 自动备份（v2.3.x）：调度循环在 internal/services/autobackup.go（仅主节点
// 启动，到期判定纯函数），执行体在本文件——构建复用 buildLbbakExport，
// 还原复用 importConfigBackupCore。备份落盘 cfg.BackupDir（容器 /app/backup，
// BACKUP_DIR 可覆盖），文件含私钥与凭证明文，目录不得入库/入镜像。

var autoBackupRunMu sync.Mutex

// autoBackupFailedRowsKeep:failed 行保留上限（内务裁剪，与 keep 无关）。
const autoBackupFailedRowsKeep = 20

var autoBackupTimePattern = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// autoBackupSafeFilename:文件名一律取自 DB 行，文件操作必须限定在备份目录
// 内——拒绝任何路径分隔符/点路径/“..”形态（带外改库的深度防御）。
func autoBackupSafeFilename(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	return filepath.Base(name) == name
}

// loadAutoBackupSectionsSetting 读取备份范围设置；空/非法/空数组 → nil（全部）。
// 存量行可能携带三分类合并前的 legacy 键(global_config/waf_files)——读出即
// 归一(2026-09-19 用户裁定),调度器/导出器消费当前三分类口径,无需迁移存量行。
func loadAutoBackupSectionsSetting() []string {
	var raw sql.NullString
	if err := db.DB.QueryRow(`SELECT auto_backup_sections FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return nil
	}
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil
	}
	var sections []string
	if err := json.Unmarshal([]byte(raw.String), &sections); err != nil || len(sections) == 0 {
		return nil
	}
	return normalizeBackupSectionKeys(sections)
}

// loadAutoBackupKeepSetting 读取保留份数；越界/读失败回退 7（写侧已限 1-30；
// 2026-09-19 追加裁定:上限 100→30,升级前保存的 31-100 存量值读侧回退）。
func loadAutoBackupKeepSetting() int {
	var keep int
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_keep,7) FROM global_config WHERE id=1`).Scan(&keep); err != nil || keep < 1 || keep > 30 {
		return 7
	}
	return keep
}

// nextAutoBackupFilename 生成不冲突的备份文件名：lbbak-{auto|manual}-YYYYMMDD-
// HHMMSS.lbbak，同秒冲突追加 -2..-201（调度与手动同秒串行执行的场景）。
func nextAutoBackupFilename(dir, trigger string, now time.Time) string {
	kind := "auto"
	if trigger == "manual" {
		kind = "manual"
	}
	base := fmt.Sprintf("lbbak-%s-%s", kind, now.Format("20060102-150405"))
	for i := 0; i < 200; i++ {
		name := base + ".lbbak"
		if i > 0 {
			name = fmt.Sprintf("%s-%d.lbbak", base, i+1)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			continue
		}
		var exists int
		if db.DB != nil && db.DB.QueryRow(`SELECT COUNT(*) FROM auto_backups WHERE filename=?`, name).Scan(&exists) == nil && exists > 0 {
			continue
		}
		return name
	}
	return base + ".lbbak"
}

func insertAutoBackupRow(filename, status string, sizeBytes int64, sectionsJSON, triggerType, message string) (int64, error) {
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, size_bytes, sections, trigger_type, message) VALUES (?, ?, ?, ?, ?, ?)`,
		filename, status, sizeBytes, sectionsJSON, triggerType, message)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// pruneAutoBackups 内务裁剪：success 行按 created_at DESC 保留 keepSuccess 个、
// failed 行保留 keepFailed 个，多余者文件+行同删（系统日志留痕，不进操作日志）。
func pruneAutoBackups(dir string, keepSuccess, keepFailed int) {
	prune := func(status string, keep int) int {
		rows, err := db.DB.Query(`SELECT id, filename FROM auto_backups WHERE status=? ORDER BY created_at DESC, id DESC`, status)
		if err != nil {
			services.Logf("warn", "自动备份裁剪：读取 %s 行失败: %v", status, err)
			return 0
		}
		defer rows.Close()
		type pruneRow struct {
			id       int64
			filename string
		}
		var all []pruneRow
		for rows.Next() {
			var r pruneRow
			if err := rows.Scan(&r.id, &r.filename); err != nil {
				continue
			}
			all = append(all, r)
		}
		rows.Close()
		removed := 0
		for idx := range all {
			if idx < keep {
				continue
			}
			r := all[idx]
			if autoBackupSafeFilename(r.filename) {
				if err := os.Remove(filepath.Join(dir, r.filename)); err != nil && !errors.Is(err, os.ErrNotExist) {
					// SYSB43-1(第 43 轮):文件删除失败(非 ErrNotExist)保留行
					// 下轮重试——行随 warn 一并删除会让残留文件成孤儿永不再裁剪。
					services.Logf("warn", "自动备份裁剪：删除文件失败 %s: %v", r.filename, err)
					continue
				}
			}
			if _, err := db.DB.Exec(`DELETE FROM auto_backups WHERE id=?`, r.id); err != nil {
				services.Logf("warn", "自动备份裁剪：删除行失败 id=%d: %v", r.id, err)
				continue
			}
			removed++
		}
		return removed
	}
	removedSuccess := prune("success", keepSuccess)
	removedFailed := prune("failed", keepFailed)
	if removedSuccess+removedFailed > 0 {
		services.Logf("info", "自动备份裁剪：删除 %d 个过期成功备份与 %d 个过期失败记录", removedSuccess, removedFailed)
	}
}

// RunAutoBackupOnce 执行一次完整备份（调度/手动共用；main.go 经
// services.SetAutoBackupExecutor 注入给调度器）。流程：MkdirAll →
// buildLbbakExport → .tmp+rename 原子写盘 → 落行 → 裁剪 → 审计。
// 失败路径同样落 failed 行与审计（错误返回给调用方）。TryLock 并发守卫：
// 调度与手动同时触发时后到者立即报错，不排队。
// operator 为审计操作者:调度路径传 system,手动触发传当前登录用户
// (2026-09-20 用户反馈:手动备份审计恒 system,看不出是谁点的)。
func (h *Handlers) RunAutoBackupOnce(trigger, operator string) error {
	if !autoBackupRunMu.TryLock() {
		return errors.New("已有备份任务正在执行，请稍后重试")
	}
	defer autoBackupRunMu.Unlock()

	action := "自动备份"
	if trigger == "manual" {
		action = "手动备份"
	}
	now := time.Now()
	dir := h.cfg.BackupDir
	filename := nextAutoBackupFilename(dir, trigger, now)
	triggerLabel := "调度"
	if trigger == "manual" {
		triggerLabel = "手动"
	}
	fail := func(stage string, err error) error {
		wrapped := fmt.Errorf("%s: %w", stage, err)
		if _, ierr := insertAutoBackupRow(filename, "failed", 0, "[]", trigger, stage+": "+err.Error()); ierr != nil {
			services.Logf("warn", "自动备份：failed 行落库失败: %v", ierr)
		}
		services.Logf("warn", "%s失败：%s（%s）", action, stage, err)
		services.RecordAuditLog(operator, "备份失败", "配置备份", services.FormatAuditDetail(
			"触发："+triggerLabel, "文件："+filename, stage+"："+err.Error(), services.AuditResultPart("failed")), "")
		return wrapped
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail("创建备份目录失败", err)
	}
	payload, exportedSections, countsSummary, _, err := h.buildLbbakExport(context.Background(), loadAutoBackupSectionsSetting())
	if err != nil {
		return fail("备份构建失败", err)
	}
	finalPath := filepath.Join(dir, filename)
	tmpPath := finalPath + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return fail("备份文件写入失败", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fail("备份文件落盘失败", err)
	}
	sectionsJSON, err := json.Marshal(exportedSections)
	if err != nil {
		sectionsJSON = []byte("[]")
	}
	id, err := insertAutoBackupRow(filename, "success", int64(len(payload)), string(sectionsJSON), trigger, countsSummary)
	if err != nil {
		// 文件已写、行未落——删除孤儿文件保持两侧一致，审计留痕后按失败返回
		_ = os.Remove(finalPath)
		return fail("备份记录写入失败", err)
	}
	// 成功落行后内务裁剪(流程注释「落行→裁剪→审计」的裁剪步,SYS41-1 接线):
	// success 按 keep 保留、failed 按 autoBackupFailedRowsKeep=20 保留,
	// 文件+行同删;裁剪失败仅告警不翻转本次成功结果。
	pruneAutoBackups(dir, loadAutoBackupKeepSetting(), autoBackupFailedRowsKeep)
	services.Logf("info", "%s完成：文件 %s（%s，%.1f KB）", action, filename, countsSummary, float64(len(payload))/1024)
	services.RecordAuditLog(operator, action, "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("备份 #%d", id), "文件："+filename, countsSummary,
		fmt.Sprintf("大小：%d 字节", len(payload)), services.AuditResultPart("success")), "")
	return nil
}

// —— HTTP 端点 ——

func (h *Handlers) requireAutoBackupMaster(c *gin.Context) bool {
	if isMaster, err := h.clusterService.IsMaster(c.Request.Context()); err != nil || !isMaster {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅主节点支持管理自动备份"})
		return false
	}
	return true
}

// autoBackupRowView 是 auto_backups 行的 API 视图（sections 解码为数组）。
type autoBackupRowView struct {
	ID          int64    `json:"id"`
	Filename    string   `json:"filename"`
	CreatedAt   string   `json:"created_at"`
	Status      string   `json:"status"`
	SizeBytes   int64    `json:"size_bytes"`
	Sections    []string `json:"sections"`
	TriggerType string   `json:"trigger_type"`
	Message     string   `json:"message"`
}

type sqlRowScanner interface {
	Scan(dest ...any) error
}

func scanAutoBackupRowView(rows sqlRowScanner) (autoBackupRowView, error) {
	var view autoBackupRowView
	var sectionsRaw string
	if err := rows.Scan(&view.ID, &view.Filename, &view.CreatedAt, &view.Status, &view.SizeBytes, &sectionsRaw, &view.TriggerType, &view.Message); err != nil {
		return view, err
	}
	view.Sections = []string{}
	_ = json.Unmarshal([]byte(sectionsRaw), &view.Sections)
	return view, nil
}

const autoBackupRowColumns = `id, filename, created_at, status, COALESCE(size_bytes,0), COALESCE(sections,'[]'), trigger_type, COALESCE(message,'')`

// AutoBackupSettings GET /api/v1/settings/auto-backup：设置 + 备份列表（DESC）。
func (h *Handlers) AutoBackupSettings(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	var enabled bool
	var freq, hhmm string
	var day, keep int
	var sectionsRaw, lastRun sql.NullString
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,0), COALESCE(auto_backup_frequency,'daily'),
		COALESCE(auto_backup_time,'03:00'), COALESCE(auto_backup_day,1), COALESCE(auto_backup_keep,7),
		auto_backup_sections, auto_backup_last_run FROM global_config WHERE id=1`).
		Scan(&enabled, &freq, &hhmm, &day, &keep, &sectionsRaw, &lastRun); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自动备份设置失败: " + err.Error()})
		return
	}
	// 读侧守卫(2026-09-19 追加裁定):升级前保存的 31-100 存量值回退 7,
	// 与调度/裁剪消费端(loadAutoBackupKeepSetting)同口径——UI 显示的即
	// 生效值,重存后落库收敛。
	if keep < 1 || keep > 30 {
		keep = 7
	}
	sections := []string{}
	if sectionsRaw.Valid {
		var stored []string
		if json.Unmarshal([]byte(sectionsRaw.String), &stored) == nil && len(stored) > 0 {
			sections = normalizeBackupSectionKeys(stored)
		}
	}
	backups := []autoBackupRowView{}
	rows, err := db.DB.Query(`SELECT ` + autoBackupRowColumns + ` FROM auto_backups ORDER BY created_at DESC, id DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取备份列表失败: " + err.Error()})
		return
	}
	defer rows.Close()
	for rows.Next() {
		view, err := scanAutoBackupRowView(rows)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取备份列表失败: " + err.Error()})
			return
		}
		backups = append(backups, view)
	}
	var lastRunValue *string
	if lastRun.Valid && lastRun.String != "" {
		lastRunValue = &lastRun.String
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "ok", Data: gin.H{
		"enabled": enabled, "frequency": freq, "time": hhmm, "day": day, "keep": keep,
		"sections": sections, "last_run": lastRunValue, "backups": backups,
	}})
}

// UpdateAutoBackupSettings PUT /api/v1/settings/auto-backup：全量保存设置。
// 校验：freq∈{daily,weekly,monthly}；time 为 HH:MM；keep 1-30(2026-09-19
// 追加裁定:上限 100→30)；day weekly 1-7 / monthly 1-28；sections 为已知
// 分类子集且非空(legacy 键保存时归一为当前三分类落库)。off→on 时置水位线
// last_run=now(2026-09-19 用户裁定)——不立即执行、不回补停用期旧槽,
// 下一次执行=启用后下一个到期槽。
func (h *Handlers) UpdateAutoBackupSettings(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	var req struct {
		Enabled   *bool    `json:"enabled"`
		Frequency *string  `json:"frequency"`
		Time      *string  `json:"time"`
		Day       *int     `json:"day"`
		Keep      *int     `json:"keep"`
		Sections  []string `json:"sections"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式不正确"})
		return
	}
	if req.Enabled == nil || req.Frequency == nil || req.Time == nil || req.Day == nil || req.Keep == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "缺少必填字段（enabled/frequency/time/day/keep/sections）"})
		return
	}
	switch *req.Frequency {
	case "daily", "weekly", "monthly":
	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份频率必须是 daily/weekly/monthly"})
		return
	}
	if !autoBackupTimePattern.MatchString(*req.Time) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份时间必须为 HH:MM（00:00-23:59）"})
		return
	}
	if *req.Keep < 1 || *req.Keep > 30 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "保留份数必须在 1-30 之间"})
		return
	}
	dayHigh := 28
	if *req.Frequency == "weekly" {
		dayHigh = 7
	}
	if *req.Day < 1 || *req.Day > dayHigh {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("备份日期必须在 1-%d 之间", dayHigh)})
		return
	}
	if len(req.Sections) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份范围不能为空"})
		return
	}
	req.Sections = normalizeBackupSectionKeys(req.Sections)
	if _, _, ok := configBackupSectionTables(req.Sections); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "未知的配置分类"})
		return
	}
	sectionsJSON, err := json.Marshal(req.Sections)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "序列化备份范围失败: " + err.Error()})
		return
	}
	var prevEnabled bool
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,0) FROM global_config WHERE id=1`).Scan(&prevEnabled); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前设置失败: " + err.Error()})
		return
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=?, auto_backup_frequency=?, auto_backup_time=?, auto_backup_day=?, auto_backup_keep=?, auto_backup_sections=? WHERE id=1`,
		*req.Enabled, *req.Frequency, *req.Time, *req.Day, *req.Keep, string(sectionsJSON)); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存自动备份设置失败: " + err.Error()})
		return
	}
	if !prevEnabled && *req.Enabled {
		// 2026-09-19 用户裁定:启用不得立即触发备份——off→on 置水位线(=now),
		// 覆盖停用期前的陈旧 last_run(否则跨停用回补),下一次执行=启用后的
		// 下一个到期槽;仅手动触发与停机跨槽补跑属预期。
		if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_last_run=? WHERE id=1`, time.Now().Format(time.RFC3339)); err != nil {
			services.Logf("warn", "自动备份：启用时写入水位线失败: %v", err)
		}
	}
	freqLabel := map[string]string{"daily": "每日", "weekly": "每周", "monthly": "每月"}[*req.Frequency]
	recordAudit(c, "备份设置", "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("启用：%s", boolText(*req.Enabled)),
		fmt.Sprintf("频率：%s %s %s", freqLabel, *req.Time, autoBackupDayLabel(*req.Frequency, *req.Day)),
		fmt.Sprintf("保留份数：%d", *req.Keep),
		"范围："+strings.Join(autoBackupSectionLabels(req.Sections), "、"),
		services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "自动备份设置已保存"})
}

func autoBackupDayLabel(freq string, day int) string {
	if freq == "weekly" {
		return []string{"", "周一", "周二", "周三", "周四", "周五", "周六", "周日"}[day]
	}
	if freq == "monthly" {
		return fmt.Sprintf("%d 日", day)
	}
	return ""
}

func autoBackupSectionLabels(sections []string) []string {
	labels := make([]string, 0, len(sections))
	for _, key := range sections {
		label := key
		for _, sec := range configBackupSections {
			if sec.Key == key {
				label = sec.Label
				break
			}
		}
		labels = append(labels, label)
	}
	return labels
}

// RunAutoBackupNow POST /api/v1/auto-backup/run：手动触发一次完整备份。
func (h *Handlers) RunAutoBackupNow(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	operator := c.GetString("username")
	if operator == "" {
		operator = "system"
	}
	if err := h.RunAutoBackupOnce("manual", operator); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份执行失败: " + err.Error()})
		return
	}
	row := db.DB.QueryRow(`SELECT ` + autoBackupRowColumns + ` FROM auto_backups WHERE trigger_type='manual' ORDER BY id DESC LIMIT 1`)
	view, err := scanAutoBackupRowView(row)
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "手动备份完成"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "手动备份完成", Data: view})
}

// autoBackupRowByID 查行；不存在时写 404 并返回 false。
func (h *Handlers) autoBackupRowByID(c *gin.Context) (autoBackupRowView, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的备份 ID"})
		return autoBackupRowView{}, false
	}
	row := db.DB.QueryRow(`SELECT `+autoBackupRowColumns+` FROM auto_backups WHERE id=?`, id)
	view, err := scanAutoBackupRowView(row)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "备份不存在"})
		return autoBackupRowView{}, false
	}
	if !autoBackupSafeFilename(view.Filename) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份文件名非法"})
		return autoBackupRowView{}, false
	}
	return view, true
}

// DeleteAutoBackup DELETE /api/v1/auto-backup/:id：删除行+文件（文件缺失容忍）。
func (h *Handlers) DeleteAutoBackup(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	view, ok := h.autoBackupRowByID(c)
	if !ok {
		return
	}
	if err := os.Remove(filepath.Join(h.cfg.BackupDir, view.Filename)); err != nil && !errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份文件删除失败: " + err.Error()})
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM auto_backups WHERE id=?`, view.ID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除备份记录失败: " + err.Error()})
		return
	}
	recordAudit(c, "备份删除", "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("备份 #%d", view.ID), "文件："+view.Filename, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "备份已删除"})
}

// RestoreAutoBackup POST /api/v1/auto-backup/:id/restore：按行读文件并走
// 导入 core 还原（action=「还原」，审计由 core 记录）。还原的是备份实际
// 包含的内容——未选分类在导出时即未写入。
func (h *Handlers) RestoreAutoBackup(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	view, ok := h.autoBackupRowByID(c)
	if !ok {
		return
	}
	data, err := os.ReadFile(filepath.Join(h.cfg.BackupDir, view.Filename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "备份文件已不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取备份文件失败: " + err.Error()})
		return
	}
	h.importConfigBackupCore(c, data, true, view.Filename, "还原")
}

// DownloadAutoBackup GET /api/v1/auto-backup/:id/download：下载备份文件
// （与手动导出同敏感级：备份含私钥与凭证明文，审计留痕）。
func (h *Handlers) DownloadAutoBackup(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	view, ok := h.autoBackupRowByID(c)
	if !ok {
		return
	}
	path := filepath.Join(h.cfg.BackupDir, view.Filename)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "备份文件已不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取备份文件失败: " + err.Error()})
		return
	}
	recordAudit(c, "备份下载", "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("备份 #%d", view.ID), "文件："+view.Filename, "含凭证与证书材料，请加密保管", services.AuditResultPart("success")))
	c.Header("Cache-Control", "no-store, private")
	c.FileAttachment(path, view.Filename)
}
