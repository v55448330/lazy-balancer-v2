package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/taskengine"
	"net/http"
	"os"
	"path/filepath"
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

// autoBackupListLimit 设置端点备份列表的窗口上限：DESC 取前 N 行。正常态由
// 内务裁剪把行数收敛到 keep(≤30)+failed(20)，本上限只对「裁剪长期失效/带外
// 灌行」的异常态兜底，避免单次响应随表增长无限序列化。
const autoBackupListLimit = 200

// autoBackupBeforeSectionsReadHook 测试钩子（生产恒 nil）：在读取备份范围之前
// 运行——用于确定性地模拟「取消恰好发生在该读取窗口」。
var autoBackupBeforeSectionsReadHook func()

// HH:MM 校验统一走 services.ValidScheduleHHMM（原本地正则与调度侧解析
// 函数双实现，已收敛）。

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

// loadAutoBackupSectionsSetting 读取备份范围设置；未设置（NULL/空串）→ nil
// （全部）。数据库读失败、损坏 JSON 与空数组必须显式报错，绝不能静默退化
// 为全量备份（否则管理员原以为只导局部，实际把全部凭证写入备份文件）。
// 存量行可能携带三分类合并前的 legacy 键(global_config/waf_files)——读出即
// 归一(2026-09-19 用户裁定),调度器/导出器消费当前分类口径,无需迁移存量行。
func loadAutoBackupSectionsSetting(ctx context.Context) ([]string, error) {
	var raw sql.NullString
	if err := db.DB.QueryRowContext(ctx, `SELECT auto_backup_sections FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return nil, fmt.Errorf("读取备份范围: %w", err)
	}
	return decodeAutoBackupSectionsRaw(raw)
}

// decodeAutoBackupSectionsRaw 备份范围存储值 → 有效分类集合单源（读设置与
// 调度执行共用）：NULL/空串 → nil（全量）；空数组/损坏 JSON/未知分类 → 错误。
func decodeAutoBackupSectionsRaw(raw sql.NullString) ([]string, error) {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	var sections []string
	if err := json.Unmarshal([]byte(raw.String), &sections); err != nil {
		return nil, fmt.Errorf("备份范围格式损坏: %w", err)
	}
	if len(sections) == 0 {
		return nil, errors.New("备份范围不能为空数组")
	}
	normalized := normalizeBackupSectionKeys(sections)
	// 未知分类名同样显式报错——此前仅导出时才 400，调度每轮失败
	// 而设置页无信号。
	if _, _, ok := configBackupSectionTables(normalized); !ok {
		return nil, fmt.Errorf("备份范围包含未知分类: %s", strings.Join(normalized, ","))
	}
	return normalized, nil
}

// allBackupSectionKeys 当前分类的键序（GET 设置读侧把「未设置=全量」
// 展开成同一份有效范围，响应与执行语义不再分叉）。
func allBackupSectionKeys() []string {
	keys := make([]string, 0, len(configBackupSections))
	for _, sec := range configBackupSections {
		keys = append(keys, sec.Key)
	}
	return keys
}

const (
	// 默认值绑定 db 治理常量（库值唯一真相）：handlers 局部常量只允许引用，
	// 不得再持第二份数字字面量——改默认值后设置页显示/归一与 DDL/调度静默分叉。
	autoBackupKeepDefault = db.DefaultAutoBackupKeep
	autoBackupKeepMin     = 1
	autoBackupKeepMax     = 30
	autoBackupDayDefault  = db.DefaultAutoBackupDay
)

func autoBackupKeepValid(keep int) bool {
	return keep >= autoBackupKeepMin && keep <= autoBackupKeepMax
}

func autoBackupKeepOrDefault(keep int) int {
	if !autoBackupKeepValid(keep) {
		return autoBackupKeepDefault
	}
	return keep
}

func autoBackupDayHigh(frequency string) int {
	if frequency == "weekly" {
		return 7
	}
	return 28
}

// normalizeAutoBackupDay 把读到的 auto_backup_day 收敛到合法域（越界回退 DB
// 默认 1）。读侧两处内联钳制收敛到此单源，与调度侧
// services.normalizeAutoBackupDay 同口径（跨包不能共用：services 不可 import
// handlers）。
func normalizeAutoBackupDay(frequency string, day int) int {
	if day < 1 || day > autoBackupDayHigh(frequency) {
		return autoBackupDayDefault
	}
	return day
}

// loadAutoBackupKeepSetting 读取保留份数。返回 (keep, known)：
//   - known=false 表示配置读取失败（库故障/表缺失）——调用方必须**跳过本轮
//     裁剪**而不是按默认值删文件。此前读失败回退 7 并照常裁剪：用户配置 30
//     份、库抖动一轮就把 7 份之外的备份（含文件）删掉，回退方向非保守。
//   - 读成功但值越界（<1 或 >30，写侧已限 1-30）按默认 7 收敛——这是存量
//     越界值归一，与读失败语义不同（后者不删任何文件）。
//
// 读失败/恢复留痕走 services 状态转换单源（首报 warn、恢复 info）。
func loadAutoBackupKeepSetting(ctx context.Context) (keep int, known bool) {
	var raw int
	if err := db.DB.QueryRowContext(ctx, `SELECT COALESCE(auto_backup_keep,`+strconv.Itoa(db.DefaultAutoBackupKeep)+`) FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		services.LogConfigReadFailure("auto-backup-keep", err)
		return autoBackupKeepDefault, false
	}
	services.LogConfigReadRecovered("auto-backup-keep")
	return autoBackupKeepOrDefault(raw), true
}

// autoBackupFilenameBase 返回同秒冲突比较与失败占位共用的基础名（无 I/O）。
func autoBackupFilenameBase(trigger string, now time.Time) string {
	kind := "auto"
	if trigger == "manual" {
		kind = "manual"
	}
	return fmt.Sprintf("lbbak-%s-%s", kind, now.Format("20060102-150405"))
}

// autoBackupNameVariants 同秒文件名候选数：基础名 + -2..-200 共 200 个候选
// （原注释写 -2..-201 与实现不符，按注释调参易错）。
const autoBackupNameVariants = 200

// nextAutoBackupFilename 生成不冲突的备份文件名：lbbak-{auto|manual}-YYYYMMDD-
// HHMMSS.lbbak，同秒冲突追加 -2..-200（调度与手动同秒串行执行的场景）。
// 200 个变体全冲突时必须报错，不得回退到基础名
// （可能是已存在文件）——否则后续 os.Rename 会覆盖既有备份。
func nextAutoBackupFilename(ctx context.Context, dir, trigger string, now time.Time) (string, error) {
	base := autoBackupFilenameBase(trigger, now)
	for i := range autoBackupNameVariants {
		name := base + ".lbbak"
		if i > 0 {
			name = fmt.Sprintf("%s-%d.lbbak", base, i+1)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("检查备份文件名 %s: %w", name, err)
		}
		var exists int
		if db.DB != nil {
			var queryErr error
			queryErr = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM auto_backups WHERE filename=?`, name).Scan(&exists)
			if queryErr != nil && ctx.Err() != nil {
				return "", ctx.Err()
			}
			if queryErr == nil && exists > 0 {
				continue
			}
		}
		return name, nil
	}
	return "", fmt.Errorf("同名备份文件冲突超过 %d 次（基准名 %s）", autoBackupNameVariants, base)
}

// appVersion 为系统真实版本（cfg.Version，不受 branding.json 版本覆盖影响，
// 2026-09-21 用户裁定备份列表「版本号」列）；存量行缺省为空串，前端显示「—」。
func insertAutoBackupRow(ctx context.Context, filename, status string, sizeBytes int64, sectionsJSON, triggerType, message, appVersion string) (int64, error) {
	res, err := db.DB.ExecContext(ctx, `INSERT INTO auto_backups (filename, status, size_bytes, sections, trigger_type, message, app_version) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		filename, status, sizeBytes, sectionsJSON, triggerType, message, appVersion)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// pruneAutoBackupStatus 裁剪单一状态：按 created_at/id 倒序保留 keep 个，
// 多余者文件+行同删；文件删除失败保留行供下轮重试。
func pruneAutoBackupStatus(ctx context.Context, dir, status string, keep int) int {
	rows, err := db.DB.QueryContext(ctx, `SELECT id, filename FROM auto_backups WHERE status=? ORDER BY created_at DESC, id DESC`, status)
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
			services.Logf("warn", "自动备份裁剪：扫描 %s 行失败: %v", status, err)
			continue
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		// 半途失败时清单不完整：放弃本轮裁剪，避免漏删/误删且无痕。
		services.Logf("warn", "自动备份裁剪：遍历 %s 行失败: %v", status, err)
		rows.Close()
		return 0
	}
	rows.Close()
	removed := 0
	for idx := range all {
		if idx < keep {
			continue
		}
		r := all[idx]
		if err := ctx.Err(); err != nil {
			return removed
		}
		if autoBackupSafeFilename(r.filename) {
			if err := os.Remove(filepath.Join(dir, r.filename)); err != nil && !errors.Is(err, os.ErrNotExist) {
				// 文件删除失败(非 ErrNotExist)保留行
				// 下轮重试——行随 warn 一并删除会让残留文件成孤儿永不再裁剪。
				services.Logf("warn", "自动备份裁剪：删除文件失败 %s: %v", r.filename, err)
				continue
			}
		}
		if _, err := db.DB.ExecContext(ctx, `DELETE FROM auto_backups WHERE id=?`, r.id); err != nil {
			services.Logf("warn", "自动备份裁剪：删除行失败 id=%d: %v", r.id, err)
			continue
		}
		removed++
	}
	return removed
}

func logAutoBackupPrune(removedSuccess, removedFailed int) {
	if removedSuccess+removedFailed > 0 {
		services.Logf("info", "自动备份裁剪：删除 %d 个过期成功备份与 %d 个过期失败记录", removedSuccess, removedFailed)
	}
}

// pruneAutoBackups 内务裁剪：success 行保留 keepSuccess 个、failed 行保留
// keepFailed 个。成功备份与失败备份都会进入对应入口，持续失败不再无界增长。
func pruneAutoBackups(ctx context.Context, dir string, keepSuccess, keepFailed int) {
	removedSuccess := pruneAutoBackupStatus(ctx, dir, "success", keepSuccess)
	removedFailed := pruneAutoBackupStatus(ctx, dir, "failed", keepFailed)
	logAutoBackupPrune(removedSuccess, removedFailed)
}

func pruneFailedAutoBackups(ctx context.Context, dir string) {
	removedFailed := pruneAutoBackupStatus(ctx, dir, "failed", autoBackupFailedRowsKeep)
	logAutoBackupPrune(0, removedFailed)
}

// cleanupAutoBackupTempFiles 只清理本模块两种临时文件形态：旧固定
// lbbak-*.lbbak.tmp 与单源原子写产生的 .lbbak-*.lbbak-*.tmp。调用方已持
// autoBackupRunMu，同进程没有在役写者；其他 .tmp 与目录/链接一律不碰。
func cleanupAutoBackupTempFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		legacy, _ := filepath.Match("lbbak-*.lbbak.tmp", name)
		atomic, _ := filepath.Match(".lbbak-*.lbbak-*.tmp", name)
		if !legacy && !atomic {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("删除残留临时文件 %s: %w", name, err)
		}
	}
	return nil
}

// writeAutoBackupPayload 备份写盘单源：写盘函数本身无 ctx，
// 取消与写盘错误同时发生时此前直接走 fail()——task_runs 记 cancelled 而
// auto_backups 落 failed 行 + 「备份失败」审计，两处终态分叉。写盘报错后先看
// ctx：已取消（含 deadline）则按取消返回，交由调用方零行/零审计收尾（与
// 同口径）；未取消才是真实磁盘故障。
// autoBackupWriteFile 落盘入口（测试缝）：生产恒等
// services.WriteAutoBackupFileSynced（唯一原子写实现，不另造平行路径）；
// 用例经此注入写错误，使写失败回归不依赖进程身份（root/容器内 chmod 不拦截）。
var autoBackupWriteFile = services.WriteAutoBackupFileSynced

func writeAutoBackupPayload(ctx context.Context, path string, payload []byte) error {
	err := autoBackupWriteFile(path, payload)
	if err != nil && ctx != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
	}
	return err
}

// RunAutoBackupOnce 执行一次完整备份（调度/手动共用；main.go 经
// services.SetAutoBackupExecutor 注入给调度器）。流程：MkdirAll →
// 清理本模块残留临时文件 → buildLbbakExport → 单源原子落盘（唯一 tmp +
// fsync + rename + 父目录 fsync）→ 落行 → 裁剪 → 审计。
// 失败路径同样落 failed 行与审计（错误返回给调用方）。TryLock 并发守卫：
// 调度与手动同时触发时后到者立即报错，不排队。
// operator 为审计操作者:调度路径传 system,手动触发传当前登录用户
// (2026-09-20 用户反馈:手动备份审计恒 system,看不出是谁点的)。
// engineRunID>0=调用方（引擎 runNow/调度 tick）已落 task_runs 行——本函数
// 跳过自记自收尾（-④ 单写方，行终态由引擎按返回错误落）。
// ctx 来自引擎 Run 上下文：demote/停止时取消在途备份
// （buildLbbakExport 与写盘检查点消费），取消不落 failed 行。
func (h *Handlers) RunAutoBackupOnce(ctx context.Context, trigger, operator string, engineRunID int64) (row autoBackupRowView, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	histRun := int64(0)
	histT0 := time.Now()
	if engineRunID <= 0 {
		histRun = taskengine.RecordRunStart("auto-backup", "backup", trigger)
		defer func() {
			status, msg := "success", ""
			switch {
			case errors.Is(err, context.Canceled):
				// 取消（角色降级/引擎停止）落 cancelled，不得记 success。
				status, msg = "cancelled", err.Error()
			case err != nil:
				status, msg = "failed", err.Error()
			}
			taskengine.RecordRunFinish(histRun, status, time.Since(histT0).Milliseconds(), msg)
		}()
	}
	// 任务日志 tee（手动/自动备份各阶段在 tasks/auto-backup.log 留痕）
	backupTee := func(stage, msg string) {
		// 时间戳/级别/阶段口径唯一来源（services.TaskLogf→TeeTaskLogTime）：
		// 禁止自算时间戳再调 TeeTaskLog（第二个写点会在格式/时区变更时漏改）。
		services.TaskLogf("auto-backup", stage, "%s", msg)
	}
	backupTee("backup", "备份开始（触发："+trigger+"）")
	defer func() {
		switch {
		case err == nil:
			backupTee("backup", "备份完成")
		case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
			backupTee("backup", "备份已取消（角色降级/引擎停止）")
		default:
			backupTee("backup", "备份失败："+err.Error())
		}
	}()

	if !autoBackupRunMu.TryLock() {
		return autoBackupRowView{}, errors.New("已有备份任务正在执行，请稍后重试")
	}
	defer autoBackupRunMu.Unlock()

	// 取消检查点——取消不是「备份失败」，不落 failed 行/审计。
	if cerr := ctx.Err(); cerr != nil {
		return autoBackupRowView{}, cerr
	}

	action := "自动备份"
	if trigger == "manual" {
		action = "手动备份"
	}
	now := time.Now()
	dir := h.cfg.BackupDir
	triggerLabel := "调度"
	if trigger == "manual" {
		triggerLabel = "手动"
	}
	// 入口 fail-fast：BackupDir 为空或相对路径时，后续任何文件操作都会落在
	// 进程 CWD（failed 行裁剪按 DB 行文件名 + dir 相对解析执行 os.Remove）。
	// 生产配置由 config 载入（LoadCollectWarnings）保证绝对路径，此处防配置缺失/测试构造形态。
	// 判据单源 autoBackupDir()——还原/下载/删除三端点共用同一守卫。
	if _, dirErr := h.autoBackupDir(); dirErr != nil {
		reason := dirErr
		services.Logf("warn", "%s失败：%v", action, reason)
		services.RecordAuditLog(operator, "备份失败", "配置备份", services.FormatAuditDetail(
			"触发："+triggerLabel, "备份目录无效", services.AuditResultPart("failed")), "")
		return autoBackupRowView{}, reason
	}
	// 目录权限 0700——备份含私钥与凭证明文（文件由
	// services.WriteAutoBackupFileSynced 以 0600 原子写），目录本身不得放宽到
	// 组/其他可读。MkdirAll 的 0700 只对新目录生效，对已存在目录（旧版本创建/
	// 手工 mkdir/宿主机 bind mount 的 0755）是 no-op，故创建后显式 Chmod 收敛；
	// chmod 失败仅告警不阻断备份（NFS/只读挂载可能拒绝改权限，文件本体仍 0600）。
	// 目录先于文件名分配校验：父路径不可用时应落「创建备份目录失败」，
	// 而不是被文件名 Stat 抢先变成无法归因的命名错误。
	if err := os.MkdirAll(dir, autoBackupDirPerm); err != nil {
		failureName := autoBackupFilenameBase(trigger, now) + ".lbbak.unavailable"
		if _, ierr := insertAutoBackupRow(ctx, failureName, "failed", 0, "[]", trigger, "创建备份目录失败: "+err.Error(), h.cfg.Version); ierr != nil {
			services.Logf("warn", "自动备份：failed 行落库失败: %v", ierr)
		} else {
			pruneFailedAutoBackups(ctx, dir)
		}
		services.Logf("warn", "%s失败：创建备份目录失败（%s）", action, err)
		services.RecordAuditLog(operator, "备份失败", "配置备份", services.FormatAuditDetail(
			"触发："+triggerLabel, "文件："+failureName, "创建备份目录失败："+err.Error(), services.AuditResultPart("failed")), "")
		return autoBackupRowView{}, fmt.Errorf("创建备份目录失败: %w", err)
	}
	convergeAutoBackupDirPermissions(dir)
	filename, ferr := nextAutoBackupFilename(ctx, dir, trigger, now)
	if ferr != nil {
		// 无安全可归因文件名，不落 failed 行；审计与任务日志留痕。
		services.Logf("warn", "%s失败：生成备份文件名：%v", action, ferr)
		services.RecordAuditLog(operator, "备份失败", "配置备份", services.FormatAuditDetail(
			"触发："+triggerLabel, "生成备份文件名："+ferr.Error(), services.AuditResultPart("failed")), "")
		return autoBackupRowView{}, fmt.Errorf("生成备份文件名: %w", ferr)
	}
	fail := func(stage string, err error) error {
		wrapped := fmt.Errorf("%s: %w", stage, err)
		if _, ierr := insertAutoBackupRow(ctx, filename, "failed", 0, "[]", trigger, stage+": "+err.Error(), h.cfg.Version); ierr != nil {
			services.Logf("warn", "自动备份：failed 行落库失败: %v", ierr)
		} else {
			// 持续失败也必须执行 failed 配额裁剪，不能等下一次成功才收敛。
			pruneFailedAutoBackups(ctx, dir)
		}
		services.Logf("warn", "%s失败：%s（%s）", action, stage, err)
		services.RecordAuditLog(operator, "备份失败", "配置备份", services.FormatAuditDetail(
			"触发："+triggerLabel, "文件："+filename, stage+"："+err.Error(), services.AuditResultPart("failed")), "")
		return wrapped
	}

	// 残留临时文件清理是卫生动作：失败降 warn 不阻断备份本体
	// 此前 fail() 把整轮备份标 failed；残留文件下一轮清理重试，且两种临时
	// 形态不参与下载/还原路径）。
	if err := cleanupAutoBackupTempFiles(dir); err != nil {
		services.Logf("warn", "自动备份：清理残留临时文件失败（不阻断本次备份）: %v", err)
	}
	if autoBackupBeforeSectionsReadHook != nil {
		autoBackupBeforeSectionsReadHook()
	}
	sections, err := loadAutoBackupSectionsSetting(ctx)
	if err != nil {
		// 取消发生在读取备份范围时，不能按「备份失败」归因：ctx 错误会以
		// 「读取备份范围: context.Canceled」形态冒出来，落 failed 行与「备份失败」
		// 审计会把角色降级/引擎停止记成用户可见的备份故障（构建与写盘检查点
		// 早按取消短路，此处此前是唯一漏口）。
		if cerr := ctx.Err(); cerr != nil {
			return autoBackupRowView{}, cerr
		}
		return autoBackupRowView{}, fail("读取备份范围", err)
	}
	payload, exportedSections, countsSummary, _, err := h.buildLbbakExport(ctx, sections)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return autoBackupRowView{}, cerr
		}
		return autoBackupRowView{}, fail("备份构建失败", err)
	}
	backupTee("build", fmt.Sprintf("备份构建完成：%s（%d 段）", countsSummary, len(exportedSections)))
	finalPath := filepath.Join(dir, filename)
	if cerr := ctx.Err(); cerr != nil {
		return autoBackupRowView{}, cerr
	}
	if err := writeAutoBackupPayload(ctx, finalPath, payload); err != nil {
		// rename 可能已经成功、仅父目录 fsync 失败：无论是否同时取消，
		// 都必须清掉未登记最终文件，避免敏感备份脱离保留策略积累。
		if removeErr := os.Remove(finalPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			services.Logf("warn", "自动备份：写失败后清理最终文件 %s 失败: %v", finalPath, removeErr)
		}
		if cerr := ctx.Err(); cerr != nil {
			// 取消发生在写盘阶段——按取消返回，不落 failed 行/审计。
			return autoBackupRowView{}, cerr
		}
		return autoBackupRowView{}, fail("备份文件写入失败", err)
	}
	if cerr := ctx.Err(); cerr != nil {
		// 文件名本次唯一；取消后删除尚未登记的最终文件，维持取消零文件/零行。
		if removeErr := os.Remove(finalPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			services.Logf("warn", "自动备份：取消后清理最终文件 %s 失败: %v", finalPath, removeErr)
		}
		return autoBackupRowView{}, cerr
	}
	// exportedSections 是 []string，encoding/json 不会产生 unsupported type/value。
	sectionsJSON, _ := json.Marshal(exportedSections)
	id, err := insertAutoBackupRow(ctx, filename, "success", int64(len(payload)), string(sectionsJSON), trigger, countsSummary, h.cfg.Version)
	if err != nil {
		// 文件已写、行未落——删除孤儿文件保持两侧一致，审计留痕后按失败返回。
		if removeErr := os.Remove(finalPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			services.Logf("warn", "自动备份：落行失败后清理最终文件 %s 失败: %v", finalPath, removeErr)
		}
		return autoBackupRowView{}, fail("备份记录写入失败", err)
	}
	// 成功落行后内务裁剪(流程注释「落行→裁剪→审计」的裁剪步, 接线)
	// success 按 keep 保留、failed 按 autoBackupFailedRowsKeep=20 保留,
	// 文件+行同删;裁剪失败仅告警不翻转本次成功结果。
	// 保留份数读取失败时跳过本轮裁剪（保守方向：未知保留意愿下不得删文件
	// ——库抖动一轮不该按默认值淘汰用户配置的更多份数），下一轮读通后自然收敛。
	if keep, known := loadAutoBackupKeepSetting(ctx); known {
		pruneAutoBackups(ctx, dir, keep, autoBackupFailedRowsKeep)
		backupTee("prune", "过期备份裁剪完成（按保留份数设置）")
	} else {
		backupTee("prune", "读取保留份数失败，本轮跳过过期备份裁剪（不删除任何文件）")
	}
	services.Logf("info", "%s完成：文件 %s（%s，%.1f KB）", action, filename, countsSummary, float64(len(payload))/1024)
	services.RecordAuditLog(operator, action, "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("备份 #%d", id), "文件："+filename, countsSummary,
		fmt.Sprintf("大小：%d 字节", len(payload)), services.AuditResultPart("success")), "")
	// 行视图在 TryLock 持有区内取——调用方回查「最新 manual 行」在并发手动
	// 备份下会取到他人行。
	view, verr := scanAutoBackupRowView(db.DB.QueryRowContext(ctx, `SELECT `+autoBackupRowColumns+` FROM auto_backups WHERE id=?`, id))
	if verr != nil {
		// 留 warn(备份已落盘,视图扫描失败不再静默)
		services.Logf("warn", "自动备份行视图扫描失败(备份已落盘): %v", verr)
		return autoBackupRowView{}, nil
	}
	return view, nil
}

// —— HTTP 端点 ——

func (h *Handlers) requireAutoBackupMaster(c *gin.Context) bool {
	isMaster, err := h.clusterService.IsMaster(c.Request.Context())
	return requireMasterResult(c, isMaster, err, masterGateOptions{
		queryFailure: "节点角色查询失败",
		forbidden:    "仅主节点支持管理自动备份",
	})
}

// autoBackupRowView 是 auto_backups 行的 API 视图（sections 解码为数组）。
// sections_error 仅在行内 sections 列损坏/带外改写时出现：空数组会被读成
// 「该备份不含任何分类」，把「范围未知」误报成「范围为空」。
type autoBackupRowView struct {
	ID            int64    `json:"id"`
	Filename      string   `json:"filename"`
	CreatedAt     string   `json:"created_at"`
	Status        string   `json:"status"`
	SizeBytes     int64    `json:"size_bytes"`
	Sections      []string `json:"sections"`
	SectionsError string   `json:"sections_error,omitempty"`
	TriggerType   string   `json:"trigger_type"`
	Message       string   `json:"message"`
	AppVersion    string   `json:"app_version"`
}

type sqlRowScanner interface {
	Scan(dest ...any) error
}

// autoBackupTimeLayout 是备份时间字段的对外形态：UTC 墙钟串，与 /audit-logs、
// /certificates 同族（前端 parseDateValue 两种形态都接受）。
const autoBackupTimeLayout = "2006-01-02 15:04:05"

// formatAutoBackupTimestamp 把驱动返回值归一到对外形态：驱动可能把 DATETIME
// 列解析成 time.Time，也可能因列元数据缺失或存量值非常规而返回原始文本。
// 可解析值统一转 UTC 墙钟串——此前直接把驱动值扫进 string，实际形态随驱动
// 变成 RFC3339，与文档示例及同族端点不一致，按示例解析的脚本会失败或把 UTC
// 当本地时间再转一次。不可解析的存量值原样返回：历史脏值只影响该行展示，
// 不得让整个备份列表 500。
func formatAutoBackupTimestamp(raw any) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case time.Time:
		return v.UTC().Format(autoBackupTimeLayout)
	case []byte:
		return formatAutoBackupTimestamp(string(v))
	case string:
		if parsed, err := time.ParseInLocation(autoBackupTimeLayout, v, time.UTC); err == nil {
			return parsed.UTC().Format(autoBackupTimeLayout)
		}
		if parsed, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return parsed.UTC().Format(autoBackupTimeLayout)
		}
		return v
	default:
		return fmt.Sprint(v)
	}
}

func scanAutoBackupRowView(rows sqlRowScanner) (autoBackupRowView, error) {
	var view autoBackupRowView
	var createdAtRaw any
	var sectionsRaw string
	if err := rows.Scan(&view.ID, &view.Filename, &createdAtRaw, &view.Status, &view.SizeBytes, &sectionsRaw, &view.TriggerType, &view.Message, &view.AppVersion); err != nil {
		return view, err
	}
	// 格式化单源在此：last_success_at 复用本字段。
	view.CreatedAt = formatAutoBackupTimestamp(createdAtRaw)
	view.Sections = []string{}
	if err := json.Unmarshal([]byte(sectionsRaw), &view.Sections); err != nil {
		// 与设置读侧同一列同一口径（decodeAutoBackupSectionsRaw 损坏即报错），
		// 行视图曾静默退化为空数组：备份列表把「范围损坏/未知」展示成「范围
		// 为空」，运维可能据此放弃还原。键集沿用空数组，另以 sections_error
		// 披露并留痕。
		view.Sections = []string{}
		view.SectionsError = "备份范围损坏"
		services.Logf("warn", "自动备份行 %d（%s）备份范围损坏: %v", view.ID, view.Filename, err)
	}
	if view.Sections == nil {
		view.Sections = []string{}
	}
	return view, nil
}

const autoBackupRowColumns = `id, filename, created_at, status, COALESCE(size_bytes,0), COALESCE(sections,'[]'), trigger_type, COALESCE(message,''), COALESCE(app_version,'')`

// AutoBackupSettings GET /api/v1/settings/auto-backup：设置 + 备份列表（DESC）。
func (h *Handlers) AutoBackupSettings(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	var enabled bool
	var freq, hhmm string
	var day, keep int
	var sectionsRaw, lastRun sql.NullString
	var lastSuccessRaw any
	// 读路径消费请求 context：客户端断开即中止（与本端点其它族、审计列表
	// 的取消契约同边——同端点两套口径会让「取消传播」无法用单一断言覆盖）。
	// last_success_at 用同一查询里的标量子查询取（DESC 首条 success），而不是
	// 从下面截断后的列表推导：列表有窗口上限，success 行落在窗口之外时推导
	// 会误报 null（「从未成功备份」）。子查询与列表窗口彻底解耦，且仍是零额外
	// 往返。
	if err := db.DB.QueryRowContext(c.Request.Context(), `SELECT COALESCE(auto_backup_enabled,`+strconv.Itoa(db.DefaultAutoBackupEnabled)+`), COALESCE(auto_backup_frequency,'`+db.DefaultAutoBackupFrequency+`'),
		COALESCE(auto_backup_time,'`+db.DefaultAutoBackupTime+`'), COALESCE(auto_backup_day,`+strconv.Itoa(db.DefaultAutoBackupDay)+`), COALESCE(auto_backup_keep,`+strconv.Itoa(db.DefaultAutoBackupKeep)+`),
		auto_backup_sections, auto_backup_last_run,
		(SELECT created_at FROM auto_backups WHERE status='success' ORDER BY created_at DESC, id DESC LIMIT 1)
		FROM global_config WHERE id=1`).
		Scan(&enabled, &freq, &hhmm, &day, &keep, &sectionsRaw, &lastRun, &lastSuccessRaw); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自动备份设置失败: " + err.Error()})
		return
	}
	// 读侧守卫(2026-09-19 追加裁定):升级前保存的 31-100 存量值回退 7,
	// 与调度/裁剪消费端(loadAutoBackupKeepSetting)同口径——UI 显示的即
	// 生效值,重存后落库收敛。
	keep = autoBackupKeepOrDefault(keep)
	// day 读侧按 frequency 钳制——与写侧校验同口径
	//（UpdateAutoBackupSettings dayHigh：weekly 1-7、daily/monthly 1-28）。
	// 越界存量值回退 1（DB 默认），与 keep 回退同格；合法值原样返回。
	day = normalizeAutoBackupDay(freq, day)
	// 读侧与执行侧（loadAutoBackupSectionsSetting）同一语义——
	// NULL/空串=全量，展开为全部分类键；损坏 JSON/[]/未知分类显式 500，
	// 不再静默呈现空数组（调度侧这些形态本来就每轮失败）。复用本查询已
	// 扫描的原始值，避免额外一次 DB 读（读侧语义单源在解码 helper）。
	storedSections, sectionsErr := decodeAutoBackupSectionsRaw(sectionsRaw)
	if sectionsErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取备份范围失败: " + sectionsErr.Error()})
		return
	}
	sections := storedSections
	if sections == nil {
		sections = allBackupSectionKeys()
	}
	backups := []autoBackupRowView{}
	// 窗口上限 +1 探测截断：多取一行即可判定「还有更旧的未返回」，无需
	// 额外 COUNT 查询。
	rows, err := db.DB.QueryContext(c.Request.Context(), `SELECT `+autoBackupRowColumns+` FROM auto_backups ORDER BY created_at DESC, id DESC LIMIT ?`, autoBackupListLimit+1)
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
	// ⑫：迭代失败显式 500——
	// 部分列表 + 200 会掩盖存储故障。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取备份列表失败: " + err.Error()})
		return
	}
	backupsTruncated := false
	if len(backups) > autoBackupListLimit {
		backups = backups[:autoBackupListLimit]
		backupsTruncated = true
	}
	var lastRunValue *string
	if lastRun.Valid {
		// 水位线回传响应面（此前扫描后零消费恒 null）。
		lastRunValue = &lastRun.String
	}
	// last_run 是调度水位线（off→on=now，2026-09-19 裁定），不是
	// 执行事实；「上次执行」取最近一次 success 备份行——由上面的标量子查询
	// 提供（与列表窗口解耦），失败行不入选。
	var lastSuccessValue *string
	if lastSuccessRaw != nil {
		// 格式单源：与列表行同一 formatAutoBackupTimestamp（驱动对该 DATETIME
		// 列可能回 time.Time、也可能回字符串，二者都必须收敛到同一墙面格式）。
		createdAt := formatAutoBackupTimestamp(lastSuccessRaw)
		lastSuccessValue = &createdAt
	}
	now := time.Now()
	var nextRunValue *string
	catchUpDue := false
	if next, ok := services.NextAutoBackupSlot(c.Request.Context(), now); ok {
		formatted := next.Format(time.RFC3339)
		nextRunValue = &formatted
		catchUpDue = !next.After(now)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "ok", Data: gin.H{
		"enabled": enabled, "frequency": freq, "time": hhmm, "day": day, "keep": keep,
		"sections": sections, "last_run": lastRunValue, "last_success_at": lastSuccessValue,
		"next_run_at": nextRunValue, "catch_up_due": catchUpDue, "backups": backups,
		// 列表窗口（autoBackupListLimit）截断标记：正常态恒 false（内务裁剪把
		// 行数收敛到 keep+failed 上限），true 表示「还有更旧的备份未返回」。
		"backups_truncated": backupsTruncated,
	}})
}

// autoBackupSettingsBodyLimit 自动备份设置请求体上限：设置项固定五字段 +
// 分类数组，16 KiB 足够；超限按 413 归因（与 JSON 语法错误区分）。
const autoBackupSettingsBodyLimit = 16 << 10

// UpdateAutoBackupSettings PUT /api/v1/settings/auto-backup：全量保存设置。
// 校验：freq∈{daily,weekly,monthly}；time 为 HH:MM；keep 1-30(2026-09-19
// 追加裁定:上限 100→30)；day weekly 1-7 / monthly 1-28；sections 为已知
// 分类子集且非空(legacy 键保存时归一为当前四分类落库——users/rules/
// security/cluster，键清单单源 configBackupSections)。off→on 时置水位线
// last_run=now(2026-09-19 用户裁定)——不立即执行、不回补停用期旧槽,
// 下一次执行=启用后下一个到期槽。
func (h *Handlers) UpdateAutoBackupSettings(c *gin.Context) {
	// 自动备份四列设置与开关都在 global_config 全量替换范围内：导入窗口内的
	// 提交会被导入静默覆盖（数据丢失），事务开启后则阻塞至 busy_timeout 后
	// 500——与同族 global_config 写者同口径 409 fast-fail。
	if rejectWriteDuringImport(c, "保存自动备份设置（配置导入进行中）") {
		return
	}
	if !h.requireAutoBackupMaster(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, autoBackupSettingsBodyLimit)
	var req struct {
		Enabled   *bool    `json:"enabled"`
		Frequency *string  `json:"frequency"`
		Time      *string  `json:"time"`
		Day       *int     `json:"day"`
		Keep      *int     `json:"keep"`
		Sections  []string `json:"sections"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// 体积超限单独归因 413：此前与 JSON 语法错误同为 400「请求格式不正确」，
		// 用户会去排查格式而不是体积（与同族端点 413 口径不一致）。
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体超过 16 KiB 上限"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式不正确"})
		return
	}
	if req.Enabled == nil || req.Frequency == nil || req.Time == nil || req.Day == nil || req.Keep == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "缺少必填字段（enabled/frequency/time/day/keep）"})
		return
	}
	switch *req.Frequency {
	case "daily", "weekly", "monthly":
	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份频率必须是 daily/weekly/monthly"})
		return
	}
	if !services.ValidScheduleHHMM(*req.Time) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "备份时间必须为 HH:MM（00:00-23:59）"})
		return
	}
	if !autoBackupKeepValid(*req.Keep) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("保留份数必须在 %d-%d 之间", autoBackupKeepMin, autoBackupKeepMax)})
		return
	}
	dayHigh := autoBackupDayHigh(*req.Frequency)
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
	// 四列设置与业务开关同事务——修复前设置先落库、开关后写，
	// 开关失败返回 500 但频率/范围/保留份数已生效（半保存）。
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存自动备份设置失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`UPDATE global_config SET auto_backup_frequency=?, auto_backup_time=?, auto_backup_day=?, auto_backup_keep=?, auto_backup_sections=?, auto_backup_sections_version=1 WHERE id=1`,
		*req.Frequency, *req.Time, *req.Day, *req.Keep, string(sectionsJSON)); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存自动备份设置失败: " + err.Error()})
		return
	}
	if err := services.SetAutoBackupEnabledTx(tx, *req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存自动备份开关失败: " + err.Error()})
		return
	}
	if err := commitTx(tx); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存自动备份设置失败: " + err.Error()})
		return
	}
	committed = true
	services.SyncAutoBackupTaskLoop(*req.Enabled)
	freqLabel := map[string]string{"daily": "每日", "weekly": "每周", "monthly": "每月"}[*req.Frequency]
	recordAudit(c, "备份设置", "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("启用：%s", boolText(*req.Enabled)),
		fmt.Sprintf("频率：%s %s %s", freqLabel, *req.Time, autoBackupDayLabel(*req.Frequency, *req.Day)),
		fmt.Sprintf("保留份数：%d", *req.Keep),
		"范围："+strings.Join(autoBackupSectionLabels(req.Sections), "、"),
		services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "自动备份设置已保存"})
}

// autoBackupDirPerm 备份目录权限：目录内是含私钥与凭证明文的备份文件
// （文件本体由 services.WriteAutoBackupFileSynced 以 0600 原子写），目录不得
// 放宽到组/其他可读（仅文件名/触发类型/时间戳可被列出）。
const autoBackupDirPerm = 0o700

// convergeAutoBackupDirPermissions 把既有备份目录权限收敛到 autoBackupDirPerm。
// os.MkdirAll 对已存在目录不修改权限——旧版本创建、手工 mkdir 或宿主机 bind
// mount 的 0755 目录会长期保持宽松。只收窄「组/其他可读」位（perm&0o077）：
// 刻意设为 0500 等只读形态的目录保持原样，不因收敛而额外授予属主写权限。
// chmod 失败仅告警不阻断：NFS/只读挂载可能拒绝改权限，文件本体仍为 0600，
// 备份可用性优先。
func convergeAutoBackupDirPermissions(dir string) {
	info, err := os.Stat(dir)
	if err != nil {
		services.Logf("warn", "自动备份：读取备份目录权限失败（%s）", err)
		return
	}
	if info.Mode().Perm()&0o077 == 0 {
		return
	}
	if err := os.Chmod(dir, autoBackupDirPerm); err != nil {
		services.Logf("warn", "自动备份：备份目录权限收敛为 0700 失败（%s）——文件本体仍为 0600", err)
	}
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
//
// 响应前转后台（此前同步 te.RunSync 会整段占住请求线程，客户端需等备份
// 完成才拿到响应，前端只能靠轮询/超时判断结果）。
// 占位改为引擎原子预留（RunAsync）——
// 入口门（paused/stopped/角色/单飞）与 running CAS 在请求线程内完成，
// 失败在 202 之前同步映射 409/403/503 并留审计；不再出现「已受理但后台
// 被静默拒绝」。运行期失败仍由引擎 task_runs/日志记录。
func (h *Handlers) RunAutoBackupNow(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	te := services.TaskEngine()
	if te == nil {
		respondTaskEngineUnavailable(c)
		return
	}
	// 审计分类单源 services.TriggerTaskAsync（三份手动触发分类
	// 收敛）——ErrAlreadyRunning 并发双击静默（不再误记「触发失败」），
	// 其余 admission/执行失败由单源补「触发失败」审计；HTTP 状态映射留本地
	//（本端点 EngineStopped=503 等文案面向备份场景）。
	actx := triggerAuditContext(c, "自动备份", "自动备份")
	if err := services.TriggerTaskAsync(te, "auto-backup", actx); err != nil {
		switch {
		case errors.Is(err, taskengine.ErrAlreadyRunning):
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "已有备份任务正在执行（含定时备份），请稍后重试"})
		case errors.Is(err, taskengine.ErrSchedulingPaused):
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务调度已暂停（配置导入进行中），请稍后重试"})
		case errors.Is(err, taskengine.ErrEngineStopped):
			c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎已停止，无法触发备份"})
		case errors.Is(err, taskengine.ErrNotMaster):
			c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: err.Error()})
		default:
			services.Logf("error", "手动备份触发失败: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "触发备份失败: " + err.Error()})
		}
		return
	}
	c.JSON(http.StatusAccepted, models.APIResponse{Code: 0, Message: "手动备份已开始，完成后可在备份列表查看"})
}

// autoBackupDir 返回可安全 filepath.Join 的备份目录：必须非空且绝对。
// 生产配置由 config.LoadCollectWarnings 保证绝对路径；配置缺失/测试构造/
// 容器 env 覆盖给出相对路径时，Join 会在进程 CWD 下解析同名文件——写路径
// （RunAutoBackupOnce）已有同口径入口 fail-fast，读/删三端点此前直接 Join，
// 故收敛到本 helper 共用同一守卫。
func (h *Handlers) autoBackupDir() (string, error) {
	dir := h.cfg.BackupDir
	if strings.TrimSpace(dir) == "" || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("备份目录未配置或不是绝对路径: %q", dir)
	}
	return dir, nil
}

// autoBackupRowByID 查行；不存在 404、DB 故障响亮 500（此前 Scan 错误一律
// 404「备份不存在」，DB 故障窗口误导排障方向；与 GetCurrentUser/
// requireAutoBackupMaster 已立先例同口径）。verb 是调用方的动作词
// （还原/下载/删除）：行面失败与文件面同属「进入高危操作核心之前」的拒绝面，
// 三个出口（400 非法 ID、404 行不存在/DB 故障 500、400 文件名非法）此前只有
// 裸 c.JSON，操作审计页零记录——管理员在列表页点「还原/下载/删除」时行可能
// 已被保留期裁剪或并发删除，被拒尝试同样要能回答「谁在何时试过哪个备份」。
func (h *Handlers) autoBackupRowByID(c *gin.Context, verb string) (autoBackupRowView, bool) {
	rawID := c.Param("id")
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		failAutoBackupAccess(c, verb, fmt.Sprintf("备份 ID %q", rawID), "无效的备份 ID",
			http.StatusBadRequest, err)
		return autoBackupRowView{}, false
	}
	subject := fmt.Sprintf("备份 #%d", id)
	// 读路径统一消费请求上下文：客户端断开/超时即中止（与本包
	// GetAuditLogs/AutoBackupSettings 的不变量同口径），不留 ctx-less 点查。
	row := db.DB.QueryRowContext(c.Request.Context(), `SELECT `+autoBackupRowColumns+` FROM auto_backups WHERE id=?`, id)
	view, err := scanAutoBackupRowView(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			failAutoBackupAccess(c, verb, subject, "备份不存在", http.StatusNotFound, err)
			return autoBackupRowView{}, false
		}
		// 5xx 文案与归因沿用 dbQueryNotFound 的口径（固定「数据库错误」，
		// 底层错误只进日志/审计）——本分支直接调用，故在此显式拼 operation。
		failAutoBackupAccess(c, verb, subject, "数据库错误", http.StatusInternalServerError,
			fmt.Errorf("查询自动备份行: %w", err))
		return autoBackupRowView{}, false
	}
	if !autoBackupSafeFilename(view.Filename) {
		failAutoBackupAccess(c, verb, fmt.Sprintf("备份 #%d", view.ID), "备份文件名非法",
			http.StatusBadRequest, fmt.Errorf("非法备份文件名 %q", view.Filename))
		return autoBackupRowView{}, false
	}
	return view, true
}

// DeleteAutoBackup DELETE /api/v1/auto-backup/:id：删除行+文件（文件缺失容忍）。
func (h *Handlers) DeleteAutoBackup(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	view, ok := h.autoBackupRowByID(c, "删除")
	if !ok {
		return
	}
	// 失败面单源：删除族（行面/文件面/提交面）每个拒绝分支都经
	// failAutoBackupAccess 落「删除失败」审计——此前六条分支裸写响应，
	// 管理员在列表点删除而失败时审计页零记录，与同族还原/下载的收尾契约
	// 不一致。subject 与文件面同形（备份 id + 文件名）便于按文件复盘。
	subject := fmt.Sprintf("备份 #%d 文件 %s", view.ID, view.Filename)
	// 目录守卫先于事务：相对/空目录时不得先删行再在 CWD 下删同名文件。
	backupDir, dirErr := h.autoBackupDir()
	if dirErr != nil {
		failAutoBackupAccess(c, "删除", subject, "备份目录无效", http.StatusInternalServerError, dirErr)
		return
	}
	// 行删除先在事务内确认影响行数，再删文件：0 行（并发先到者已删）
	// 不得碰文件；文件删除失败回滚行删除，保留可重试入口且不记成功审计。
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		failAutoBackupAccess(c, "删除", subject, "删除备份记录失败", http.StatusInternalServerError,
			fmt.Errorf("开启删除事务: %w", err))
		return
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM auto_backups WHERE id=?`, view.ID)
	if err != nil {
		failAutoBackupAccess(c, "删除", subject, "删除备份记录失败", http.StatusInternalServerError,
			fmt.Errorf("删除自动备份行: %w", err))
		return
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		failAutoBackupAccess(c, "删除", subject, "删除备份记录失败", http.StatusInternalServerError,
			fmt.Errorf("读取删除行数: %w", err))
		return
	}
	if deleted == 0 {
		failAutoBackupAccess(c, "删除", subject, "备份不存在（可能已被删除）", http.StatusNotFound, sql.ErrNoRows)
		return
	}
	if err := os.Remove(filepath.Join(backupDir, view.Filename)); err != nil && !errors.Is(err, os.ErrNotExist) {
		failAutoBackupAccess(c, "删除", subject, "删除备份文件失败", http.StatusInternalServerError,
			fmt.Errorf("删除备份文件 %s: %w", view.Filename, err))
		return
	}
	// 文件先于提交删除：提交失败时行恢复、文件已亡，这是本端点最坏的分叉
	// （列表仍显示该备份，下载/还原才 404）。文案必须显式说明已发生的副作用
	// 与可执行的下一步，不得只说「删除失败」。
	if err := commitTx(tx); err != nil {
		// database/sql 在 Commit 失败后不再调用 driver.Rollback，SQLite 的
		// deferred 约束/IO 类失败会让底层事务保持活动（连接归还池后，复用该
		// 连接的读会看到未提交的删除）。统一补发 ROLLBACK 才能真正兑现文案里
		// 「记录已恢复保留」的承诺（与提交失败族同一收尾）。
		rollbackLeakedTx()
		failAutoBackupAccess(c, "删除", subject,
			"备份记录提交失败（备份文件已删除、记录已恢复保留，请再次删除该记录）",
			http.StatusInternalServerError, fmt.Errorf("提交删除事务: %w", err))
		return
	}
	recordAudit(c, "备份删除", "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("备份 #%d", view.ID), "文件："+view.Filename, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "备份已删除"})
}

// failAutoBackupAccess 是自动备份高危操作族（还原/下载/删除）失败收尾的单一
// 来源：失败审计 + 运行日志 + 原状态码信封。行面（autoBackupRowByID 的 400/
// 404/500）与文件面（failRestoreFileAccess 的 404/413/500）共用本函数——此前
// 两个阶段各写各的裸 c.JSON，被拒尝试在操作审计页零记录。
//
// 动作词取词表内静态字面量（操作标签 ≤4 词）：还原失败 / 下载失败 / 删除失败；
// 对象固定「配置备份」。subject 携带备份标识与阶段供审计复盘，message 保持原
// API 文案（客户端契约不变）。失败分支不记成功审计——未交付不得虚记交付。
// 5xx 的公开文案仍为固定中文（底层错误只进日志/审计），与本文件其余 5xx 写法
// 同口径。
func failAutoBackupAccess(c *gin.Context, verb, subject, message string, status int, cause error) {
	detail := subject + "：" + message
	recordAudit(c, verb+"失败", "配置备份", detail)
	level := "warn"
	if status >= http.StatusInternalServerError {
		level = "error"
	}
	services.Logf(level, "自动备份%s被拒绝（%d）: %s（%v）", verb, status, detail, cause)
	c.JSON(status, models.APIResponse{Code: status, Message: message})
}

// failRestoreFileAccess 是自动备份「还原/下载」进入导入核心之前**文件面**失败的
// 收尾适配器（保留 download 位以维持 9 个调用点的可读性）：文件面与行面同经
// failAutoBackupAccess 落「还原失败/下载失败」审计 + 运行日志 + 原状态码响应。
// 与 HTTP 读体超限的 413 不同（那属客户端探测面、不落审计），这里的 413 来自
// 本地备份文件自身超限，是管理员操作的真实失败面。
func failRestoreFileAccess(c *gin.Context, download bool, subject, message string, status int, cause error) {
	verb := "还原"
	if download {
		verb = "下载"
	}
	failAutoBackupAccess(c, verb, subject, message, status, cause)
}

// RestoreAutoBackup POST /api/v1/auto-backup/:id/restore：按行读文件并走
// 导入 core 还原（action=「还原」，审计由 core 记录）。还原的是备份实际
// 包含的内容——未选分类在导出时即未写入。
func (h *Handlers) RestoreAutoBackup(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	view, ok := h.autoBackupRowByID(c, "还原")
	if !ok {
		return
	}
	subject := fmt.Sprintf("备份 #%d 文件 %s", view.ID, view.Filename)
	// 目录守卫：相对/空 BackupDir 会在进程 CWD 下解析同名文件（误读非备份
	// 目录文件），与写路径入口 fail-fast 同口径。
	backupDir, dirErr := h.autoBackupDir()
	if dirErr != nil {
		failRestoreFileAccess(c, false, subject, "备份目录无效", http.StatusInternalServerError, dirErr)
		return
	}
	path := filepath.Join(backupDir, view.Filename)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			failRestoreFileAccess(c, false, subject, "备份文件已不存在", http.StatusNotFound, err)
			return
		}
		failRestoreFileAccess(c, false, subject, "读取备份文件失败: "+err.Error(), http.StatusInternalServerError, err)
		return
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		failRestoreFileAccess(c, false, subject, "读取备份文件失败: "+err.Error(), http.StatusInternalServerError, err)
		return
	}
	if info.Size() > maxConfigImportBytes {
		_ = file.Close()
		failRestoreFileAccess(c, false, subject, configImportLimitMessage(), http.StatusRequestEntityTooLarge,
			fmt.Errorf("备份文件 %d 字节超过导入上限 %d 字节", info.Size(), maxConfigImportBytes))
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigImportBytes+1))
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		failRestoreFileAccess(c, false, subject, "读取备份文件失败: "+err.Error(), http.StatusInternalServerError, err)
		return
	}
	if int64(len(data)) > maxConfigImportBytes {
		failRestoreFileAccess(c, false, subject, configImportLimitMessage(), http.StatusRequestEntityTooLarge,
			fmt.Errorf("备份文件读取 %d 字节超过导入上限 %d 字节", len(data), maxConfigImportBytes))
		return
	}
	h.importConfigBackupCore(c, data, view.Filename, "还原")
}

// DownloadAutoBackup GET /api/v1/auto-backup/:id/download：下载备份文件
// （与手动导出同敏感级：备份含私钥与凭证明文，审计留痕）。
func (h *Handlers) DownloadAutoBackup(c *gin.Context) {
	if !h.requireAutoBackupMaster(c) {
		return
	}
	view, ok := h.autoBackupRowByID(c, "下载")
	if !ok {
		return
	}
	subject := fmt.Sprintf("备份 #%d 文件 %s", view.ID, view.Filename)
	// 目录守卫（同还原）：相对/空 BackupDir 不得在 CWD 下读取同名文件。
	backupDir, dirErr := h.autoBackupDir()
	if dirErr != nil {
		failRestoreFileAccess(c, true, subject, "备份目录无效", http.StatusInternalServerError, dirErr)
		return
	}
	path := filepath.Join(backupDir, view.Filename)
	// 句柄先行——os.Open 成功后才审计并流式交付，
	// 消除 Stat→FileAttachment 窗口内备份完成 prune 掉目标文件导致的
	// 打开失败 panic/500 与「审计先于交付」虚记。
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			failRestoreFileAccess(c, true, subject, "备份文件已不存在", http.StatusNotFound, err)
			return
		}
		failRestoreFileAccess(c, true, subject, "读取备份文件失败: "+err.Error(), http.StatusInternalServerError, err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		failRestoreFileAccess(c, true, subject, "读取备份文件失败: "+err.Error(), http.StatusInternalServerError, err)
		return
	}
	c.Header("Cache-Control", "no-store, private")
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", view.Filename))
	c.Header("Content-Length", strconv.FormatInt(fi.Size(), 10))
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, f); err != nil {
		services.Logf("warn", "备份下载交付中断 #%d %s: %v", view.ID, view.Filename, err)
		recordAudit(c, "下载失败", "配置备份", services.FormatAuditDetail(
			fmt.Sprintf("备份 #%d", view.ID), "文件："+view.Filename, "交付中断："+err.Error(), services.AuditResultPart("failure")))
		return
	}
	recordAudit(c, "备份下载", "配置备份", services.FormatAuditDetail(
		fmt.Sprintf("备份 #%d", view.ID), "文件："+view.Filename, "含凭证与证书材料，请加密保管", services.AuditResultPart("success")))
}
