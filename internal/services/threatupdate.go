package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/wafiplist"
)

// 威胁情报库（v2.3.x）：三个内置只读源（USTC/FireHOL level1/ET Compromised）
// 的单一顺序更新任务。状态机镜像 CRS/IP2Region 更新族（idle/running/
// success/failed + 失败指数退避），差异：多行表（每源一行状态）、产物为
// 纯文本名单（无内存热换——@ipListFast 算子按 mtime/size 自动重建）。

var ErrThreatUpdateRunning = errors.New("威胁情报库更新任务正在进行中")

// ThreatDataDir 是威胁库文件目录（每源 <name>.txt + 合并 intel-merged.txt）。
// 测试可改。
var ThreatDataDir = "/app/waf/threat"

const (
	threatMaxBodyBytes   = 16 << 20 // 16MB
	threatMaxEntries     = 200000
	threatMinParseRatio  = 0.5
	threatDownloadTimout = 30 * time.Second
)

type ThreatUpdateManager struct {
	mu            sync.Mutex
	running       bool
	runDone       chan struct{}
	schedulerStop chan struct{}
	schedulerDone chan struct{}
}

// nil-until-init（镜像 CRS/IP2Region 管理器）：仅 main.go 初始化——集群
// promote/demote 路径的 SetMasterRole 在测试二进制中经 nil 守卫跳过，
// 不会把调度器（首轮即下载）带进无关测试。
var threatUpdateManager *ThreatUpdateManager

// InitThreatUpdateManager 初始化单例（main.go 启动装配调用一次）。
func InitThreatUpdateManager() {
	threatUpdateManager = &ThreatUpdateManager{}
}

func GetThreatUpdateManager() *ThreatUpdateManager {
	return threatUpdateManager
}

// ResetThreatUpdateManagerForTest 换成全新实例（含停调度器）——测试二进制
// 中初始化入口（main 不运行），同时切断跨测试的 running/调度器残留。
func ResetThreatUpdateManagerForTest() {
	if threatUpdateManager != nil {
		threatUpdateManager.StopScheduler()
	}
	threatUpdateManager = &ThreatUpdateManager{}
}

func (m *ThreatUpdateManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// RebuildMergedFile 导出合并重建（apply 开关变更后由 handler 调用，
// 使 id:14 规则随新开关即时收敛，无需等下次更新任务）。
func (m *ThreatUpdateManager) RebuildMergedFile() {
	m.rebuildMergedFile()
}

// threatReloader 合并文件变化后的 Caddy 重载（main.go 注入 caddyReloader；
// 镜像 CRS/IP2Region 更新后 reloader 同族——否则 id:14 拦截面不随更新收敛）。
var threatReloader func() error

// SetThreatReloader 注册重载回调（nil=清除，测试用）。
func SetThreatReloader(fn func() error) {
	threatReloader = fn
}

// StartUpdate 异步启动更新任务（单实例在飞）；返回完成通道。
func (m *ThreatUpdateManager) StartUpdate(trigger string) (chan struct{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil, ErrThreatUpdateRunning
	}
	m.running = true
	m.runDone = make(chan struct{})
	done := m.runDone
	go func() {
		defer close(done)
		m.run(trigger)
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	return done, nil
}

// RunUpdate 同步执行更新任务（测试与内部路径）。
func (m *ThreatUpdateManager) RunUpdate(trigger string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrThreatUpdateRunning
	}
	m.running = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	m.run(trigger)
	return nil
}

type threatSourceRow struct {
	id            int
	name          string
	url           string
	updateEnabled bool
	applyEnabled  bool
}

// threatDueSources 返回本次任务处理的源：manual=全部启用源；auto=启用且到期
// （next_update 空或已过）——失败源按退避排程单独重试，不拖累健康源的重下载。
func threatDueSources(trigger string) ([]threatSourceRow, error) {
	rows, err := db.DB.Query(`SELECT id, name, url, update_enabled, apply_enabled, COALESCE(next_update,'')
		FROM security_threat_sources WHERE update_enabled=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []threatSourceRow
	now := time.Now().UTC()
	for rows.Next() {
		var s threatSourceRow
		var nextUpdate string
		if err := rows.Scan(&s.id, &s.name, &s.url, &s.updateEnabled, &s.applyEnabled, &nextUpdate); err != nil {
			return nil, err
		}
		if trigger != "manual" && nextUpdate != "" {
			if due, err := time.Parse(crsTimeLayout, nextUpdate); err == nil && now.Before(due) {
				continue
			}
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

func (m *ThreatUpdateManager) run(trigger string) {
	sources, err := threatDueSources(trigger)
	if err != nil {
		Logf("error", "威胁情报库: 读取源列表失败: %v", err)
		return
	}
	if len(sources) == 0 {
		return
	}
	for _, source := range sources {
		m.updateOneSource(source, trigger)
	}
	if m.rebuildMergedFile() && threatReloader != nil {
		if err := threatReloader(); err != nil {
			Logf("error", "威胁情报库: 合并文件变化后重载失败: %v", err)
		}
	}
}

// updateOneSource 下载→解析→写文件→更新行状态；失败仅影响该源。
func (m *ThreatUpdateManager) updateOneSource(source threatSourceRow, trigger string) {
	now := time.Now().UTC()
	nowStr := now.Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='running', message='', trigger=?, started_at=?, last_checked=?, updated_at=datetime('now') WHERE id=?`,
		trigger, nowStr, nowStr, source.id); err != nil {
		Logf("error", "威胁情报库: 标记源 %s 运行中失败: %v", source.name, err)
		return
	}

	entries, err := downloadAndParseThreatSource(source)
	finished := time.Now().UTC().Format(crsTimeLayout)
	if err != nil {
		failSourceRow(source.id, finished, err)
		return
	}

	// 条目文件（原子写；空名单写空文件——源合法为空时该源贡献零条目）
	path := filepath.Join(ThreatDataDir, source.name+".txt")
	if err := writeTextFileAtomic(path, strings.Join(entries, "\n")+"\n"); err != nil {
		failSourceRow(source.id, finished, fmt.Errorf("写入源文件失败: %w", err))
		return
	}
	version := time.Now().UTC().Format("2006.01.02")
	next := time.Now().UTC().Add(24 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='success', message='', entry_count=?, version=?, finished_at=?, next_update=?, consecutive_failures=0, updated_at=datetime('now') WHERE id=?`,
		len(entries), version, finished, next, source.id); err != nil {
		Logf("error", "威胁情报库: 更新源 %s 成功状态失败: %v", source.name, err)
	}
	Logf("info", "威胁情报库: 源 %s 更新成功（%d 条，版本 %s）", source.name, len(entries), version)
}

// failSourceRow 失败落库：status=failed + message + consecutive_failures+1 +
// 指数退避 next_update（1h→2h→4h→8h→24h 封顶，镜像 CRS/IP2Region 语义）。
func failSourceRow(id int, finished string, cause error) {
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET consecutive_failures=consecutive_failures+1 WHERE id=?`, id); err != nil {
		Logf("error", "威胁情报库: 失败计数更新失败: %v", err)
	}
	var failures int
	if err := db.DB.QueryRow(`SELECT consecutive_failures FROM security_threat_sources WHERE id=?`, id).Scan(&failures); err != nil {
		failures = 1
	}
	next := time.Now().UTC().Add(updateRetryBackoff(failures)).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='failed', message=?, finished_at=?, next_update=?, updated_at=datetime('now') WHERE id=?`,
		cause.Error(), finished, next, id); err != nil {
		Logf("error", "威胁情报库: 失败状态落库失败: %v", err)
	}
	Logf("warn", "威胁情报库: 源更新失败: %v", cause)
}

// downloadAndParseThreatSource 下载并解析单源（format=plain）：
// 30s 超时、HTTP 200、body ≤16MB；空行与 #/; 注释跳过；可解析行比例 <50%
// 判失败（防错页/HTML 劫持）；条目 >200000 拒绝。
func downloadAndParseThreatSource(source threatSourceRow) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), threatDownloadTimout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, threatMaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if len(body) > threatMaxBodyBytes {
		return nil, fmt.Errorf("响应体超过 16MB 上限")
	}

	var entries []string
	total := 0
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		total++
		if _, err := parseThreatEntry(line); err == nil {
			entries = append(entries, line)
		}
	}
	if total == 0 {
		return nil, fmt.Errorf("响应无可解析条目（空名单）")
	}
	if float64(len(entries))/float64(total) < threatMinParseRatio {
		return nil, fmt.Errorf("可解析行比例 %d/%d 低于 50%%——疑似错页或劫持", len(entries), total)
	}
	if len(entries) > threatMaxEntries {
		return nil, fmt.Errorf("条目数 %d 超过 200000 上限", len(entries))
	}
	return entries, nil
}

func parseThreatEntry(entry string) (any, error) {
	return wafiplist.ParseIPEntry(entry)
}

// rebuildMergedFile 取全部 apply_enabled 源的当前条目文件并集（含失败源的
// 上次成功文件——失败不清空已生效判定），聚合后原子写 intel-merged.txt；
// 全部源关闭应用时删除合并文件（预检 id:14 随之跳过）。
// 返回 changed=合并文件内容真实变化（调用方据此决定是否重载 Caddy）。
func (m *ThreatUpdateManager) rebuildMergedFile() bool {
	rows, err := db.DB.Query(`SELECT name FROM security_threat_sources WHERE apply_enabled=1 ORDER BY id`)
	if err != nil {
		Logf("error", "威胁情报库: 读取应用开关失败: %v", err)
		return false
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			Logf("error", "威胁情报库: 扫描应用开关失败: %v", err)
			return false
		}
		names = append(names, name)
	}
	rows.Close()

	mergedPath := filepath.Join(ThreatDataDir, "intel-merged.txt")
	var union []string
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(ThreatDataDir, name+".txt"))
		if err != nil {
			continue // 无文件（从未成功/被禁用更新）——该源本轮无贡献
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				union = append(union, line)
			}
		}
	}
	if len(union) == 0 {
		if _, statErr := os.Stat(mergedPath); statErr == nil {
			_ = os.Remove(mergedPath)
			return true
		}
		return false
	}
	merged := wafiplist.AggregateIPEntries(union)
	newContent := strings.Join(merged, "\n") + "\n"
	if old, readErr := os.ReadFile(mergedPath); readErr == nil && string(old) == newContent {
		return false
	}
	if err := writeTextFileAtomic(mergedPath, newContent); err != nil {
		Logf("error", "威胁情报库: 合并文件写入失败: %v", err)
		return false
	}
	Logf("info", "威胁情报库: 合并生效 %d 条（%d 源）", len(merged), len(names))
	return true
}

// writeTextFileAtomic tmp+rename 原子写。
func writeTextFileAtomic(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
