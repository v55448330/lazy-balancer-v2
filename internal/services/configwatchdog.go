package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// ConfigDriftStatus 配置一致性看门狗的当前状态：数据库（唯一事实源）中应渲染的
// 规则与 Caddy 实际运行配置的比对结果。
type ConfigDriftStatus struct {
	Consistent bool     `json:"consistent"`
	Missing    []string `json:"missing"` // 应渲染但运行配置缺失的规则（名称（caddy_id））
	Extra      []string `json:"extra"`   // 运行配置中存在但 DB 已不存在的规则路由
	Since      string   `json:"since"`   // 首次确认不一致的时间（UTC）
	CheckedAt  string   `json:"checked_at"`
}

var (
	configDriftMu         sync.RWMutex
	configDriftStatus     = ConfigDriftStatus{Consistent: true}
	configDriftStreak     int
	configDriftReadWarned bool
)

// ResetConfigDrift 角色切换时重置看门狗状态——曾漂移的主节点降级为从节点后，
// 内存中的陈旧漂移态必须清除（从节点不再运行检查，状态不会自行过期）。
func ResetConfigDrift() {
	configDriftMu.Lock()
	defer configDriftMu.Unlock()
	configDriftStatus = ConfigDriftStatus{Consistent: true}
	configDriftStreak = 0
	configDriftReadWarned = false
}

// CurrentConfigDrift 返回看门狗当前状态（GetCaddyStatus 等展示路径消费）。
func CurrentConfigDrift() ConfigDriftStatus {
	configDriftMu.RLock()
	defer configDriftMu.RUnlock()
	status := configDriftStatus
	status.Missing = append([]string(nil), configDriftStatus.Missing...)
	status.Extra = append([]string(nil), configDriftStatus.Extra...)
	return status
}

// StartConfigWatchdog 主节点每 60s 比对「应渲染规则」与 Caddy 运行配置：不一致时
// 经系统日志 + 操作日志 + GetCaddyStatus（前端全局横幅）三通道告知，连续两轮不一致
// 才置状态（防配置应用窗口的瞬时误报）。从节点不运行——同步链路已有 drift 检测与
// 重载失败标记自愈覆盖。恢复由用户手动重启完成（横幅入口），不做自动重应用。
func StartConfigWatchdog(adminURL string) {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			// 看门狗是唯一消费者，panic 必须留痕而不是让 goroutine 静默死亡。
			func() {
				defer func() {
					if r := recover(); r != nil {
						Logf("error", "配置一致性看门狗：检查 panic: %v", r)
					}
				}()
				checkConfigConsistency(adminURL)
			}()
		}
	}()
}

func checkConfigConsistency(adminURL string) {
	if db.DB == nil {
		return
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	expected, err := expectedRenderedRules()
	if err != nil {
		Logf("warn", "配置一致性看门狗：读取规则失败: %v", err)
		return
	}
	running, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		// Caddy 不可达由 GetCaddyStatus 的 status 通道报告；但「配置超解析上限/
		// 解析失败」会让看门狗永久静默——须留痕（首次失败告警，恢复后复位）。
		configDriftMu.Lock()
		if !configDriftReadWarned {
			configDriftReadWarned = true
			Logf("warn", "配置一致性看门狗：读取运行配置失败（本轮起跳过检查）: %v", err)
		}
		configDriftMu.Unlock()
		return
	}
	configDriftMu.Lock()
	configDriftReadWarned = false
	configDriftMu.Unlock()
	updateConfigDrift(diffExpectedMissing(expected, running), diffRunningExtra(expected, running))
}

// expectedRenderedRules 计算应出现在运行配置中的规则：启用中且至少有一个启用上游
// （零上游规则渲染跳过是正常语义，不计入——与 caddy.go 的渲染口径一致）。
// 返回 caddy_id → 规则名称。
func expectedRenderedRules() (map[string]string, error) {
	rows, err := db.DB.Query(`SELECT caddy_id, name FROM lb_rules WHERE enabled=1
		AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id=lb_rules.caddy_id AND IIF(u.enabled IN ('1',1),1,0)=1)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	expected := make(map[string]string)
	for rows.Next() {
		var caddyID, name string
		if err := rows.Scan(&caddyID, &name); err != nil {
			return nil, err
		}
		expected[caddyID] = name
	}
	return expected, rows.Err()
}

// runningRuleRouteIDs 从 Caddy 运行配置收集规则路由 @id（lb_ 前缀），
// 覆盖 http 与 layer4 两类服务器。
func runningRuleRouteIDs(adminURL string) (map[string]bool, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(adminURL, "/") + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin status %d", resp.StatusCode)
	}
	var config map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&config); err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	apps, _ := config["apps"].(map[string]interface{})
	for _, appName := range []string{"http", "layer4"} {
		app, _ := apps[appName].(map[string]interface{})
		servers, _ := app["servers"].(map[string]interface{})
		for _, srv := range servers {
			routes, _ := srv.(map[string]interface{})["routes"].([]interface{})
			for _, route := range routes {
				if id, ok := route.(map[string]interface{})["@id"].(string); ok && strings.HasPrefix(id, "lb_") {
					ids[id] = true
				}
			}
		}
	}
	return ids, nil
}

func diffExpectedMissing(expected map[string]string, running map[string]bool) []string {
	var missing []string
	for caddyID, name := range expected {
		if !running[caddyID] {
			missing = append(missing, fmt.Sprintf("%s（%s）", name, caddyID))
		}
	}
	return missing
}

func diffRunningExtra(expected map[string]string, running map[string]bool) []string {
	var extra []string
	for routeID := range running {
		// 子路由（lb_x_redirect / lb_x_path_0 等，caddy.go tagRuleRoute 系）属于其
		// 主规则——仅当没有任何期望规则认领该 @id 时才计为多余（R36 WD-1：
		// 精确匹配会把每条 HTTPS 跳转/路径规则的子路由误报为多余）。
		if !routeClaimedByAny(routeID, expected) {
			extra = append(extra, routeID)
		}
	}
	return extra
}

func routeClaimedByAny(routeID string, expected map[string]string) bool {
	for caddyID := range expected {
		if routeID == caddyID || strings.HasPrefix(routeID, caddyID+"_") {
			return true
		}
	}
	return false
}

func updateConfigDrift(missing, extra []string) {
	drifted := len(missing) > 0 || len(extra) > 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	configDriftMu.Lock()
	defer configDriftMu.Unlock()
	if !drifted {
		if !configDriftStatus.Consistent {
			Logf("info", "配置一致性看门狗：运行配置与规则数据已恢复一致")
			RecordAuditLog("system", "配置恢复", "Caddy配置", "运行配置与规则数据已恢复一致", "")
		}
		configDriftStreak = 0
		configDriftStatus = ConfigDriftStatus{Consistent: true, CheckedAt: now}
		return
	}
	configDriftStreak++
	if configDriftStatus.Consistent && configDriftStreak < 2 {
		configDriftStatus.CheckedAt = now
		return
	}
	if configDriftStatus.Consistent {
		detail := formatDriftDetail(missing, extra)
		Logf("error", "配置一致性看门狗：%s", detail)
		RecordAuditLog("system", "配置不一致", "Caddy配置", detail, "")
		configDriftStatus = ConfigDriftStatus{Consistent: false, Since: now}
	}
	configDriftStatus.Missing = missing
	configDriftStatus.Extra = extra
	configDriftStatus.CheckedAt = now
}

func formatDriftDetail(missing, extra []string) string {
	parts := make([]string, 0, 2)
	if len(missing) > 0 {
		parts = append(parts, "缺失规则路由: "+strings.Join(missing, "、"))
	}
	if len(extra) > 0 {
		parts = append(parts, "多余规则路由: "+strings.Join(extra, "、"))
	}
	return "运行配置与规则数据不一致（" + strings.Join(parts, "；") + "），请重启服务恢复"
}
