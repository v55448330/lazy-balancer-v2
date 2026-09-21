package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 安全测试事件生成/清除（R45 验证辅助，用户裁定）：向 metrics 库生成固定
// 标记的 curated 事件集，覆盖阶段化安全流水线各消费链（事件列表族筛选、
// 总览攻击分类与今日口径、stage-stats 分桶、IP 弹框计数）验证所需的代表
// 形状。全部行 rule_caddy_id 恒为 securityTestEventMarker，清除仅删标记
// 行——用户真实事件（含同 IP 真实命中）永不受影响。写入只落 metrics 库，
// 不触碰主库与 Caddy 配置（零渲染）。

// securityTestEventMarker 是测试事件的固定标记列值：生成侧写入、清除侧删除
// 的唯一判据。
const securityTestEventMarker = "lb_testevent"

// securityTestEvent 是 curated 集中的一条事件。timeOffset 为 SQLite
// datetime 的相对偏移（datetime('now', offset)），使生成时刻的分布恒定：
// 近 1h 一簇验证 24h 窗内口径，-20h 验证总览今日/昨日边界，-30h 验证 24h
// 窗外排除。msg 文案对齐引擎真实发射（id:2/4/7/8/11 与预检 800xxx 段、
// 自定义规则、CRS 942100/949110），保证 UI 归因与族分类按真实路径渲染。
type securityTestEvent struct {
	timeOffset    string
	ruleTriggered string
	ruleMsg       string
	action        string
	clientIP      string
	anomalyScore  int
}

// generatedSecurityTestEvents 返回 curated 事件集（12 条）。形状设计：
//   - 阶段 1 引擎：id:2（ACL deny）、id:4（遗留黑名单）、id:7（allow 模式
//     交集外拒绝）各一条 blocked；
//   - GeoIP：遗留共享 id:8 一条（策略引擎时代历史形状）、预检精确段
//     800001/800499 各一条——属主解析走查询侧（绑定策略存在时精确命中，
//     无绑定时 geoipFamilyCondition fallback 同样承接）；
//   - 阶段 3：942100（SQL 注入族）、949110（评分拦截）、10005/10006（自定义
//     规则拦截/仅记录）、11（请求体异常）各一条；
//   - detection 口径：942100 logged 一条（与 blocked 同族不同动作，验证
//     今日检测计数）；该行 msg 留空（历史事件缺 msg 文案的形状）；
//   - rule_msg 多样性：949110 文案含逗号，多条中文文案，一条空串——族筛选
//     输入解析不得受 msg 内容干扰。
func generatedSecurityTestEvents() []securityTestEvent {
	return []securityTestEvent{
		{timeOffset: "-5 minutes", ruleTriggered: "2", ruleMsg: "IP 黑名单拒绝", action: "blocked", clientIP: "198.51.100.10"},
		{timeOffset: "-15 minutes", ruleTriggered: "4", ruleMsg: "IP 黑名单", action: "blocked", clientIP: "198.51.100.23"},
		{timeOffset: "-30 minutes", ruleTriggered: "7", ruleMsg: "IP 白名单拒绝", action: "blocked", clientIP: "198.51.100.45"},
		{timeOffset: "-45 minutes", ruleTriggered: "800001", ruleMsg: "GeoIP 区域拦截", action: "blocked", clientIP: "2001:db8::15"},
		{timeOffset: "-55 minutes", ruleTriggered: "942100", ruleMsg: "SQL Injection Attack Detected via libinjection", action: "blocked", clientIP: "198.51.100.10", anomalyScore: 5},
		{timeOffset: "-2 hours", ruleTriggered: "949110", ruleMsg: "Inbound Anomaly Score Exceeded (Total Score: 7, libinjection: 5)", action: "blocked", clientIP: "203.0.113.77", anomalyScore: 7},
		{timeOffset: "-3 hours", ruleTriggered: "10005", ruleMsg: "自定义规则 拦截测试 命中", action: "blocked", clientIP: "198.51.100.10"},
		{timeOffset: "-4 hours", ruleTriggered: "10006", ruleMsg: "自定义规则 仅记录观察 命中", action: "logged", clientIP: "198.51.100.23"},
		{timeOffset: "-6 hours", ruleTriggered: "11", ruleMsg: "请求体解析失败", action: "blocked", clientIP: "198.51.100.45", anomalyScore: 5},
		{timeOffset: "-8 hours", ruleTriggered: "942100", ruleMsg: "", action: "logged", clientIP: "203.0.113.77"},
		{timeOffset: "-20 hours", ruleTriggered: "8", ruleMsg: "GeoIP 区域拦截", action: "blocked", clientIP: "203.0.113.77"},
		{timeOffset: "-30 hours", ruleTriggered: "800499", ruleMsg: "GeoIP 区域拦截", action: "blocked", clientIP: "2001:db8::15"},
	}
}

// CreateSecurityTestEvents 生成 curated 测试事件集（管理员）。响应
// data.inserted 为实际插入行数；data.hint 提示测试数据会进入安全总览与
// stage-stats 统计、可用本组 DELETE 端点清除。重复生成允许累积（不幂等），
// 清除一次全净。
func (h *Handlers) CreateSecurityTestEvents(c *gin.Context) {
	if db.MetricsDB == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "metrics 数据库不可用"})
		return
	}
	events := generatedSecurityTestEvents()
	tx, err := db.MetricsDB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer tx.Rollback()
	inserted := 0
	for _, e := range events {
		res, err := tx.ExecContext(c.Request.Context(), `INSERT INTO security_events
			(event_time, rule_caddy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score)
			VALUES (datetime('now', ?), ?, ?, 'GET', '/lb-test-path', 'waf', ?, ?, ?, ?)`,
			e.timeOffset, securityTestEventMarker, e.clientIP, e.ruleTriggered, e.ruleMsg, e.action, e.anomalyScore)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		if n, err := res.RowsAffected(); err == nil {
			inserted += int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	recordAudit(c, "生成", "测试事件", services.FormatAuditDetail(
		fmt.Sprintf("标记：%s", securityTestEventMarker),
		fmt.Sprintf("插入：%d 条", inserted),
		"测试数据计入安全总览与规则阶段统计，可用清除端点删除"))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全测试事件已生成", Data: gin.H{
		"inserted": inserted,
		"hint":     "测试数据已计入安全总览与阶段统计，可通过 DELETE /api/v1/security/test-events 清除",
	}})
}

// DeleteSecurityTestEvents 清除全部标记行（管理员），响应 data.deleted 为
// 实际删除行数（RowsAffected）——非标记行（用户真实事件）不受影响。
func (h *Handlers) DeleteSecurityTestEvents(c *gin.Context) {
	if db.MetricsDB == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "metrics 数据库不可用"})
		return
	}
	res, err := db.MetricsDB.ExecContext(c.Request.Context(),
		`DELETE FROM security_events WHERE rule_caddy_id = ?`, securityTestEventMarker)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	deleted := int64(0)
	if n, err := res.RowsAffected(); err == nil {
		deleted = n
	}
	recordAudit(c, "清除", "测试事件", services.FormatAuditDetail(
		fmt.Sprintf("标记：%s", securityTestEventMarker),
		fmt.Sprintf("删除：%d 条", deleted)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "安全测试事件已清除", Data: gin.H{
		"deleted": deleted,
	}})
}
