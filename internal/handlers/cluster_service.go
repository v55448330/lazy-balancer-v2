package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// clusterServiceControlMaxBytes 限制服务控制请求体大小（票据 + 动作合法载荷
// 恒 <2KB；与节点上报端点 clusterReportMaxBytes 同模式的防滥用边界）。
const clusterServiceControlMaxBytes int64 = 64 << 10

// clusterServiceExitDelay / clusterServiceExit：restart_app「先应答后退出」的
// 延迟与退出注入点（生产=os.Exit(0)，容器 restart: unless-stopped 拉起；
// 测试替换为 channel 信号，与 caddyRunCommand/caddyStopCommand 同模式）。
var clusterServiceExitDelay = time.Second
var clusterServiceExit = func() { os.Exit(0) }

// clusterServiceControlClientFactory 为主节点→从节点调用构造 HTTP 客户端的
// 注入点（默认走 TOFU 指纹校验；测试直连 httptest 桩从节点）。
var clusterServiceControlClientFactory = func(dataDir string) *http.Client {
	return services.NewClusterControlHTTPClient(dataDir, db.DB)
}

type clusterServiceControlRejection struct{ message string }

func (e *clusterServiceControlRejection) Error() string {
	return "从节点拒绝服务控制请求：" + e.message
}

// ControlClusterNodeService 主节点端点（admin + mfaWriteGuard 语义由路由组承担）：
// 签发一次性 HMAC 服务控制票据 → 转发从节点 /cluster/service-control →
// 中继结果并记录主节点审计。
func (h *Handlers) ControlClusterNodeService(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterMachineBodyLimitBytes)
	if !h.requireMaster(c) {
		return
	}
	// 特权服务控制的所有失败早退（编号非法/体解析失败/
	// 动作不支持/票据签发失败）此前零审计，越权探测与故障签发在操作日志中不可见。
	// 统一经 recordAudit 留痕「失败」；动作串经 registerAuditField 截断去控制字符。
	auditFailure := func(nodeID int, detail string) {
		// 路径参数未清洗：已认证管理员可经 %0A 等注入换行/控制字符伪造审计
		// 段落。与 action/operator 同源走 registerAuditField（去控制字符 +
		// 128B 截断），可打印原值保留供取证。
		nodePart := "节点 " + registerAuditField(c.Param("id"))
		if nodeID > 0 {
			nodePart = fmt.Sprintf("节点 %d", nodeID)
		}
		recordAudit(c, "服务控制", "节点服务", services.FormatAuditDetail(nodePart, detail, "结果：失败"))
	}
	nodeID, err := strconv.Atoi(c.Param("id"))
	if err != nil || nodeID <= 0 {
		auditFailure(nodeID, "节点编号无效")
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.nodeIdInvalid", err))
		return
	}
	var req models.ClusterNodeServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		auditFailure(nodeID, "请求格式错误")
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "common.malformedRequest", err))
		return
	}
	if !models.IsValidClusterServiceAction(req.Action) {
		auditFailure(nodeID, "动作："+registerAuditField(req.Action)+"（不支持）")
		c.JSON(http.StatusBadRequest, clusterErrorKeyedResponse(http.StatusBadRequest, "cluster.unsupportedServiceControlAction", nil))
		return
	}
	issued, err := h.clusterService.IssueServiceControlTicket(c.Request.Context(), nodeID, req.Action, time.Now())
	if err != nil {
		// 服务层降级竞态：handler 角色门通过后节点簿记已降级——与 requireMaster
		// 门同源 403（携带 X-LB-Error-Code），不得折叠成 404/500。
		if errors.Is(err, services.ErrNotMasterNode) {
			auditFailure(nodeID, "签发票据失败（动作："+registerAuditField(req.Action)+"）")
			clusterMasterForbidden(c, err)
			return
		}
		status := http.StatusInternalServerError
		message := "签发服务控制票据失败"
		key := "cluster.issueServiceControlTicketFailed"
		switch {
		case errors.Is(err, services.ErrNodeNotFound):
			status = http.StatusNotFound
		case errors.Is(err, services.ErrNodeTokenPending):
			// 已批准但令牌尚未交付：节点存在、只是暂不可签发——409 + 单源文案。
			status = http.StatusConflict
			message = err.Error()
			key = ""
			// ErrInvalidServiceAction 不可达：handler 已在入口对非法动作先行 400
			// （服务层校验是同一谓词首语句），此处无需 400 分支。
		}
		auditFailure(nodeID, "签发票据失败（动作："+registerAuditField(req.Action)+"）")
		emitClusterError(c, status, message, key, err)
		return
	}
	message, err := h.callClusterServiceControl(c.Request.Context(), issued.URL, req.Action, issued.Ticket, currentUsername(c))
	result := "成功"
	if err != nil {
		result = "失败"
	}
	recordAudit(c, "服务控制", "节点服务", services.FormatAuditDetail(
		// 补节点 ID(nodes.name 无 UNIQUE,仅名无法定位行)。
		fmt.Sprintf("节点 %d（%s）", nodeID, issued.NodeName), "操作："+req.Action, "结果："+result))
	if err != nil {
		var rejected *clusterServiceControlRejection
		if errors.As(err, &rejected) {
			c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: rejected.message})
			return
		}
		// 指纹不匹配必须与通用不可达区分下发——否则前端无法提示
		//「清除该节点证书指纹」补救通道（该信息此前只进服务端日志）。
		if errors.Is(err, services.ErrClusterPinMismatch) {
			// 结构化语义键 cluster.pinMismatch（与文案解耦，前端按 message_key
			// 判定补救通道），与从节点侧 sync_error_code 同口径。
			c.JSON(http.StatusBadGateway, clusterErrorKeyedResponse(http.StatusBadGateway, "cluster.pinMismatch", err))
			return
		}
		c.JSON(http.StatusBadGateway, clusterErrorKeyedResponse(http.StatusBadGateway, "cluster.nodeUnreachable", err))
		return
	}
	notify.Publish(notify.Event{Type: notify.EvtClusterServiceControl, Fields: map[string]string{"1": c.GetString("username"), "2": fmt.Sprintf("节点 %d（%s）", nodeID, issued.NodeName), "3": clusterServiceActionLabel(req.Action), "4": "成功"}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

// clusterServiceActionLabel 服务控制动作码→中文操作名（事件正文单源）：
// 通知正文不得直出内部动作码（start_caddy/restart_app 对收件人无意义）。
// 未知码原样返回（fail-visible：上游已由 IsValidClusterServiceAction 拦截，
// 未知值只可能来自未来新增动作的漏映射，原样可见比静默空串更可排障）。
func clusterServiceActionLabel(action string) string {
	switch action {
	case models.ClusterServiceActionStartCaddy:
		return "启动 Caddy"
	case models.ClusterServiceActionStopCaddy:
		return "停止 Caddy"
	case models.ClusterServiceActionRestartCaddy:
		return "重启 Caddy"
	case models.ClusterServiceActionRestartApp:
		return "重启面板应用"
	default:
		return action
	}
}

func (h *Handlers) callClusterServiceControl(ctx context.Context, baseURL, action, ticket, operator string) (string, error) {
	payload, err := json.Marshal(models.ClusterServiceControlRequest{Action: action, Ticket: ticket, Operator: operator})
	if err != nil {
		return "", fmt.Errorf("编码服务控制请求: %w", err)
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/v1/cluster/service-control"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("构造服务控制请求: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	// 从节点启用管理 HTTPS 后明文端口 301——按集群同步
	// 同一契约对同主机 https Location 重放一次，否则票据调用在空 body 上报解析
	// 错误、服务控制全线不可用。
	// 客户端按请求构造（工厂是测试注入点），其 Transport 自带连接池
	// 且 IdleConnTimeout=90s——此前无关闭动作，每次控制调用都会留下一批空闲
	// 连接与读循环 goroutine 直到空闲超时。用完即关闭空闲连接（body 已读完后
	// 才执行，不影响本次请求）。
	client := clusterServiceControlClientFactory(h.cfg.DataDir)
	defer client.CloseIdleConnections()
	response, err := services.DoWithSameHostTLSUpgradeRedirect(client, request)
	if err != nil {
		return "", fmt.Errorf("调用从节点服务控制: %w", err)
	}
	defer response.Body.Close()
	// 同主机 https 升级已由 DoWithSameHostTLSUpgradeRedirect
	// 重放，残留 3xx（跨主机/反代重定向）的空 body 落进 JSON 解析只会报
	// 「unexpected end of JSON input」——与集群同步 Pull/Register 3xx 分支同款
	// 可行动指引，在读 body 前拦截。
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return "", fmt.Errorf("从节点返回 %d 重定向(%s)——从节点启用 HTTPS 后请将该节点的访问地址改为 https://，或修正反向代理配置后重试", response.StatusCode, response.Header.Get("Location"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, clusterServiceControlMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("读取从节点响应: %w", err)
	}
	// 与同族读端点一致的 limit+1 探测：超限显式报错，不把截断体交给 JSON
	// 解析（只会得到「unexpected end of JSON input」并掩盖真实原因）。
	if int64(len(body)) > clusterServiceControlMaxBytes {
		return "", fmt.Errorf("从节点响应超过 %dKB 读取上限", clusterServiceControlMaxBytes>>10)
	}
	var slaveResponse models.APIResponse
	if err := json.Unmarshal(body, &slaveResponse); err != nil {
		return "", fmt.Errorf("解析从节点响应（HTTP %d）: %w", response.StatusCode, err)
	}
	if response.StatusCode != http.StatusOK || slaveResponse.Code != 0 {
		message := slaveResponse.Message
		if message == "" {
			message = fmt.Sprintf("HTTP %d", response.StatusCode)
		}
		return "", &clusterServiceControlRejection{message: message}
	}
	if slaveResponse.Message == "" {
		slaveResponse.Message = "操作已完成"
	}
	return slaveResponse.Message, nil
}

// ClusterServiceControl 从节点端点：凭主节点签发的一次性票据执行服务控制
// （start/stop/restart Caddy、重启应用），全部路径记录从节点审计，
// 票据正文不落任何日志。
func (h *Handlers) ClusterServiceControl(c *gin.Context) {
	if !h.requireClusterService(c) {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterServiceControlMaxBytes)
	var req models.ClusterServiceControlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// 解析失败时 Action 多为零值空串，审计
		// 「操作：」段落空——无法区分「动作未知的畸形请求」。部分绑定成功的
		// 形态保留实际动作，空串以「<解析失败>」占位符显式留痕。
		action := req.Action
		if action == "" {
			action = "<解析失败>"
		}
		recordClusterServiceControlAudit(c, action, "失败：请求格式错误")
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, http.StatusBadRequest, "common.malformedRequest"))
		return
	}
	if !models.IsValidClusterServiceAction(req.Action) {
		recordClusterServiceControlAudit(c, req.Action, "失败：不支持的动作")
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, http.StatusBadRequest, "cluster.unsupportedServiceControlAction"))
		return
	}
	// 导入窗口内的 Caddy 启停会与导入会话互抢 caddyOpMu（导入自
	// beginConfigImport 起到 close() 全程持有该锁）：主节点侧票据调用 60s 超时
	// 判失败、从节点稍后锁释放仍执行——双向审计相反且终态不可知。与本族写
	// 端点同口径 409 fast-fail。位置在票据校验前（窗口内拒绝不得消费一次性
	// 票据，主节点重试不必重新注册），且仅收 caddy 动作——restart_app 的进程
	// 退出本身会终结导入会话，不存在「超时判失败后仍执行」的双向错位。
	// 留痕口径如实披露：rejectWriteDuringImport 全局统一 409 响应不留操作
	// 审计（导入窗拒绝是瞬态门控，权威痕迹在导入会话审计与访问日志）——
	// 本端点票据校验后的失败路径有审计，窗口 409 分支无，属全局门控有意
	// 口径而非本端点遗漏（补留痕须改全局门，影响全部写端点）。
	if req.Action != models.ClusterServiceActionRestartApp {
		if rejectWriteDuringImport(c, "执行服务控制（配置导入进行中）") {
			return
		}
	}
	if err := h.clusterService.ValidateServiceControlTicket(c.Request.Context(), req.Ticket, req.Action, time.Now()); err != nil {
		if errors.Is(err, services.ErrInvalidServiceControlTicket) {
			recordClusterServiceControlAudit(c, req.Action, "失败：票据校验未通过（"+serviceControlTicketFailureReason(err)+"）")
			c.JSON(http.StatusUnauthorized, clusterErrorKeyedResponse(http.StatusUnauthorized, "cluster.serviceControlTicketInvalid", err))
			return
		}
		recordClusterServiceControlAudit(c, req.Action, "失败：票据校验出错")
		c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.serviceControlTicketValidationFailed", err))
		return
	}
	if req.Action == models.ClusterServiceActionRestartApp {
		// 与 caddy 分支同口径带 operator——空 operator 回退「主节点」，
		// 非空则记录主节点侧实际操作人（此前 restart_app 恒匿名）。
		recordClusterServiceControlAuditBy(c, req.Action, "已接受：服务即将重启", req.Operator)
		c.JSON(http.StatusOK, apimsg.Envelope(c, 0, "system.serviceRestarting"))
		go func() {
			time.Sleep(clusterServiceExitDelay)
			clusterServiceExit()
		}()
		return
	}
	message, err := h.executeClusterCaddyAction(req.Action)
	if err != nil {
		recordClusterServiceControlAuditBy(c, req.Action, "失败："+err.Error(), req.Operator)
		// 5xx 固定文案：本端点凭一次性票据可达（v1 组，非 admin 会话），
		// 底层错误（admin 地址/exec 退出码/路径）不得直出——详情由上方
		// 从节点审计留痕（经 RedactCaddyAdminEndpoint 脱敏）+运行日志承担，
		// 与票据校验失败分支（固定文案+clusterError 日志）同口径。
		services.Logf("error", "cluster service-control: action %s failed: %v", req.Action, err)
		c.JSON(http.StatusInternalServerError, apimsg.Envelope(c, http.StatusInternalServerError, "cluster.serviceControlFailed"))
		return
	}
	// 成功消息一并落审计——从节点操作日志可见「配置已从数据库载入」等
	// 实际执行细节(原仅记「成功」,消息只回传主节点不落从节点审计)
	recordClusterServiceControlAuditBy(c, req.Action, "成功："+message, req.Operator)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

// serviceControlTicketFailureReason 把票据校验的细分哨兵翻成审计可读原因：
// 运维据此区分「票据已使用（重放，无需重新注册）」与「签名错误（节点集群
// 凭证不一致，需重新注册）」等不同补救路径。
func serviceControlTicketFailureReason(err error) string {
	switch {
	case errors.Is(err, services.ErrServiceControlSignature):
		return "签名错误"
	case errors.Is(err, services.ErrServiceControlExpired):
		return "已过期"
	case errors.Is(err, services.ErrServiceControlReplay):
		return "已使用"
	default:
		return "无效"
	}
}

// executeClusterCaddyAction 与本机 /caddy/start|stop|restart handler 同一锁序
// （caddyOpMu 全程互斥），Caddy 启停后重放数据库生成的权威配置。
func (h *Handlers) executeClusterCaddyAction(action string) (string, error) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	switch action {
	case models.ClusterServiceActionStartCaddy:
		if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
			return "", err
		}
		if note := h.caddyApplyNoteLocked(); note != "" {
			return "", errors.New("Caddy 已启动" + note)
		}
		return "Caddy 已启动（配置已从数据库载入）", nil
	case models.ClusterServiceActionStopCaddy:
		if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
			return "", err
		}
		return "Caddy 已停止", nil
	case models.ClusterServiceActionRestartCaddy:
		if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
			return "", err
		}
		if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
			return "", err
		}
		if note := h.caddyApplyNoteLocked(); note != "" {
			return "", errors.New("Caddy 已重启" + note)
		}
		return "Caddy 已重启（配置已从数据库载入）", nil
	}
	return "", fmt.Errorf("不支持的服务控制动作：%s", action)
}

func recordClusterServiceControlAudit(c *gin.Context, action, result string) {
	recordClusterServiceControlAuditBy(c, action, result, "")
}

// recordClusterServiceControlAuditBy 带 operator 版——从节点审计记录主节点侧
// 操作人。已知边界：operator 是持票方自述字段（不在票据签名载荷内），只影响
// 审计归属文案、不改变可执行动作；空串回退「主节点」（兼容旧主节点）。
//
// result 落盘前必须经 services.RedactCaddyAdminEndpoint：Caddy 应用失败的原文
// 来自指向 admin 端点的 *url.Error（请求地址 + 拨号地址），而操作审计是全员
// 可读面——把内部控制面地址与端口写给只读用户等于拓扑披露。执行失败的 5xx
// 响应为固定文案（本端点票据凭证可达，非 admin 会话），底层原文只进本审计
// 与运行日志（见 ClusterServiceControl 失败分支）。
func recordClusterServiceControlAuditBy(c *gin.Context, action, result, operator string) {
	// action/operator 来自请求体，须先经 registerAuditField
	// 清洗（去控制字符、截断 128B）再拼接，防伪造换行/超长注入审计详情。
	op := registerAuditField(operator)
	if op == "" {
		op = "主节点"
	}
	services.RecordAuditLog(op, "服务控制", "节点服务",
		services.FormatAuditDetail("来源：主节点", "操作："+registerAuditField(action), "结果："+services.RedactCaddyAdminEndpoint(result)), c.ClientIP())
}

// currentUsername 从 gin context 取 JWT/API Key 中间件注入的操作人用户名。
func currentUsername(c *gin.Context) string {
	username, _ := c.Get("username")
	s, _ := username.(string)
	return s
}
