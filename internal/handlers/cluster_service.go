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

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
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
	if !h.requireMaster(c) {
		return
	}
	nodeID, err := strconv.Atoi(c.Param("id"))
	if err != nil || nodeID <= 0 {
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	var req models.ClusterNodeServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "请求格式错误", err)
		return
	}
	if !models.IsValidClusterServiceAction(req.Action) {
		clusterError(c, http.StatusBadRequest, "不支持的服务控制动作", nil)
		return
	}
	issued, err := h.clusterService.IssueServiceControlTicket(c.Request.Context(), nodeID, req.Action, time.Now())
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, services.ErrNodeNotFound):
			status = http.StatusNotFound
		case errors.Is(err, services.ErrInvalidServiceAction):
			status = http.StatusBadRequest
		}
		clusterError(c, status, "签发服务控制票据失败", err)
		return
	}
	message, err := h.callClusterServiceControl(c.Request.Context(), issued.URL, req.Action, issued.Ticket)
	result := "成功"
	if err != nil {
		result = "失败"
	}
	recordAudit(c, "服务控制", "节点服务", services.FormatAuditDetail(
		fmt.Sprintf("节点 %s", issued.NodeName), "操作："+req.Action, "结果："+result))
	if err != nil {
		var rejected *clusterServiceControlRejection
		if errors.As(err, &rejected) {
			c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: rejected.message})
			return
		}
		clusterError(c, http.StatusBadGateway, "从节点不可达或响应异常", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
}

func (h *Handlers) callClusterServiceControl(ctx context.Context, baseURL, action, ticket string) (string, error) {
	payload, err := json.Marshal(models.ClusterServiceControlRequest{Action: action, Ticket: ticket})
	if err != nil {
		return "", fmt.Errorf("编码服务控制请求: %w", err)
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/v1/cluster/service-control"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("构造服务控制请求: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := clusterServiceControlClientFactory(h.cfg.DataDir).Do(request)
	if err != nil {
		return "", fmt.Errorf("调用从节点服务控制: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, clusterServiceControlMaxBytes))
	if err != nil {
		return "", fmt.Errorf("读取从节点响应: %w", err)
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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterServiceControlMaxBytes)
	var req models.ClusterServiceControlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		recordClusterServiceControlAudit(c, req.Action, "失败：请求格式错误")
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: http.StatusBadRequest, Message: "请求格式错误"})
		return
	}
	if !models.IsValidClusterServiceAction(req.Action) {
		recordClusterServiceControlAudit(c, req.Action, "失败：不支持的动作")
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: http.StatusBadRequest, Message: "不支持的服务控制动作"})
		return
	}
	if err := h.clusterService.ValidateServiceControlTicket(c.Request.Context(), req.Ticket, req.Action, time.Now()); err != nil {
		if errors.Is(err, services.ErrInvalidServiceControlTicket) {
			recordClusterServiceControlAudit(c, req.Action, "失败：票据校验未通过")
			clusterError(c, http.StatusUnauthorized, "服务控制票据无效或已过期", err)
			return
		}
		recordClusterServiceControlAudit(c, req.Action, "失败：票据校验出错")
		clusterError(c, http.StatusInternalServerError, "服务控制校验失败", err)
		return
	}
	if req.Action == models.ClusterServiceActionRestartApp {
		recordClusterServiceControlAudit(c, req.Action, "已接受：服务即将重启")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "服务正在重启"})
		go func() {
			time.Sleep(clusterServiceExitDelay)
			clusterServiceExit()
		}()
		return
	}
	message, err := h.executeClusterCaddyAction(req.Action)
	if err != nil {
		recordClusterServiceControlAudit(c, req.Action, "失败："+err.Error())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: http.StatusInternalServerError, Message: err.Error()})
		return
	}
	recordClusterServiceControlAudit(c, req.Action, "成功")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message})
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
		return "Caddy 已启动", nil
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
		return "Caddy 已重启", nil
	}
	return "", fmt.Errorf("不支持的服务控制动作：%s", action)
}

func recordClusterServiceControlAudit(c *gin.Context, action, result string) {
	services.RecordAuditLog("system", "服务控制", "节点服务",
		services.FormatAuditDetail("来源：主节点", "操作："+action, "结果："+result), c.ClientIP())
}
