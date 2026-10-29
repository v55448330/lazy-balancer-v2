package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListCAProviders(c *gin.Context) {
	list, err := h.caProviderService.ListCAProviders()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询 CA 提供商列表失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: list})
}

func (h *Handlers) GetCAProvider(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 ID 参数"})
		return
	}

	p, err := h.caProviderService.GetCAProvider(id)
	if err != nil {
		if errors.Is(err, services.ErrCAProviderNotFound) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询 CA 提供商失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: p})
}

// credentialAuditState 是 CA 提供商凭证字段的审计口径：把「空白串（会真实
// 清空 credentials 列）」「真实值变更」「无变更」三态区分开。旧实现把空白串
// 视为未变更——清空落库却审计成「无修改」。
//
// 全星号占位（前端掩码回传）不在此枚举内：服务层对非 LE 提供商的凭证执行
// JSON 门（ErrCAProviderInvalidCredentials），全星号载荷在进入审计判定前即
// 被 400 拒绝，故「掩码回传」态在生产不可达，不得为不可达态保留分支/文案。
type credentialAuditState int

const (
	credentialUnchanged credentialAuditState = iota
	credentialChanged
	credentialCleared
)

// credentialAuditStateFor 判定凭证载荷的审计/变更语义。
func credentialAuditStateFor(newCredentials, oldCredentials string) credentialAuditState {
	trimmed := strings.TrimSpace(newCredentials)
	if trimmed == "" {
		if strings.TrimSpace(oldCredentials) == "" {
			return credentialUnchanged
		}
		// 空串=显式清空：服务层会把 credentials 写成空（ZeroSSL 分支放行空值）。
		return credentialCleared
	}
	if credentialsSemanticallyEqual(trimmed, oldCredentials) {
		return credentialUnchanged
	}
	return credentialChanged
}

// credentialsSemanticallyEqual 报告两段凭证 JSON 语义相等（键序/空白无关）。
// 实现单源在 services.CredentialsSemanticallyEqual（DNS 配置写路径共用同一
// 判定，两侧不得各自解释「凭证变更」）。
func credentialsSemanticallyEqual(a, b string) bool {
	return services.CredentialsSemanticallyEqual(a, b)
}

// recordCAProviderUpdateFailure 记录 CA 提供商更新失败。PUT /api/v1/ca-providers/:id
// 是 Explicit 审计路由——中间件对 Explicit 既不补记成功也不补记失败，handler
// 必须自己覆盖「业务拒绝」与「内部错误」两类失败面，否则运维无法从审计回答
// 「谁试图禁用默认 CA 提供商、被什么挡住」。入参校验类 4xx（提供商类型/名称/
// 并发/凭证门）属未进入写入层的载荷拒绝，不落审计。
func recordCAProviderUpdateFailure(c *gin.Context, id int, reason string) {
	recordAudit(c, "更新失败", "CA提供商", services.FormatAuditDetail(
		fmt.Sprintf("提供商 %d", id), reason, services.AuditResultPart("failure")))
}

func (h *Handlers) UpdateCAProvider(c *gin.Context) {
	// ca_providers 在导入全量替代表清单内。
	if rejectWriteDuringImport(c, "保存 CA 提供商（配置导入进行中）") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 ID 参数"})
		return
	}

	// credentials 为自由 JSON 字符串：请求体上限跟随全局「请求体大小」配置项，
	// 与证书配置/签发等写端点同源（独立硬编码会让调整全局上限后本端点行为
	// 分叉）。超限经 isRequestBodyTooLarge 映射 413。
	if !guardConfiguredJSONBody(c) {
		return
	}
	var req models.UpdateCAProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}
	// CA 提供商的「守卫 + 提交」必须与规则/默认 CA 的「校验 + 提交」互斥：
	// 否则并发写可提交「启用 ACME 规则 × 禁用 provider」（规则侧随后每次签发
	// 硬失败）或「默认 CA = 禁用 provider」（静默改派到首个启用 provider）。
	// 锁序 caddyOpMu → DB，与证书配置写路径同序。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	old, err := h.caProviderService.UpdateCAProvider(id, req)
	if err != nil {
		if errors.Is(err, services.ErrCAProviderNotFound) {
			recordCAProviderUpdateFailure(c, id, "提供商不存在")
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA provider not found"})
			return
		}
		if errors.Is(err, services.ErrCAProviderLastEnabled) {
			recordCAProviderUpdateFailure(c, id, err.Error())
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		if errors.Is(err, services.ErrCAProviderDefault) {
			recordCAProviderUpdateFailure(c, id, err.Error())
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
			return
		}
		if errors.Is(err, services.ErrCAProviderInUse) {
			// 禁用被规则/任务引用的 CA 提供商 → 409 点名
			// 引用方（对齐 DNS 配置禁用守卫），不再静默改派到其他 CA。
			recordCAProviderUpdateFailure(c, id, err.Error())
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
			return
		}
		switch {
		case errors.Is(err, services.ErrCAProviderInvalidProvider):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "提供商类型必须是 letsencrypt 或 zerossl"})
		case errors.Is(err, services.ErrCAProviderInvalidName):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能为空"})
		case errors.Is(err, services.ErrCAProviderNameTooLong):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能超过 100 个字符"})
		// directory_url 两个 400 分支已删——服务层按 provider 无条件覆写
		// 常量（services/caproviders.go:195-199），用户输入实际无效，两错误永不触发。
		case errors.Is(err, services.ErrCAProviderInvalidCredentials):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "凭证必须是有效的 JSON"})
		case errors.Is(err, services.ErrCAProviderLetsEncryptCredentialsNotEmpty):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Let's Encrypt 凭证必须为空"})
		case errors.Is(err, services.ErrCAProviderMaxConcurrentTooHigh):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "最大并发不能超过 100"})
		case errors.Is(err, services.ErrCAProviderMinIntervalTooHigh):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "最小间隔不能超过 60000 毫秒"})
		default:
			services.Logf("error", "Failed to update CA provider %d: %v", id, err)
			recordCAProviderUpdateFailure(c, id, err.Error())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新 CA 提供商失败"})
		}
		return
	}
	// changed 清单的比对基线改为服务层返回的事务内旧行，
	// 消除「事务外预读 → 事务提交」窗口内并发写入导致的清单失真（基于陈旧
	// 旧值漏记/多记变更字段）。
	changed := []string{}
	credentialState := credentialUnchanged
	if req.Credentials != nil {
		credentialState = credentialAuditStateFor(*req.Credentials, old.Credentials)
	}
	// 名称按生效值（trim 后）比对：服务层写库前 TrimSpace，按请求原值比对会把
	// 「提交带空白填充的同一名称」记成变更——审计假阳性，且与同函数内
	// 最大并发/最小间隔「归一后生效值才算变更」的口径相悖。
	if req.Name != nil && strings.TrimSpace(*req.Name) != strings.TrimSpace(old.Name) {
		changed = append(changed, "名称")
	}
	if req.Provider != nil && *req.Provider != old.Provider {
		changed = append(changed, "提供商类型")
	}
	switch credentialState {
	case credentialChanged:
		changed = append(changed, "凭证")
	case credentialCleared:
		// 空串会真实清空 credentials 列，不得记「无修改」。
		changed = append(changed, "凭证（清空）")
	}
	// 钳制后的生效值才算变更：服务层把 <=0 归一为默认（0→1 / 0→1000），
	// 按请求原值比对会把「提交 0 而库值已是 1」记成「变更」（审计假阳性）。
	if req.MaxConcurrent != nil && services.NormalizeCAProviderMaxConcurrent(*req.MaxConcurrent) != old.MaxConcurrent {
		changed = append(changed, "最大并发")
	}
	if req.MinIntervalMS != nil && services.NormalizeCAProviderMinIntervalMS(*req.MinIntervalMS) != old.MinIntervalMS {
		changed = append(changed, "最小间隔")
	}
	if req.Enabled != nil && *req.Enabled != old.Enabled {
		changed = append(changed, "启用状态")
	}
	if len(changed) == 0 {
		parts := []string{fmt.Sprintf("提供商 %d", id), old.Name, "无修改"}
		recordAudit(c, "更新", "CA提供商", services.FormatAuditDetail(parts...))
	} else {
		recordAudit(c, "更新", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), old.Name, fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA 提供商已更新"})
}

// auditCAProviderTestResult 是 TestCAProvider 全部失败出口的审计详情单源：
// 「提供商 N [名称]；结果：<result>」。name 传空串（预查询 404 尚无名称）时
// 省略名称段，与既有形态逐字一致；结果段经 AuditResultPart 统一渲染。
func auditCAProviderTestResult(c *gin.Context, id int, name, result string) {
	parts := []string{fmt.Sprintf("提供商 %d", id)}
	if name != "" {
		parts = append(parts, name)
	}
	recordAudit(c, "测试失败", "CA提供商", services.FormatAuditDetail(append(parts, services.AuditResultPart(result))...))
}

func (h *Handlers) TestCAProvider(c *gin.Context) {
	// ZeroSSL EAB 测试会写 ca_providers.credentials（账户绑定结果）——与
	// 导入的整表替换互斥。这里不取 caddyOpMu：测试含网络往返，持全局锁会把
	// 规则/证书配置写路径拖死（锁只保护本地事务级竞态）。
	if rejectWriteDuringImport(c, "测试 CA 提供商（配置导入进行中）") {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 ID 参数"})
		return
	}
	// 复用服务层单源查询（含 ErrCAProviderNotFound 分类），不再在
	// handler 里另写一份 SELECT——单源分叉风险与审计名称口径漂移都由此消除。
	provider, err := h.caProviderService.GetCAProvider(id)
	if err != nil {
		if errors.Is(err, services.ErrCAProviderNotFound) {
			// 预查询 404 与测试内核的 not_found 同一结果类别：测试入口无论在哪一层
			// 判定不存在都必须留审计（成功/失败测试均留痕的既有口径）。
			auditCAProviderTestResult(c, id, "", "not_found")
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA 提供商不存在"})
			return
		}
		services.Logf("error", "Failed to query CA provider %d before test: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询 CA 提供商失败"})
		return
	}
	providerName := provider.Name

	if err := h.caProviderService.TestCAProviderWithContext(c.Request.Context(), id); err != nil {
		result := "provider_error"
		if errors.Is(err, services.ErrCAProviderNotFound) {
			result = "not_found"
			auditCAProviderTestResult(c, id, providerName, result)
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA 提供商不存在或已禁用"})
			return
		}
		var terr *services.CAProviderTestError
		if errors.As(err, &terr) {
			switch terr.Phase {
			case "email":
				result = "missing_acme_email"
				auditCAProviderTestResult(c, id, providerName, result)
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "未配置 ACME 邮箱，请在「系统设置 / 免费证书」中填写邮箱"})
			case "config":
				result = "invalid_config"
				auditCAProviderTestResult(c, id, providerName, result)
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "CA 提供商配置无效: " + terr.Error()})
			case "register":
				result = "register_failed"
				auditCAProviderTestResult(c, id, providerName, result)
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ACME 账户注册失败，请检查 CA 配置或网络: " + terr.Error()})
			default:
				auditCAProviderTestResult(c, id, providerName, result)
				services.Logf("error", "CA provider test failed for provider %d: %v", id, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 提供商测试失败"})
			}
			return
		}
		auditCAProviderTestResult(c, id, providerName, result)
		services.Logf("error", "CA provider test failed for provider %d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 提供商测试失败"})
		return
	}

	recordAudit(c, "测试成功", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA 提供商配置有效"})
}
