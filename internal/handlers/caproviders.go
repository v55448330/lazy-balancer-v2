package handlers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListCAProviders(c *gin.Context) {
	list, err := h.caProviderService.ListCAProviders()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to list CA providers"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: list})
}

func (h *Handlers) GetCAProvider(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}

	p, err := h.caProviderService.GetCAProvider(id)
	if err != nil {
		if errors.Is(err, services.ErrCAProviderNotFound) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get CA provider"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: p})
}

func credentialsMeaningfullyChanged(newCredentials, oldCredentials string) bool {
	trimmed := strings.TrimSpace(newCredentials)
	if trimmed == "" || strings.Contains(trimmed, services.MaskedHMACKey) || strings.Trim(trimmed, "*") == "" {
		return false
	}
	return trimmed != oldCredentials
}

func (h *Handlers) UpdateCAProvider(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}

	var req models.UpdateCAProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}
	var oldName, oldProvider, oldDirectoryURL, oldCredentials string
	var oldMaxConcurrent, oldMinIntervalMS int
	var oldEnabled bool
	if err := db.DB.QueryRow(`SELECT name, provider, directory_url, COALESCE(credentials,''), max_concurrent, min_interval_ms, enabled FROM ca_providers WHERE id=?`, id).Scan(&oldName, &oldProvider, &oldDirectoryURL, &oldCredentials, &oldMaxConcurrent, &oldMinIntervalMS, &oldEnabled); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA provider not found"})
		return
	}
	changed := []string{}
	if req.Name != nil && *req.Name != oldName {
		changed = append(changed, "名称")
	}
	if req.Provider != nil && *req.Provider != oldProvider {
		changed = append(changed, "提供商类型")
	}
	if req.DirectoryURL != nil && *req.DirectoryURL != oldDirectoryURL {
		changed = append(changed, "目录地址")
	}
	if req.Credentials != nil && credentialsMeaningfullyChanged(*req.Credentials, oldCredentials) {
		changed = append(changed, "凭证")
	}
	if req.MaxConcurrent != nil && *req.MaxConcurrent != oldMaxConcurrent {
		changed = append(changed, "最大并发")
	}
	if req.MinIntervalMS != nil && *req.MinIntervalMS != oldMinIntervalMS {
		changed = append(changed, "最小间隔")
	}
	if req.Enabled != nil && *req.Enabled != oldEnabled {
		changed = append(changed, "启用状态")
	}

	if err := h.caProviderService.UpdateCAProvider(id, req); err != nil {
		if errors.Is(err, services.ErrCAProviderNotFound) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA provider not found"})
			return
		}
		if errors.Is(err, services.ErrCAProviderLastEnabled) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		switch {
		case errors.Is(err, services.ErrCAProviderInvalidProvider):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "提供商类型必须是 letsencrypt 或 zerossl"})
		case errors.Is(err, services.ErrCAProviderInvalidName):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能为空"})
		case errors.Is(err, services.ErrCAProviderNameTooLong):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能超过 100 个字符"})
		case errors.Is(err, services.ErrCAProviderInvalidDirectoryURL):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "目录地址必须是有效的 HTTPS URL"})
		case errors.Is(err, services.ErrCAProviderDirectoryURLTooLong):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "目录地址不能超过 255 个字符"})
		case errors.Is(err, services.ErrCAProviderInvalidCredentials):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "凭证必须是有效的 JSON"})
		case errors.Is(err, services.ErrCAProviderMissingZeroSSLCredentials):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ZeroSSL 凭证需要 eab_kid 和 eab_hmac_key"})
		case errors.Is(err, services.ErrCAProviderLetsEncryptCredentialsNotEmpty):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Let's Encrypt 凭证必须为空"})
		case errors.Is(err, services.ErrCAProviderMaxConcurrentTooHigh):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "最大并发不能超过 100"})
		case errors.Is(err, services.ErrCAProviderMinIntervalTooHigh):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "最小间隔不能超过 60000 毫秒"})
		case errors.Is(err, services.ErrCAProviderMaskedHMACNotAvailable):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无法保留现有 HMAC 密钥"})
		default:
			log.Printf("Failed to update CA provider %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update CA provider"})
		}
		return
	}
	if len(changed) == 0 {
		recordAudit(c, "更新", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), oldName, "无修改"))
	} else {
		recordAudit(c, "更新", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), oldName, fmt.Sprintf("变更：%s", strings.Join(changed, "、"))))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA provider updated"})
}

func (h *Handlers) TestCAProvider(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 ID 参数"})
		return
	}
	var providerName string
	db.DB.QueryRow("SELECT name FROM ca_providers WHERE id=?", id).Scan(&providerName)

	if err := h.caProviderService.TestCAProvider(id); err != nil {
		result := "provider_error"
		if errors.Is(err, services.ErrCAProviderNotFound) {
			result = "not_found"
			recordAudit(c, "测试失败", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart(result)))
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA 提供商不存在或已禁用"})
			return
		}
		var terr *services.CAProviderTestError
		if errors.As(err, &terr) {
			switch terr.Phase {
			case "email":
				result = "missing_acme_email"
				recordAudit(c, "测试失败", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart(result)))
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "未配置 ACME 邮箱，请在「系统设置 / 免费证书」中填写邮箱"})
			case "config":
				result = "invalid_config"
				recordAudit(c, "测试失败", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart(result)))
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "CA 提供商配置无效: " + terr.Error()})
			case "register":
				result = "register_failed"
				recordAudit(c, "测试失败", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart(result)))
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ACME 账户注册失败，请检查 CA 配置或网络: " + terr.Error()})
			default:
				recordAudit(c, "测试失败", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart(result)))
				log.Printf("CA provider test failed for provider %d: %v", id, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 提供商测试失败"})
			}
			return
		}
		recordAudit(c, "测试失败", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart(result)))
		log.Printf("CA provider test failed for provider %d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 提供商测试失败"})
		return
	}

	recordAudit(c, "测试成功", "CA提供商", services.FormatAuditDetail(fmt.Sprintf("提供商 %d", id), providerName, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA 提供商配置有效"})
}
