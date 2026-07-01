package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type testCAProviderRequest struct {
	Domain string `json:"domain"`
}

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
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "provider must be letsencrypt or zerossl"})
		case errors.Is(err, services.ErrCAProviderInvalidName):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "name is required"})
		case errors.Is(err, services.ErrCAProviderNameTooLong):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "name must be <= 100 characters"})
		case errors.Is(err, services.ErrCAProviderInvalidDirectoryURL):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "directory_url must be a valid HTTPS URL"})
		case errors.Is(err, services.ErrCAProviderDirectoryURLTooLong):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "directory_url must be <= 255 characters"})
		case errors.Is(err, services.ErrCAProviderInvalidCredentials):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "credentials must be valid JSON"})
		case errors.Is(err, services.ErrCAProviderMissingZeroSSLCredentials):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "zerossl credentials require eab_kid and eab_hmac_key"})
		case errors.Is(err, services.ErrCAProviderLetsEncryptCredentialsNotEmpty):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "letsencrypt credentials must be empty"})
		case errors.Is(err, services.ErrCAProviderMaxConcurrentTooHigh):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "max_concurrent must be <= 100"})
		case errors.Is(err, services.ErrCAProviderMinIntervalTooHigh):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "min_interval_ms must be <= 60000"})
		case errors.Is(err, services.ErrCAProviderMaskedHMACNotAvailable):
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "existing HMAC key is not available"})
		default:
			log.Printf("Failed to update CA provider %d: %v", id, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update CA provider"})
		}
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA provider updated"})
}

func (h *Handlers) TestCAProvider(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid id parameter"})
		return
	}

	var req testCAProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}
	if !isValidACMEDomain(req.Domain) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "domain must be a valid domain name"})
		return
	}

	if err := h.caProviderService.TestCAProvider(id, req.Domain); err != nil {
		if errors.Is(err, services.ErrCAProviderNotFound) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "CA provider not found or disabled"})
			return
		}
		var terr *services.CAProviderTestError
		if errors.As(err, &terr) {
			switch terr.Phase {
			case "email":
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ACME email is not configured"})
			case "config":
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid CA provider config: " + terr.Error()})
			case "register":
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "ACME registration failed: " + terr.Error()})
			default:
				log.Printf("CA provider test failed for provider %d: %v", id, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA provider test failed"})
			}
			return
		}
		log.Printf("CA provider test failed for provider %d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA provider test failed"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "CA provider configuration is valid"})
}
