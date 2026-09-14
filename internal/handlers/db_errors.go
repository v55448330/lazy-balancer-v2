package handlers

import (
	"database/sql"
	"errors"
	"lazy-balancer-v2/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func dbQueryNotFound(c *gin.Context, err error, notFoundMessage, operation string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: notFoundMessage})
		return true
	}
	services.Logf("error", "%s: %v", operation, err)
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
	return true
}
