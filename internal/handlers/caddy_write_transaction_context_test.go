package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBeginCaddyWriteTxSurvivesRequestCancellation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	requestCtx, cancel := context.WithCancel(context.Background())
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPut, "/config", nil).WithContext(requestCtx)
	tx, err := beginCaddyWriteTx(ginCtx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	cancel()
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE global_config SET timezone=timezone WHERE id=1`); err != nil {
		t.Fatalf("transaction was rolled back with the request context: %v", err)
	}
}
