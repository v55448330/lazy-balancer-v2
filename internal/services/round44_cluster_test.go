package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// CL44-2（第 44 轮审计）：主节点返回 200 但载荷畸形（registration_id<=0 或
// registration_secret 为空）时，RegisterWithMaster 此前静默成功，残缺注册信息
// 会被调用方落库——必须在返回前显式拒绝。
func TestCL44_2_RegisterWithMaster_rejectsMalformedRegistrationPayload(t *testing.T) {
	// Given：主节点 200 但 data 缺注册编号与注册密钥
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok","data":{"registration_id":0,"registration_secret":""}}`))
	}))
	t.Cleanup(master.Close)
	service := NewSyncService(nil, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, err := service.RegisterWithMaster(context.Background(), master.URL, models.ClusterRegisterRequest{})

	// Then：显式报错而非静默成功
	if err == nil || !strings.Contains(err.Error(), "注册") {
		t.Fatalf("error=%v, want 畸形注册载荷显式报错", err)
	}
}

// CL44-2 回归形状：合法载荷照常解码通过（registration_id>0 且 secret 非空）。
func TestCL44_2_RegisterWithMaster_acceptsValidRegistrationPayload(t *testing.T) {
	// Given
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok","data":{"registration_id":44,"registration_secret":"s3cret"}}`))
	}))
	t.Cleanup(master.Close)
	service := NewSyncService(nil, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	registration, err := service.RegisterWithMaster(context.Background(), master.URL, models.ClusterRegisterRequest{})

	// Then
	if err != nil || registration.RegistrationID != 44 || registration.RegistrationSecret != "s3cret" {
		t.Fatalf("registration=%+v err=%v, want 合法载荷通过", registration, err)
	}
}
