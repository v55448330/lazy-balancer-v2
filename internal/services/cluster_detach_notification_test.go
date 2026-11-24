package services

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNotifyMasterDetach_residualRedirectIsVisibleFailure(t *testing.T) {
	for _, status := range []int{http.StatusMultipleChoices, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Location", "https://other-master.invalid/api/v1/cluster/nodes/report")
				w.WriteHeader(status)
			}))
			defer server.Close()
			logs := captureLogf(t)

			notifyMasterDetach(context.Background(), server.URL, "old-token", "")

			if hits.Load() != 1 {
				t.Fatalf("requests=%d, want 1 (redirect must not be followed)", hits.Load())
			}
			if output := logs.String(); !strings.Contains(output, "cluster detach notify") || !strings.Contains(output, fmt.Sprintf("%d", status)) {
				t.Fatalf("logs=%q, want visible detach failure for HTTP %d", output, status)
			}
		})
	}
}

// 生产语义：4xx 记 "rejected"；2xx 成功**不记任何日志**（best-effort 脱离通知）。
// 用例名与断言必须与这条真实契约一致——旧名承诺「拒绝/成功日志可区分」，
// 但生产根本没有成功分支，断言只覆盖拒绝路径（名不副实 → 泛化文案也不变红）。
func TestNotifyMasterDetach_rejectionLoggedAndSuccessSilent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	logs := captureLogf(t)
	notifyMasterDetach(context.Background(), server.URL, "old-token", "")
	if !strings.Contains(logs.String(), "cluster detach notify rejected") {
		t.Fatalf("4xx logs=%q, want rejected", logs.String())
	}

	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer successServer.Close()
	successLogs := captureLogf(t)
	notifyMasterDetach(context.Background(), successServer.URL, "old-token", "")
	if successLogs.Len() != 0 {
		t.Fatalf("2xx 成功路径必须静默（不得出现 rejected/failed 文案）, got %q", successLogs.String())
	}
}
