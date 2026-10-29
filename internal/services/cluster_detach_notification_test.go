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

func TestNotifyMasterDetach_rejectionAndSuccessLoggingRemainDistinct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	logs := captureLogf(t)
	notifyMasterDetach(context.Background(), server.URL, "old-token", "")
	if !strings.Contains(logs.String(), "cluster detach notify rejected") {
		t.Fatalf("4xx logs=%q, want rejected", logs.String())
	}
}
