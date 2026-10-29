package services

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 威胁更新首个源已产生内容变化，第二个源在下载期间发生角色变化或取消。
// When 更新运行收尾并决定是否收敛投影。
// Then 主节点成功并收敛；降级/角色未知零投影；手动取消仍收敛已提交源；
// 所有中止形态都不得继续下载第三个源。
func TestThreatUpdateRun_roleAbortAttribution(t *testing.T) {
	for _, tc := range []struct {
		name              string
		roleTransition    func(t *testing.T, m *ThreatUpdateManager)
		wantOutcome       string
		wantRunError      error
		wantSecondStatus  string
		wantRefreshes     int
		wantThirdRequests int64
	}{
		{
			name:              "master",
			roleTransition:    func(t *testing.T, m *ThreatUpdateManager) {},
			wantOutcome:       "success",
			wantSecondStatus:  "success",
			wantRefreshes:     1,
			wantThirdRequests: 1,
		},
		{
			name: "demoted",
			roleTransition: func(t *testing.T, m *ThreatUpdateManager) {
				if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
					t.Errorf("demote node: %v", err)
				}
			},
			wantOutcome:      "skipped",
			wantSecondStatus: "running",
			wantRefreshes:    0,
		},
		{
			name: "unknown",
			roleTransition: func(t *testing.T, m *ThreatUpdateManager) {
				if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
					t.Errorf("remove role row: %v", err)
				}
			},
			wantOutcome:      "failed",
			wantRunError:     ErrThreatUpdateFailed,
			wantSecondStatus: "running",
			wantRefreshes:    0,
		},
		{
			name: "cancelled",
			roleTransition: func(t *testing.T, m *ThreatUpdateManager) {
				m.CancelRunning()
			},
			wantOutcome:   "cancelled",
			wantRefreshes: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overrideWafDirForTest(t)
			newClusterTestService(t)
			setupThreatTest(t, nil, nil, nil)
			newTaskLogDir(t)
			manager := GetThreatUpdateManager()
			if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1 WHERE name IN ('ustc','firehol_l1','et_compromised')`); err != nil {
				t.Fatal(err)
			}

			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("203.0.113.7\n198.51.100.9\n"))
			}))
			t.Cleanup(first.Close)
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.roleTransition(t, manager)
				_, _ = w.Write([]byte("192.0.2.44\n198.51.100.44\n"))
			}))
			var thirdRequests atomic.Int64
			third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				thirdRequests.Add(1)
				_, _ = w.Write([]byte("192.0.2.88\n198.51.100.88\n"))
			}))
			t.Cleanup(third.Close)
			t.Cleanup(second.Close)
			if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, first.URL); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='firehol_l1'`, second.URL); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='et_compromised'`, third.URL); err != nil {
				t.Fatal(err)
			}
			var initialThirdStatus string
			if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE name='et_compromised'`).Scan(&initialThirdStatus); err != nil {
				t.Fatal(err)
			}

			refreshes := 0
			SetThreatProjectionRefresher(func() (IPListProjectionOutcome, error) {
				refreshes++
				return ProjectionConverged, nil
			})
			t.Cleanup(func() { SetThreatProjectionRefresher(nil) })

			runErr := manager.RunUpdate("manual", nil)
			if !errors.Is(runErr, tc.wantRunError) {
				t.Fatalf("run error=%v, want %v", runErr, tc.wantRunError)
			}
			if got := manager.StatusSnapshot().Outcome; got != tc.wantOutcome {
				t.Fatalf("outcome=%q, want %q", got, tc.wantOutcome)
			}
			var secondStatus string
			if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE name='firehol_l1'`).Scan(&secondStatus); err != nil {
				t.Fatal(err)
			}
			if tc.wantSecondStatus != "" && secondStatus != tc.wantSecondStatus {
				t.Fatalf("aborted source status=%q, want %q", secondStatus, tc.wantSecondStatus)
			}
			wantThirdStatus := initialThirdStatus
			if tc.wantOutcome == "success" {
				wantThirdStatus = "success"
			}
			var thirdStatus string
			if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE name='et_compromised'`).Scan(&thirdStatus); err != nil {
				t.Fatal(err)
			}
			if thirdStatus != wantThirdStatus {
				t.Fatalf("remaining source status=%q, want %q", thirdStatus, wantThirdStatus)
			}
			if got := thirdRequests.Load(); got != tc.wantThirdRequests {
				t.Fatalf("remaining source requests=%d, want %d", got, tc.wantThirdRequests)
			}
			if refreshes != tc.wantRefreshes {
				t.Fatalf("projection refreshes=%d, want %d", refreshes, tc.wantRefreshes)
			}
		})
	}
}
