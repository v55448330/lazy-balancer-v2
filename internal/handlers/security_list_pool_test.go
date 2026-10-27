package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func assertSecurityListWithinPool(t *testing.T, router *gin.Engine, path string, maxOpen, concurrency int) {
	t.Helper()
	previousMaxOpen := db.DB.Stats().MaxOpenConnections
	db.DB.SetMaxOpenConns(maxOpen)
	defer db.DB.SetMaxOpenConns(previousMaxOpen)

	start := make(chan struct{})
	results := make(chan int, concurrency)
	for range concurrency {
		go func() {
			<-start
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			results <- recorder.Code
		}()
	}
	close(start)

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for completed := range concurrency {
		select {
		case status := <-results:
			if status != http.StatusOK {
				t.Fatalf("list status=%d, want 200", status)
			}
		case <-deadline.C:
			// 放开连接上限以解开旧实现的自锁 goroutine，再让用例失败；
			// 不把阻塞中的请求和清理链遗留给后续用例。
			db.DB.SetMaxOpenConns(concurrency*2 + 1)
			for drained := completed; drained < concurrency; drained++ {
				<-results
			}
			t.Fatalf("%s with maxOpen=%d concurrency=%d deadlocked on nested queries", path, maxOpen, concurrency)
		}
	}
}

func TestListSecurityPolicies_singleConnectionPool(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name,enabled) VALUES ('pool-policy',1)`); err != nil {
		t.Fatal(err)
	}
	assertSecurityListWithinPool(t, newSecurityRouter(t), "/security/policies", 1, 1)
}

func TestListSecurityPolicies_tenConcurrentRequestsWithinPool(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name,enabled) VALUES ('pool-policy',1)`); err != nil {
		t.Fatal(err)
	}
	assertSecurityListWithinPool(t, newSecurityRouter(t), "/security/policies", 10, 10)
}

func TestListIPLists_singleConnectionPool(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name,entries) VALUES ('pool-list','[]')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	h := &Handlers{}
	router.GET("/security/ip-lists", h.ListIPLists)
	assertSecurityListWithinPool(t, router, "/security/ip-lists", 1, 1)
}

func TestListIPLists_tenConcurrentRequestsWithinPool(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name,entries) VALUES ('pool-list','[]')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	h := &Handlers{}
	router.GET("/security/ip-lists", h.ListIPLists)
	assertSecurityListWithinPool(t, router, "/security/ip-lists", 10, 10)
}
