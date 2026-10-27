package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 连接池自锁回归面：maxOpen=1 时列表接口不得在行迭代期间
// 再取连接。
//
// 断言面：只断言 HTTP 200 时，一个在 defer
// rows.Close() 之前提前关闭游标的实现（列表恒空、状态仍是 200）也能全绿。
// 因此每次请求都必须**同时**校验载荷：解码 data 数组，逐条比对刚播种的行名，
// 且空列表属于失败形态。判据抽成纯函数 securityListPayloadError，反例自检在
// 文件末尾（空载荷/错名必须被判错），避免判据本身静默退化。

type securityListResult struct {
	code int
	body []byte
}

// securityListPayloadError 判定列表载荷是否真的带上了期望行。
func securityListPayloadError(body []byte, wantName string) error {
	var envelope struct {
		Code int `json:"code"`
		Data []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("decode list payload: %w", err)
	}
	if envelope.Code != 0 {
		return fmt.Errorf("业务码=%d, want 0", envelope.Code)
	}
	if len(envelope.Data) == 0 {
		// 两个列表端点在不带过滤条件时至少返回刚播种的那一行：空列表=丢行
		// （提前关游标/漏行），不是合法的「空结果」。
		return fmt.Errorf("列表为空，want 至少 1 条（%s）", wantName)
	}
	for _, row := range envelope.Data {
		if row.Name == wantName {
			if row.ID <= 0 {
				return fmt.Errorf("行 %s 的 id=%d, want >0", wantName, row.ID)
			}
			return nil
		}
	}
	return fmt.Errorf("列表不含刚播种的行 %s（共 %d 条）", wantName, len(envelope.Data))
}

func assertSecurityListWithinPool(t *testing.T, router *gin.Engine, path, wantName string, maxOpen, concurrency int) {
	t.Helper()
	previousMaxOpen := db.DB.Stats().MaxOpenConnections
	db.DB.SetMaxOpenConns(maxOpen)
	defer db.DB.SetMaxOpenConns(previousMaxOpen)

	start := make(chan struct{})
	results := make(chan securityListResult, concurrency)
	for range concurrency {
		go func() {
			<-start
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			results <- securityListResult{code: recorder.Code, body: recorder.Body.Bytes()}
		}()
	}
	close(start)

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for completed := range concurrency {
		select {
		case result := <-results:
			if result.code != http.StatusOK {
				t.Fatalf("list status=%d body=%s, want 200", result.code, string(result.body))
			}
			if err := securityListPayloadError(result.body, wantName); err != nil {
				t.Fatalf("maxOpen=%d concurrency=%d 列表载荷错误: %v（body=%s）", maxOpen, concurrency, err, string(result.body))
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
	assertSecurityListWithinPool(t, newSecurityRouter(t), "/security/policies", "pool-policy", 1, 1)
}

func TestListSecurityPolicies_tenConcurrentRequestsWithinPool(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name,enabled) VALUES ('pool-policy',1)`); err != nil {
		t.Fatal(err)
	}
	assertSecurityListWithinPool(t, newSecurityRouter(t), "/security/policies", "pool-policy", 10, 10)
}

func TestListIPLists_singleConnectionPool(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name,entries) VALUES ('pool-list','[]')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	h := &Handlers{}
	router.GET("/security/ip-lists", h.ListIPLists)
	assertSecurityListWithinPool(t, router, "/security/ip-lists", "pool-list", 1, 1)
}

func TestListIPLists_tenConcurrentRequestsWithinPool(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name,entries) VALUES ('pool-list','[]')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	h := &Handlers{}
	router.GET("/security/ip-lists", h.ListIPLists)
	assertSecurityListWithinPool(t, router, "/security/ip-lists", "pool-list", 10, 10)
}

// 判据自检（反例固化）：这两条反例正是审计变异造出的形态——
//   - 提前关游标 → 空数组 + 200；
//   - 漏行/错行 → 非空数组但缺目标行。
//
// 两者都必须被判错，否则上面的池用例会退化成「只看状态码」。
func TestSecurityListPayloadErrorRejectsEmptyAndWrongPayloads(t *testing.T) {
	if err := securityListPayloadError([]byte(`{"code":0,"data":[]}`), "pool-policy"); err == nil {
		t.Fatal("空列表（提前关游标的形态）必须判错")
	}
	if err := securityListPayloadError([]byte(`{"code":0,"data":[{"id":1,"name":"other"}]}`), "pool-policy"); err == nil {
		t.Fatal("缺目标行必须判错")
	}
	if err := securityListPayloadError([]byte(`{"code":500,"data":[{"id":1,"name":"pool-policy"}]}`), "pool-policy"); err == nil {
		t.Fatal("非零业务码必须判错")
	}
	if err := securityListPayloadError([]byte(`{"code":0,"data":[{"id":1,"name":"pool-policy"}]}`), "pool-policy"); err != nil {
		t.Fatalf("合法载荷被误判: %v", err)
	}
}
