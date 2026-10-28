package middleware

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// newAPIKeyWhitelistFixture 建最小库（users/api_keys）并返回请求函数；
// 三把 Key 分别覆盖白名单 JSON 畸形、CIDR 越界（/33）与合法 CIDR。
func newAPIKeyWhitelistFixture(t *testing.T) func(apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	oldDB := db.DB
	database, err := sql.Open("sqlite", t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB = database
	db.SetDB(database)
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldDB)
		database.Close()
	})
	if _, err := database.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, is_enabled BOOLEAN);
		CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name TEXT, key_hash TEXT, key_prefix TEXT, created_by INTEGER, last_used DATETIME, expires_at DATETIME, is_enabled BOOLEAN, mcp_enabled BOOLEAN, read_only BOOLEAN, mcp_ip_whitelist TEXT);
		INSERT INTO users VALUES (1,'whitelist-user','user',1);`); err != nil {
		t.Fatal(err)
	}
	seed := func(id int, name, plain, whitelist string) {
		hash := sha256.Sum256([]byte(plain))
		if _, err := database.Exec(`INSERT INTO api_keys VALUES (?,?,?,?,1,NULL,NULL,1,0,0,?)`,
			id, name, hex.EncodeToString(hash[:]), plain[:12], whitelist); err != nil {
			t.Fatal(err)
		}
	}
	seed(11, "bad-json", "lb_sk_bad-json-whitelist", "not-json")
	seed(12, "bad-cidr", "lb_sk_bad-cidr-whitelist", `["10.0.0.0/33"]`)
	seed(13, "valid-cidr", "lb_sk_valid-cidr-whitelist", `["192.0.2.0/24"]`)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(apiKeyAuth(db.DB))
	router.GET("/api/v1/rules", func(c *gin.Context) { c.Status(http.StatusOK) })
	return func(apiKey string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		request.RemoteAddr = "192.0.2.8:1234"
		request.Header.Set("X-API-Key", apiKey)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
}

// TestAPIKeyAuthRejectsMalformedWhitelistJSON 钉住反序列化失败分支：配置无效
// 必须是 500（而非静默放行/401 密钥无效）。
func TestAPIKeyAuthRejectsMalformedWhitelistJSON(t *testing.T) {
	withIsolatedAPIKeyWhitelistCache(t)
	request := newAPIKeyWhitelistFixture(t)

	response := request("lb_sk_bad-json-whitelist")
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "API Key IP 白名单配置无效") {
		t.Fatalf("status=%d body=%s, want 500 白名单配置无效", response.Code, response.Body.String())
	}
}

// TestAPIKeyAuthRejectsInvalidCIDRWithoutCaching 钉住 CIDR 解析失败分支与
// 「解析失败不缓存」契约：两次请求都必须 500，且缓存中不得出现该 Key 的条目
// （缓存了空结果会让后续请求跳过校验）。
func TestAPIKeyAuthRejectsInvalidCIDRWithoutCaching(t *testing.T) {
	withIsolatedAPIKeyWhitelistCache(t)
	request := newAPIKeyWhitelistFixture(t)

	for attempt := 1; attempt <= 2; attempt++ {
		response := request("lb_sk_bad-cidr-whitelist")
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "API Key IP 白名单配置无效") {
			t.Fatalf("第 %d 次请求 status=%d body=%s, want 500 白名单配置无效", attempt, response.Code, response.Body.String())
		}
	}
	cacheKey := `12|["10.0.0.0/33"]`
	if _, cached := apiKeyWhitelistCache.Load(cacheKey); cached {
		t.Fatalf("解析失败的 CIDR 被写入缓存（key=%s）——后续请求会跳过校验", cacheKey)
	}
}

// 包级缓存被写入异构值时必须视为未命中并重新解析，不能让请求 goroutine
// 因无 comma-ok 类型断言 panic；解析后的正确类型应回写缓存。
func TestAPIKeyAuthRecoversFromHeterogeneousWhitelistCacheEntry(t *testing.T) {
	withIsolatedAPIKeyWhitelistCache(t)
	request := newAPIKeyWhitelistFixture(t)
	const cacheKey = `13|["192.0.2.0/24"]`
	apiKeyWhitelistCache.Store(cacheKey, "heterogeneous")

	response := request("lb_sk_valid-cidr-whitelist")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 after cache reparse", response.Code, response.Body.String())
	}
	cached, ok := apiKeyWhitelistCache.Load(cacheKey)
	if !ok {
		t.Fatal("reparsed whitelist was not cached")
	}
	networks, ok := cached.([]*net.IPNet)
	if !ok || len(networks) != 1 || networks[0].String() != "192.0.2.0/24" {
		t.Fatalf("cache entry was not replaced with parsed networks: %T %v", cached, cached)
	}
}
