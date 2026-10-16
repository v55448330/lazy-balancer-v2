package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 爬虫地址库名单条目在地址列表与详情中必须一致可见；不得被威胁库计数/
// 文件读取路径覆写成空。
func TestIPLists_crawlerEntriesVisibleInListAndDetail(t *testing.T) {
	// Given：两条真实爬虫名单条目
	h := newBackupTestHandlers(t)
	var listID int
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at)
		VALUES ('Google 官方爬虫 IP（common-crawlers）','Google 官方源','搜索引擎爬虫','[{"value":"66.249.66.0/24"},{"value":"66.249.67.0/24"}]',1,datetime('now'),datetime('now')) RETURNING id`).Scan(&listID); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)
	router.GET("/security/ip-lists/:id", h.GetIPList)

	// When：列表
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	// Then：条目数=2，不是威胁计数覆写后的 0
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResp.Code, listResp.Body.String())
	}
	var payload struct {
		Data []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			EntryCount int    `json:"entry_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range payload.Data {
		if row.ID == listID {
			found = true
			if row.EntryCount != 2 {
				t.Errorf("列表条目数=%d want 2", row.EntryCount)
			}
		}
	}
	if !found {
		t.Fatal("爬虫名单未出现在地址列表")
	}

	// When：详情
	detailResp := httptest.NewRecorder()
	router.ServeHTTP(detailResp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(listID), nil))
	// Then：详情也返回同样两条，而非威胁文件空集
	if detailResp.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", detailResp.Code, detailResp.Body.String())
	}
	var detail struct {
		Data struct {
			Entries []struct {
				Value string `json:"value"`
			} `json:"entries"`
			EntryCount int `json:"entry_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(detailResp.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Data.Entries) != 2 || detail.Data.EntryCount != 2 {
		t.Fatalf("详情条目错误: %+v", detail.Data)
	}
}
