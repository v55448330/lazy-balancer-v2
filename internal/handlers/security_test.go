package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// SLB9-6(第 9 轮审计):GetCRSInfo/GetIP2RegionInfo 对齐 SC-11——仅行缺失
// (ErrNoRows)合法回落默认值,真实 DB 故障 500 可见(此前一律吞为默认)。
func TestGetCRSInfo_dbFailureReturns500(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 换坏库:关掉真库换一个无表库使查询报错(非 ErrNoRows)
	bad, err := sql.Open("sqlite", t.TempDir()+"/bad.db")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	oldDB := db.DB
	db.DB = bad
	t.Cleanup(func() { db.DB = oldDB })
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.GetCRSInfo(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("CRS status=%d, want 500 on real DB failure", w.Code)
	}
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	h.GetIP2RegionInfo(c2)
	if w2.Code != http.StatusInternalServerError {
		t.Fatalf("IP2Region status=%d, want 500 on real DB failure", w2.Code)
	}
}
