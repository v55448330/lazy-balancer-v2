package handlers

// QQ 扫码绑定闭环：①生成一次性绑定码（10 分钟有效，同用户旧码作废）
// ②轮询绑定状态（绑定码被 QQ 侧「绑定 XXX」指令消费 → 通道 target 已写入
// openid = bound）。前端向导展示码+引导扫码发指令，轮询到 bound 即自动
// 进入下一步（openid 由绑定流程写入，无需手填）。

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// PostQQBindCode 生成绑定码（登录用户；旧码立即作废防堆积）。
func (h *Handlers) PostQQBindCode(c *gin.Context) {
	uid := contextUserID(c)
	code := make([]byte, 0, 6)
	for range 6 {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("生成绑定码失败", err)})
			return
		}
		code = append(code, byte('0'+n.Int64()))
	}
	_, _ = db.DB.Exec(`DELETE FROM qq_bind_codes WHERE user_id=?`, uid)
	expires := time.Now().UTC().Add(10 * time.Minute)
	if _, err := db.DB.Exec(`INSERT INTO qq_bind_codes (code, user_id, expires_at) VALUES (?,?,?)`,
		string(code), uid, expires.UTC().Format("2006-01-02 15:04:05")); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("生成绑定码失败", err)})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"code":       string(code),
		"expires_at": expires.UTC().Format(time.RFC3339),
	}})
}

// GetQQBindCode 轮询绑定状态：该用户 qq 通道存在（绑定指令已消费落 openid）
// 即 bound=true；否则回最新有效码供继续展示（消费后码已删——bound 不可依赖
// 码行存在，直接以通道行为准）。
func (h *Handlers) GetQQBindCode(c *gin.Context) {
	uid := contextUserID(c)
	var openid string
	var boundErr error
	if boundErr = db.DB.QueryRow(`SELECT target FROM notification_channels WHERE user_id=? AND type='qq' ORDER BY updated_at DESC LIMIT 1`, uid).Scan(&openid); boundErr == nil {
		var target struct {
			OpenID string `json:"openid"`
		}
		if json.Unmarshal([]byte(openid), &target) == nil && target.OpenID != "" {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
				"bound":  true,
				"openid": target.OpenID,
			}})
			return
		}
	}
	var code string
	var generatedAt time.Time
	err := db.DB.QueryRow(`SELECT code, expires_at FROM qq_bind_codes WHERE user_id=? ORDER BY expires_at DESC LIMIT 1`, uid).
		Scan(&code, &generatedAt)
	if err != nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"bound": false, "has_code": false}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"has_code":     true,
		"code":         code,
		"expires_at":   generatedAt.UTC().Format(time.RFC3339),
		"bound":        false,
		"openid":       "",
	}})
}
