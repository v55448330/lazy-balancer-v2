package handlers

// QQ 扫码绑定 REST（官方插件协议：create_bind_task → connect.html 二维码 →
// poll_bind_result → 凭据下发）。协议实现见 internal/notify/qqbind.go。
// 状态机：POST 生成二维码（per-user task，内存态；重启作废重新生成）→
// 前端轮询 GET → completed 时凭据落 notify_settings + openid 绑定通知通道。

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

var (
	qqTaskMu     sync.Mutex
	qqTaskByUser = map[int64]*notify.BindTask{}
)

// PostQQBindCode 生成扫码绑定二维码（旧任务作废）。
func (h *Handlers) PostQQBindCode(c *gin.Context) {
	uid := contextUserID(c)
	qrContent, task, err := notify.CreateBindTask()
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_413b63ec", err.Error()), MessageKey: msgQQTaskCreateFailed})
		return
	}
	qqTaskMu.Lock()
	qqTaskByUser[uid] = task
	qqTaskMu.Unlock()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"qr_content": qrContent,
		"expires_in": 600,
	}})
}

// GetQQBindCode 轮询绑定状态：completed 时凭据落 notify_settings + openid 绑
// 定通知通道（投递目标），返回 bound=true。
func (h *Handlers) GetQQBindCode(c *gin.Context) {
	uid := contextUserID(c)
	qqTaskMu.Lock()
	task := qqTaskByUser[uid]
	qqTaskMu.Unlock()
	if task == nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"bound": false, "has_task": false}})
		return
	}
	if time.Since(task.CreatedAt) > 10*time.Minute {
		qqTaskMu.Lock()
		delete(qqTaskByUser, uid)
		qqTaskMu.Unlock()
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"bound": false, "has_task": false, "expired": true}})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	result, err := notify.PollBindResult(ctx, task)
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_27469cbd", err.Error()), MessageKey: msgQQPollFailed})
		return
	}
	if result.Status != notify.BindCompleted {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
			"bound": false, "has_task": true, "status": int(result.Status),
		}})
		return
	}

	// completed：凭据落 notify_settings（连接 Daemon 鉴权单源）
	if err := notify.SaveQQBotCredentials(result.AppID, result.AppSecret); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("凭据落库失败", err)})
		return
	}
	// openid 绑定通知通道（投递目标：QQ 单聊）——先 UPDATE（重绑场景），
	// 0 行命中再 INSERT（首绑；ON CONFLICT 依赖唯一索引匹配，target JSON
	// 常量表达式的冲突目标不可靠，故显式两步）。
	res, err := db.DB.Exec(`UPDATE notification_channels SET target=?, updated_at=datetime('now')
		WHERE user_id=? AND type='qq'`, `{"openid":"`+result.UserOpenID+`"}`, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("绑定通道回填失败", err)})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled, created_at, updated_at)
			VALUES (?, 'qq', 'QQ 机器人', ?, 1, datetime('now'), datetime('now'))`,
			uid, `{"openid":"`+result.UserOpenID+`"}`); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("绑定通道创建失败", err)})
			return
		}
	}
	qqTaskMu.Lock()
	delete(qqTaskByUser, uid)
	qqTaskMu.Unlock()

	recordAudit(c, "绑定", "QQ 机器人", "扫码绑定成功（AppID "+result.AppID+"，openid "+result.UserOpenID+"）")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"bound":  true,
		"appid":  result.AppID,
		"openid": result.UserOpenID,
	}})
}
