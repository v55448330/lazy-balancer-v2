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
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

var (
	qqTaskMu     sync.Mutex
	qqTaskByUser = map[int64]*notify.BindTask{}
	// qqBoundByUser 最近一次绑定完成下发的凭据（per-user，qqTaskMu 守护）。
	// 多机器人：全局仅首 bot（入站 WS），后续 bot 凭据在保存通道时钉入
	// target——本映射是保存钉住的凭据源（openid 匹配防误钉）。
	qqBoundByUser = map[int64]qqBoundCred{}
)

// qqBoundCred 扫码绑定完成下发的凭据+openid。
type qqBoundCred struct {
	AppID  string
	Secret string
	OpenID string
}

// PostQQBindCode 生成扫码绑定二维码（旧任务作废）。
func (h *Handlers) PostQQBindCode(c *gin.Context) {
	uid := contextUserID(c)
	qrContent, task, err := notify.CreateBindTask()
	if err != nil {
		c.JSON(http.StatusBadGateway, apimsg.Envelope(c, 502, "notify.qqBindTaskCreateFailed", err.Error()))
		return
	}
	qqTaskMu.Lock()
	qqTaskByUser[uid] = task
	qqTaskMu.Unlock()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"qr_content": qrContent,
		"expires_in": 300, // 统一绑定窗口 5min（与 wx 一致；超时提示获取新码）
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
	if time.Since(task.CreatedAt) > 5*time.Minute {
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
		c.JSON(http.StatusBadGateway, apimsg.Envelope(c, 502, "notify.qqBindPollFailed", err.Error()))
		return
	}
	if result.Status != notify.BindCompleted {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
			"bound": false, "has_task": true, "status": int(result.Status),
		}})
		return
	}

	// completed：首个 bot 凭据落全局（入站 WS 鉴权单源）；后续绑定不覆盖
	// 全局（覆盖=连接 Daemon 重连老 bot 掉线根因），凭据记入 qqBoundByUser
	// 供保存通道时钉入 target。通道创建不在此处——「保存」动作是建通道的
	// 唯一入口（此前绑定完成即 upsert 通道，导致「删除通道→重新绑定→保存」
	// 被误判已存在）。
	if _, err := notify.SaveQQBotCredentialsIfAbsent(result.AppID, result.AppSecret); err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.qqBindCredentialSaveFailed", err))
		return
	}
	qqTaskMu.Lock()
	delete(qqTaskByUser, uid)
	qqBoundByUser[uid] = qqBoundCred{AppID: result.AppID, Secret: result.AppSecret, OpenID: result.UserOpenID}
	qqTaskMu.Unlock()

	recordAudit(c, "绑定", "QQ 机器人", "扫码绑定成功（AppID "+result.AppID+"，openid "+result.UserOpenID+"）")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"bound":  true,
		"appid":  result.AppID,
		"openid": result.UserOpenID,
	}})
}
