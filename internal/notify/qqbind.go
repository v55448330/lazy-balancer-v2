package notify

// QQ 官方「扫码绑定」协议实现（对齐 @tencent-connect/qqbot-connector 1.2.0
// 行为，端点为腾讯 Agent 生态内部接口——2026-03 起稳定，无兼容性承诺，
// 变更即本文件集中适配）。
//
// 流程：①本地生成 32B 随机 AES-256 密钥（base64）→ create_bind_task 换
// task_id；②二维码内容 = q.qq.com/qqbot/openclaw/connect.html?task_id=…
// （前端渲染二维码，手机 QQ 扫码后在 QQ 内置浏览器选机器人确认绑定）；
// ③轮询 poll_bind_result：status=2（COMPLETED）时下发 bot_appid +
// bot_encrypt_secret（base64(IV(12B)‖ciphertext‖GCM-Tag(16B))，密钥即步骤①
// 密钥）→ AES-GCM 解密出 appSecret；status=3（EXPIRED）→ 重建 task 换新码。
// 绑定产出 appId/appSecret/userOpenid——凭据落 notify_settings（连接 Daemon
// 鉴权单源），openid 绑定通知通道 target（投递目标）。

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// 端点 var（测试 mock 覆写；生产=官方 Agent 生态端点，见协议调研）。
var (
	// 端点 var（测试 mock 覆写；生产=官方 Agent 生态端点）。
	BindTaskURL = "https://q.qq.com/lite/create_bind_task"
	BindPollURL = "https://q.qq.com/lite/poll_bind_result"

	qqConnectURLTmpl = "https://q.qq.com/qqbot/openclaw/connect.html?task_id=%s&source=&_wv=2"
)

// BindTask 一次扫码绑定会话（进程内存态；重启即作废，用户重新生成）。
type BindTask struct {
	Key       []byte // 32B AES-256 密钥
	TaskID    string
	CreatedAt time.Time
}

var (
	bindMu         sync.Mutex
	bindTaskByUser = map[int64]*BindTask{}
)

// CreateBindTask 创建扫码绑定任务：返回可直接渲染的二维码内容（connect URL）
// 与内部 task（poll 用）。
func CreateBindTask() (qrContent string, task *BindTask, err error) {
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return "", nil, err
	}
	body, _ := json.Marshal(map[string]string{"key": base64.StdEncoding.EncodeToString(key)})
	req, err := http.NewRequest(http.MethodPost, BindTaskURL, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return "", nil, fmt.Errorf("create_bind_task status=%d body=%.256s", resp.StatusCode, string(raw))
	}
	var pr struct {
		Retcode int `json:"retcode"`
		Data    struct {
			TaskID string `json:"task_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &pr); err != nil || pr.Retcode != 0 || pr.Data.TaskID == "" {
		return "", nil, fmt.Errorf("create_bind_task 响应异常: %.256s", string(raw))
	}
	task = &BindTask{Key: key, TaskID: pr.Data.TaskID, CreatedAt: time.Now()}
	return fmt.Sprintf(qqConnectURLTmpl, pr.Data.TaskID), task, nil
}

// bindStatus 扫码状态。
type bindStatus int

const (
	bindNone      bindStatus = 0
	bindPending   bindStatus = 1
	BindCompleted bindStatus = 2
	BindExpired   bindStatus = 3
)

// BindResult 轮询结果（completed 时含凭据）。
type BindResult struct {
	Status     bindStatus
	AppID      string
	AppSecret  string
	UserOpenID string
}

// PollBindResult 轮询绑定结果；status=completed 时自动解密 appSecret。
func PollBindResult(ctx context.Context, task *BindTask) (BindResult, error) {
	body, _ := json.Marshal(map[string]string{"task_id": task.TaskID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BindPollURL, bytes.NewReader(body))
	if err != nil {
		return BindResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return BindResult{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return BindResult{}, fmt.Errorf("poll_bind_result status=%d body=%.256s", resp.StatusCode, string(raw))
	}
	var pr struct {
		Retcode int `json:"retcode"`
		Data    struct {
			Status           int    `json:"status"`
			BotAppID         string `json:"bot_appid"`
			BotEncryptSecret string `json:"bot_encrypt_secret"`
			UserOpenID       string `json:"user_openid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &pr); err != nil {
		return BindResult{}, fmt.Errorf("poll 响应解析失败: %w", err)
	}
	out := BindResult{Status: bindStatus(pr.Data.Status)}
	if out.Status != BindCompleted {
		return out, nil
	}
	if pr.Data.BotEncryptSecret == "" {
		return BindResult{}, errors.New("绑定完成响应缺 bot_encrypt_secret")
	}
	secret, err := decryptBotSecret(task.Key, pr.Data.BotEncryptSecret)
	if err != nil {
		return BindResult{}, fmt.Errorf("解密 appSecret 失败: %w", err)
	}
	out.AppID = pr.Data.BotAppID
	out.AppSecret = secret
	out.UserOpenID = pr.Data.UserOpenID
	return out, nil
}

// decryptBotSecret AES-256-GCM：密文 = base64(IV(12B)‖ciphertext‖tag(16B))，
// key = create_bind_task 上交的 32B 密钥。
func decryptBotSecret(key []byte, encB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return "", err
	}
	if len(raw) < 12+16 {
		return "", errors.New("bot_encrypt_secret 长度不足（IV+tag）")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv, ct := raw[:12], raw[12:]
	plain, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM 解密失败: %w", err)
	}
	return string(plain), nil
}
