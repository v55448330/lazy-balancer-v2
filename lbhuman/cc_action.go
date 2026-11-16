package lbhuman

// CC 触发动作三态分流（2026-11 用户裁定：统一检测面，响应动作可选）：
//   - challenge（默认，存量行为冻结）：人机验证挑战页/JSON 401；
//   - queue：排队等待页（200+HTML+倒计时自动重试组件，复用挑战页模板通道
//     {{queue_widget}} 占位符）；API/XHR 客户端拿 JSON 429+Retry-After；
//   - reject：429 拒绝（HTML 拦截页由渲染链 errors 路由承载——插件侧直接
//     429+Retry-After，浏览器拿内置等待/拒绝页，API 拿 JSON）。
//
// 等待秒数：cc_queue_wait_sec=0 自动取 CC 窗口（窗口过期自然放行）；
// 客户端指数退避（N→2N→4N 封顶 300s）在 queue_widget JS 内实现，服务端
// 零队列状态——强制力在「仍超限→仍等待页」，退避只是重试风暴防护。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// queueWaitSec 生效等待秒数：显式值优先，0=自动取 CC 窗口（下限 1s）。
func (h *HumanHandler) queueWaitSec() int {
	if h.CCQueueWaitSec > 0 {
		return h.CCQueueWaitSec
	}
	if h.CCWindowSec > 0 {
		return h.CCWindowSec
	}
	return 1
}

// serveCCTriggerAction CC 触发后按策略动作分流。force 模式不经此（恒挑战）。
func (h *HumanHandler) serveCCTriggerAction(w http.ResponseWriter, r *http.Request, ip string) {
	switch h.CCTriggerAction {
	case "queue":
		h.serveQueueWait(w, r, ip)
	case "reject":
		h.serveRateReject(w, r, ip)
	default: // challenge（含空串缺省）
		h.serveChallengeForRequest(w, r, ip)
	}
}

// serveQueueWait 排队等待页：浏览器拿 200+HTML（倒计时自动重试），
// API/XHR 或非幂等请求拿 JSON 429+Retry-After（机器客户端按标准头重试）。
func (h *HumanHandler) serveQueueWait(w http.ResponseWriter, r *http.Request, ip string) {
	wait := h.queueWaitSec()
	if !isIdempotentMethod(r.Method) || wantsJSONRequest(r) {
		h.serveRateJSON(w, r, ip, wait, "queue")
		return
	}
	// queue 等待页属挑战发放口径（kind=challenge），与事件落库同口径计计数器。
	humanStats.Challenges.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), "challenge")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK) // 等待页=200（与挑战页同语义，非错误）
	redirectJSON, _ := json.Marshal(r.URL.RequestURI())
	widget := fmt.Sprintf(queueWidgetHTML, wait, wait, string(redirectJSON))
	if h.ChallengePageHTML != "" && strings.Contains(h.ChallengePageHTML, "{{queue_widget}}") {
		_, _ = io.WriteString(w, strings.Replace(h.ChallengePageHTML, "{{queue_widget}}", widget, 1))
		return
	}
	_, _ = io.WriteString(w, fmt.Sprintf(queueWaitPage, widget))
}

// serveRateReject 限流拒绝：429+Retry-After。浏览器文档导航拿内置拒绝页
// （策略拦截页由渲染链承载；插件侧回退内置页），API 拿 JSON。
func (h *HumanHandler) serveRateReject(w http.ResponseWriter, r *http.Request, ip string) {
	wait := h.queueWaitSec()
	if !isIdempotentMethod(r.Method) || wantsJSONRequest(r) {
		h.serveRateJSON(w, r, ip, wait, "reject")
		return
	}
	// reject 事件按「被拦截」口径喂自动封禁（kind=rate_reject → blocked 维度）。
	// 大屏口径（用户裁定，注释明示）：rate_reject 落库
	// action=blocked/rule=cc_rate_reject，进事件 feed 与总量，但**不入攻击
	// 光流环**（光流只收 WAF 攻击族；CC 限流拒绝属人机通道）——同屏「有 CC
	// 光流（挑战族）无 CC 弧（拒绝族）」是有意口径，非遗漏。
	// anomaly_score 口径：人机/CC 事件不自带评分，落库恒 0，
	// 评分由面板预检/存量补分承载——产生侧不发射评分字段。
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), "rate_reject")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", strconv.Itoa(wait))
	w.WriteHeader(http.StatusTooManyRequests)
	if h.ChallengePageHTML != "" && !strings.Contains(h.ChallengePageHTML, "{{queue_widget}}") && !strings.Contains(h.ChallengePageHTML, "{{human_") {
		// 策略绑定的纯拦截页（无挑战/排队占位符）直接作为拒绝页 body。
		_, _ = io.WriteString(w, h.ChallengePageHTML)
		return
	}
	_, _ = io.WriteString(w, rateRejectPage)
}

// serveRateJSON API/XHR 客户端的 429 JSON（queue/reject 同形，code 区分）。
func (h *HumanHandler) serveRateJSON(w http.ResponseWriter, r *http.Request, ip string, wait int, action string) {
	if action == "reject" {
		reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), "rate_reject")
	} else {
		// queue JSON 同属挑战发放口径（reject 走 rate_reject→blocked，不计）。
		humanStats.Challenges.Add(1)
		reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), "challenge")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", strconv.Itoa(wait))
	w.WriteHeader(http.StatusTooManyRequests)
	payload, _ := json.Marshal(map[string]any{
		"code":        "rate_limited",
		"action":      action,
		"message":     "too many requests; retry after the wait period",
		"retry_after": wait,
	})
	_, _ = w.Write(payload)
}

// queueWidgetHTML 排队倒计时组件（%d=等待秒数，%s=原 URI JSON）。
// 客户端指数退避：首次等 N 秒自动重放；倒计时自然结束保留退避计数——仍超限
// 再拿等待页时 JS 读 sessionStorage 计数翻倍等待（封顶 300s）；仅手动
// Retry now 清零回基础等待。服务端零队列状态。
const queueWidgetHTML = `<div class="lb-queue" style="width:300px;max-width:100%%;margin:18px auto 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-align:center">
<div style="font-size:34px;font-weight:700;color:#d97706" id="lb-queue-count">%d</div>
<div style="font-size:13px;color:#6b7280;margin-top:6px">Too many requests — retrying automatically when the countdown ends.</div>
<button id="lb-queue-retry" style="margin-top:14px;padding:8px 22px;border:1px solid #d97706;background:#fffbeb;color:#b45309;font-size:13px;cursor:pointer">Retry now</button>
<script>
(function(){
var base=%d,uri=%s,key="lb_queue_backoff";
var n=parseInt(sessionStorage.getItem(key)||"0",10);
var wait=Math.min(base*Math.pow(2,n),300);
sessionStorage.setItem(key,String(n+1));
var el=document.getElementById("lb-queue-count"),left=wait;
el.textContent=left;
function go(manual){if(manual){sessionStorage.removeItem(key);}window.location.href=uri;}
var t=setInterval(function(){left--;if(left<=0){clearInterval(t);go();}else{el.textContent=left;}},1000);
document.getElementById("lb-queue-retry").onclick=function(){clearInterval(t);go(true);};
})();
</script>
</div>`

// queueWaitPage 内置等待页回退（策略未配页/无占位符时）。
const queueWaitPage = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Please Wait</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fffbeb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<div style="text-align:center;padding:32px">
<div style="font-size:20px;font-weight:700;color:#b45309">Please Wait</div>
<div style="font-size:13px;color:#92400e;margin-top:8px">You have sent too many requests. This page retries automatically.</div>
%s
</div>
</body></html>`

// rateRejectPage 内置拒绝页回退（429）。
const rateRejectPage = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>429 Too Many Requests</title></head>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fffbeb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<div style="text-align:center;padding:32px">
<div style="font-size:20px;font-weight:700;color:#b45309">429 · Too Many Requests</div>
<div style="font-size:13px;color:#92400e;margin-top:8px">You have sent too many requests in a short time. Please wait and try again.</div>
</div>
</body></html>`
