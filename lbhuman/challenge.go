package lbhuman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// humanVerifyPath JS 挑战校验端点路径（保留路径前缀，业务路径冲突时豁免配置兜底）。
const humanVerifyPath = "/__lb/human/verify"

// humanStats 全局挑战统计（总览卡数据源）。CC「封禁」响应退役（2026-11-13）：
// 封禁由自动封禁管线承载，此处只计挑战发放/通过/失败。
var humanStats struct {
	Challenges atomic.Int64 // 挑战页发放数
	Passes     atomic.Int64 // 验证通过数
	Fails      atomic.Int64 // 验证失败数
}

// serveJSChallenge 发放 JS 挑战页（PoW 工作量证明，浏览器执行）。
// 判定边界（准确表述）：挡的是**不执行 JS 的客户端**（curl/requests/多数扫描器与
// CC 工具）；能跑 JS 的自动化客户端（headless 浏览器）可以通过，PoW 只提高其
// 成本，不构成人机识别——真实拦截力来自自动封禁按挑战发放/失败计数封 IP。
// 页面选择与滑块同构：策略页含 {{human_js_widget}} 则注入 JS 组件，否则回退内置页。
func (h *HumanHandler) serveJSChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	humanStats.Challenges.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "challenge")
	token := issueChallengeToken()
	registerChallengeSession(token, "js", h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), challengeTokenTTL, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK) // 挑战页=200（不是错误），与拦截页（4xx）语义区分
	// redirect 注入 JS 字符串用 json.Marshal（HTML 实体在 <script> 内是字面文本）。
	redirectJSON, _ := json.Marshal(r.URL.RequestURI())
	widget := fmt.Sprintf(jsWidgetHTML, token, string(redirectJSON))
	if h.ChallengePageHTML != "" && strings.Contains(h.ChallengePageHTML, "{{human_js_widget}}") {
		_, _ = io.WriteString(w, strings.Replace(h.ChallengePageHTML, "{{human_js_widget}}", widget, 1))
		return
	}
	_, _ = io.WriteString(w, fmt.Sprintf(jsChallengePage, widget))
}

// serveJSVerify 校验 PoW 答案 → 通过发签名 cookie → 前端跳转原 URL。
func (h *HumanHandler) serveJSVerify(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	token := r.FormValue("token")
	nonce := r.FormValue("nonce")
	tokenOK := token != "" && nonce != "" && consumeChallengeToken(token)
	powOK := tokenOK && powValid(token, nonce)
	// 通过时先签 cookie，再把真实 exp 登记进运行态会话（放行剩余/到期数据源）。
	var cookieValue string
	var exp time.Time
	if powOK {
		cookieValue, exp = signCookie([]byte(h.Secret), ip, r.UserAgent(), time.Duration(h.TTLMinutes)*time.Minute)
	}
	if tokenOK {
		markChallengeAttempt(token, powOK, true, exp)
	} else {
		markChallengeInvalid(token)
	}
	if !tokenOK || !powOK {
		humanStats.Fails.Add(1)
		reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "fail")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	// cookie 已在上方签发（exp 已登记进运行态会话），此处只写出响应头。
	secure := ""
	if r.TLS != nil {
		secure = "; Secure"
	}
	w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s; Path=/; HttpOnly; SameSite=Lax; Expires=%s%s", cookieName, cookieValue, exp.UTC().Format(http.TimeFormat), secure))
	humanStats.Passes.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "pass")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// serveChallengeByType 按策略验证方式分流挑战页（slider=滑块，js=PoW）。
func (h *HumanHandler) serveChallengeByType(w http.ResponseWriter, r *http.Request, ip string) {
	if h.Type == "slider" {
		h.serveSliderChallenge(w, r, ip)
		return
	}
	h.serveJSChallenge(w, r, ip)
}

// jsWidgetHTML 自定义挑战页的 JS 验证组件（{{human_js_widget}} 替换目标）。
// 与滑块组件并列、互不干扰：滑块用 {{human_verify_widget}}。内联样式隔离
// （类名前缀 lb-hv-js），直角方形、英文状态，零外部资源。
const jsWidgetHTML = `<div class="lb-hv-js" style="width:280px;max-width:100%%;margin:18px auto 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif">
<style>
.lb-hv-js *{box-sizing:border-box}
.lb-hv-js .lb-hv-js-bar{position:relative;width:100%%;height:10px;background:#eef2f7;border:1px solid #dbe4f0;border-radius:0;overflow:hidden}
.lb-hv-js .lb-hv-js-fill{position:absolute;left:0;top:0;bottom:0;width:35%%;background:#2563eb;border-radius:0;animation:lbHvJsScan 1.1s ease-in-out infinite}
@keyframes lbHvJsScan{0%%{left:-35%%}100%%{left:100%%}}
.lb-hv-js .lb-hv-js-status{text-align:center;font-size:13px;min-height:20px;margin-top:10px;color:#64748b;transition:color .15s}
.lb-hv-js .lb-hv-js-ok{color:#15803d}
.lb-hv-js .lb-hv-js-fail{color:#dc2626}
.lb-hv-js.lb-hv-js-done .lb-hv-js-fill{animation:none;left:0;width:100%%;background:#15803d}
.lb-hv-js.lb-hv-js-error .lb-hv-js-fill{animation:none;left:0;width:100%%;background:#dc2626}
</style>
<div class="lb-hv-js-bar"><div class="lb-hv-js-fill"></div></div>
<div class="lb-hv-js-status" aria-live="polite">Verifying your browser…</div>
<noscript><div style="text-align:center;font-size:13px;color:#dc2626;margin-top:10px">JavaScript is required to complete verification.</div></noscript>
<script>
(function(){
var token="%s",redirect=%s,root=document.currentScript.parentNode,st=root.querySelector(".lb-hv-js-status"),prefix="0000";
function fail(msg){root.classList.add("lb-hv-js-error");st.textContent=msg;st.className="lb-hv-js-status lb-hv-js-fail"}
function sha256Hex(msg){return crypto.subtle.digest("SHA-256",new TextEncoder().encode(msg)).then(function(buf){return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0")}).join("")})}
async function solve(){var nonce=0,start=Date.now();for(;;){var hex=await sha256Hex(token+nonce);if(hex.indexOf(prefix)===0)return String(nonce);nonce++;if(nonce%%512===0){st.textContent="Verifying your browser… ("+nonce+")";await new Promise(function(r){setTimeout(r,0)});if(Date.now()-start>30000)throw new Error("timeout")}}}
if(!window.crypto||!crypto.subtle){fail("This browser cannot complete verification.");return}
solve().then(function(nonce){return fetch("/__lb/human/verify",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},credentials:"same-origin",body:"token="+encodeURIComponent(token)+"&nonce="+encodeURIComponent(nonce)})}).then(function(res){
if(!res.ok)throw new Error("verify failed");
root.classList.add("lb-hv-js-done");st.textContent="Verified";st.className="lb-hv-js-status lb-hv-js-ok";setTimeout(function(){window.location.href=redirect},400)}).catch(function(){fail("Verification failed, please reload the page.")})})();
</script></div>`

// jsChallengePage 内置 JS 挑战页（英文、直角方形，与内置拦截页壳同族）。
// 复用 jsWidgetHTML 组件（消除两套视觉/交互）；仅在策略未配 JS 挑战页时命中。
const jsChallengePage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Check</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(165deg, #f8fafc 0%%, #f1f5f9 45%%, #eef2f7 100%%); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .card { background: #fff; border-radius: 0; box-shadow: 0 1px 2px rgba(16,24,40,.05), 0 12px 32px -8px rgba(16,24,40,.12); padding: 40px 32px 28px; max-width: 400px; width: 92%%; text-align: center; }
  .shield { width: 56px; height: 56px; margin: 0 auto 16px; display: flex; align-items: center; justify-content: center; background: linear-gradient(145deg, #eff6ff, #dbeafe); border: 1px solid #bfdbfe; }
  .shield svg { width: 30px; height: 30px; }
  h1 { font-size: 20px; font-weight: 700; color: #0f172a; margin-bottom: 8px; }
  .sub { font-size: 13px; color: #64748b; line-height: 1.6; }
</style>
</head>
<body>
<div class="card">
  <div class="shield"><svg viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg></div>
  <h1>Security Check</h1>
  <div class="sub">Please wait while your browser is verified. You will be redirected automatically.</div>
  %s
</div>
</body>
</html>`
