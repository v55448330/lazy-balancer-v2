package lbhuman

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// humanVerifyPath JS 挑战校验端点路径（保留路径前缀，业务路径冲突时豁免配置兜底）。
const humanVerifyPath = "/__lb/human/verify"

// humanStats 全局挑战统计（总览卡数据源）。
var humanStats struct {
	Challenges atomic.Int64 // 挑战页发放数
	Passes     atomic.Int64 // 验证通过数
	Fails      atomic.Int64 // 验证失败数
	Bans       atomic.Int64 // CC ban 响应数
}

// serveJSChallenge 发放 JS 挑战页（PoW 工作量证明，浏览器执行，脚本无法）。
func (h *HumanHandler) serveJSChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	humanStats.Challenges.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "challenge")
	token := issueChallengeToken()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK) // 挑战页=200（不是错误），与拦截页（4xx）语义区分
	_, _ = fmt.Fprintf(w, jsChallengePage, token, r.URL.RequestURI())
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
	if token == "" || nonce == "" || !consumeChallengeToken(token) || !powValid(token, nonce) {
		humanStats.Fails.Add(1)
		reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "fail")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	cookieValue, exp := signCookie([]byte(h.Secret), ip, r.UserAgent(), time.Duration(h.TTLMinutes)*time.Minute)
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

// jsChallengePage 内置 JS 挑战页（内联 JS/CSS，零外部资源）。
// 交互：浏览器计算 SHA256(token+nonce) 前 4 位十六进制为零 → 提交 → 跳转。
// 真人无感（<1s），脚本无法执行 JS 直接挡住。中英双语。
const jsChallengePage = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全验证 · Security Check</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #f0f2f5; font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; }
  .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 24px rgba(0,0,0,.08); padding: 40px 36px; max-width: 420px; width: 92%%; text-align: center; }
  .shield { font-size: 48px; margin-bottom: 16px; }
  h1 { font-size: 20px; color: #1a202c; margin-bottom: 8px; }
  p { font-size: 13px; color: #718096; line-height: 1.6; margin-bottom: 20px; }
  .spinner { width: 32px; height: 32px; border: 3px solid #e2e8f0; border-top-color: #4299e1; border-radius: 50%%; margin: 0 auto 16px; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .status { font-size: 13px; color: #4299e1; min-height: 20px; }
  .success { color: #38a169; }
  .fail { color: #e53e3e; }
</style>
</head>
<body>
<div class="card">
  <div class="shield">🛡</div>
  <h1>安全验证 · Security Check</h1>
  <p>正在验证您的浏览器，请稍候…<br>Verifying your browser, please wait…</p>
  <div class="spinner" id="spinner"></div>
  <div class="status" id="status">正在计算…</div>
</div>
<script>
(function () {
  var token = "%s";
  var redirect = "%s";
  var statusEl = document.getElementById("status");
  var spinner = document.getElementById("spinner");
  var difficulty = 4;
  var prefix = "0000";

  function sha256Hex(msg) {
    var enc = new TextEncoder().encode(msg);
    return crypto.subtle.digest("SHA-256", enc).then(function (buf) {
      return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    });
  }

  async function solve() {
    var nonce = 0;
    var start = Date.now();
    while (true) {
      var hex = await sha256Hex(token + nonce);
      if (hex.startsWith(prefix)) return String(nonce);
      nonce++;
      if (nonce %% 1000 === 0) {
        statusEl.textContent = "验证中… (" + nonce + ")";
        await new Promise(function (r) { setTimeout(r, 0); });
        if (Date.now() - start > 30000) throw new Error("timeout");
      }
    }
  }

  solve().then(function (nonce) {
    statusEl.textContent = "验证通过，正在跳转… Verified, redirecting…";
    statusEl.className = "status success";
    spinner.style.display = "none";
    return fetch("/__lb/human/verify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "token=" + encodeURIComponent(token) + "&nonce=" + encodeURIComponent(nonce),
      credentials: "same-origin"
    });
  }).then(function (res) {
    if (res.ok) {
      setTimeout(function () { window.location.href = redirect; }, 400);
    } else {
      throw new Error("verify failed");
    }
  }).catch(function () {
    statusEl.textContent = "验证失败，请刷新重试 · Failed, please refresh";
    statusEl.className = "status fail";
    spinner.style.display = "none";
  });
})();
</script>
</body>
</html>`
