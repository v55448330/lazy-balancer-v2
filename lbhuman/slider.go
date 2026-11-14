package lbhuman

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// 滑块验证（M2，2026-11-12）：SVG 拼图（零素材文件，服务端内存生成）+
// 轨迹合理性校验 + 签名 cookie。挑战页零外部资源、内联 JS/CSS。

const (
	sliderWidth       = 240 // 拼图区宽度 px
	sliderHeight      = 134
	sliderPieceSize   = 34 // 拼图片块边长
	sliderTolerance   = 3  // x 偏移容差 px（收紧：视觉偏差不再轻易通过）
	sliderPuzzleTTL   = 2 * time.Minute
	sliderMaxAttempts = 3 // 失败 3 次强制换图（防爆破）
	// humanVerifyMaxBody 匿名校验端点请求体硬上限（64KiB，滑块与 JS PoW 同口径；
	// 远超合法提交：track 点数帽 4096 × 每点 ≤8 字符 + 表单开销）。
	humanVerifyMaxBody = 64 << 10
	// sliderTrackMaxPoints 轨迹采样点数帽（10s 时长上限内合法拖动远低于此值；
	// 超限直接 400，不做无界 Split）。
	sliderTrackMaxPoints = 4096
)

type sliderPuzzle struct {
	id        string
	gapX      int
	createdAt time.Time
	attempts  int
}

var (
	sliderPuzzles   = map[string]*sliderPuzzle{}
	sliderPuzzlesMu sync.Mutex
)

// newSliderPuzzle 生成拼图：随机缺口 x（40%–85% 区段），TTL 2min。
func newSliderPuzzle() *sliderPuzzle {
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	// 缺口 x ∈ [40%, 85%] 区段（避开左端起始与右端终点）
	margin := 12 // 缺口不贴拼图左右边缘
	usable := float64(sliderWidth - sliderPieceSize - margin*2)
	minX := margin + int(usable*0.25)
	maxX := margin + int(usable*0.75)
	gapX := minX + int(raw[0])%(maxX-minX+1)
	p := &sliderPuzzle{id: id, gapX: gapX, createdAt: time.Now()}
	sliderPuzzlesMu.Lock()
	sliderPuzzles[id] = p
	// 清理过期
	for k, v := range sliderPuzzles {
		if time.Since(v.createdAt) > sliderPuzzleTTL {
			delete(sliderPuzzles, k)
		}
	}
	evictOldestPuzzlesLocked(challengeMaterialCap)
	sliderPuzzlesMu.Unlock()
	return p
}

// evictOldestPuzzlesLocked 超硬上限时按创建时刻淘汰最旧拼图（调用方持锁；
// 与 challengeTokens 同款有界热路径）。
func evictOldestPuzzlesLocked(limit int) {
	if len(sliderPuzzles) <= limit {
		return
	}
	ids := make([]string, 0, len(sliderPuzzles))
	for k := range sliderPuzzles {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := sliderPuzzles[ids[i]], sliderPuzzles[ids[j]]
		if !a.createdAt.Equal(b.createdAt) {
			return a.createdAt.Before(b.createdAt)
		}
		return ids[i] < ids[j]
	})
	for _, k := range ids[:len(sliderPuzzles)-limit] {
		delete(sliderPuzzles, k)
	}
}

// puzzleSVG 拼图 SVG：背景（渐变+低透明度几何层次）+ 缺口（socket 语义）。
// 缺口 rect 携带 data-lb-gap（客户端接近高亮用；gap 答案本就视觉可见，不泄露新信息）。
func puzzleSVG(gapX int) string {
	gapY := (sliderHeight-sliderPieceSize)/2 + 10
	return fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%%" stop-color="#2563eb"/><stop offset="1" stop-color="#3b82f6"/>
    </linearGradient>
  </defs>
  <rect width="%d" height="%d" fill="url(#bg)"/>
  <path d="M 0 34 H 240 M 0 96 H 240 M 58 0 V 134 M 176 0 V 134" stroke="#ffffff" opacity="0.07"/>
  <circle cx="196" cy="26" r="30" fill="#ffffff" opacity="0.06"/>
  <path d="M 0 134 L 70 70 L 130 134 Z" fill="#1e40af" opacity="0.10"/>
  <rect x="%d" y="%d" width="%d" height="%d" fill="#0b1220" opacity="0.58" stroke="#ffffff" stroke-opacity="0.65" stroke-width="1.5" data-lb-gap="%d"/>
</svg>`,
		sliderWidth, sliderHeight, sliderWidth, sliderHeight,
		gapX, gapY, sliderPieceSize, sliderPieceSize, gapX)
}

// pieceSVG 拼图片块（亮色主体+单内描边+预烘焙偏移阴影，直角方形）。
func pieceSVG() string {
	return fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">
  <rect x="2" y="2" width="%d" height="%d" fill="#0b1220" opacity="0.18"/>
  <rect x="1" y="1" width="%d" height="%d" fill="#f8fafc" stroke="#1d4ed8" stroke-width="2"/>
  <rect x="6" y="6" width="%d" height="%d" fill="none" stroke="#93c5fd" stroke-width="1"/>
</svg>`, sliderPieceSize, sliderPieceSize, sliderPieceSize-2, sliderPieceSize-2, sliderPieceSize-2, sliderPieceSize-2, sliderPieceSize-12, sliderPieceSize-12)
}

// humanSliderVerifyPath 滑块校验端点路径。
const humanSliderVerifyPath = "/__lb/human/slider-verify"

// sliderVerify 校验：x 偏移容差 + 轨迹合理性（采样点数/时长/加速度方差）。
func sliderVerify(p *sliderPuzzle, x int, track []int, durationMs int) bool {
	if p == nil || time.Since(p.createdAt) > sliderPuzzleTTL {
		return false
	}
	if int(math.Abs(float64(x-p.gapX))) > sliderTolerance {
		return false
	}
	// 轨迹合理性：采样点数≥8、时长 300ms–10s、非匀速（加速度方差>0）
	if len(track) < 8 || durationMs < 300 || durationMs > 10000 {
		return false
	}
	// 加速度方差（相邻位移差的方差）——匀速直线拖动方差=0（脚本特征）
	if len(track) < 3 {
		return false
	}
	deltas := make([]float64, len(track)-1)
	for i := 1; i < len(track); i++ {
		deltas[i-1] = float64(track[i] - track[i-1])
	}
	mean := 0.0
	for _, d := range deltas {
		mean += d
	}
	mean /= float64(len(deltas))
	variance := 0.0
	for _, d := range deltas {
		variance += (d - mean) * (d - mean)
	}
	variance /= float64(len(deltas))
	return variance > 0.5 // 有非匀速性
}

// consumeSliderPuzzle 消费拼图（一次性；失败达上限后下一次强制失效换新；
// TTL 过期即删返回 nil——过期提交走 retryable=false 换新图路径）。
// 返回锁内值快照：attempts/gapX/createdAt 不再被并发消耗改写，
// 调用方锁外读快照无数据竞争（attempts_left 响应组装据此）。
func consumeSliderPuzzle(id string) *sliderPuzzle {
	sliderPuzzlesMu.Lock()
	defer sliderPuzzlesMu.Unlock()
	p, ok := sliderPuzzles[id]
	if !ok {
		return nil
	}
	if time.Since(p.createdAt) > sliderPuzzleTTL {
		delete(sliderPuzzles, id)
		return nil
	}
	p.attempts++
	if p.attempts > sliderMaxAttempts {
		delete(sliderPuzzles, id)
		return nil
	}
	snap := *p
	return &snap
}

// serveSliderChallenge 滑块挑战页（内联 SVG+JS，零外部资源）。
func (h *HumanHandler) serveSliderChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	humanStats.Challenges.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "challenge")
	p := newSliderPuzzle()
	registerChallengeSession(p.id, "slider", h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), sliderPuzzleTTL, sliderMaxAttempts)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	// redirect 注入 JS 字符串：用 json.Marshal（与 challenge.go 同口径），
	// 不得用 html.EscapeString——HTML 实体在 <script> 内是字面文本，& 会被错误编码。
	redirectJSON, _ := json.Marshal(r.URL.RequestURI())
	redirect := string(redirectJSON)
	widget := fmt.Sprintf(sliderWidgetHTML, puzzleSVG(p.gapX), pieceSVG(), p.id, redirect)
	if h.ChallengePageHTML != "" && strings.Contains(h.ChallengePageHTML, "{{human_verify_widget}}") {
		_, _ = io.WriteString(w, strings.Replace(h.ChallengePageHTML, "{{human_verify_widget}}", widget, 1))
		return
	}
	_, _ = io.WriteString(w, fmt.Sprintf(sliderChallengePage, widget))
}

// serveSliderVerify 滑块校验端点。
func (h *HumanHandler) serveSliderVerify(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	// 匿名端点请求体硬上限：超限读取报错 → 400（不得全量读入无界 body）。
	r.Body = http.MaxBytesReader(w, r.Body, humanVerifyMaxBody)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	puzzleID := r.FormValue("puzzle_id")
	xStr := r.FormValue("x")
	trackStr := r.FormValue("track") // 逗号分隔的位移序列
	durationStr := r.FormValue("duration_ms")
	x := atoiSafe(xStr)
	duration := atoiSafe(durationStr)
	parts := strings.Split(trackStr, ",")
	if len(parts) > sliderTrackMaxPoints {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	var track []int
	for _, part := range parts {
		if v := atoiSafe(strings.TrimSpace(part)); v >= 0 {
			track = append(track, v)
		}
	}
	p := consumeSliderPuzzle(puzzleID)
	sliderOK := sliderVerify(p, x, track, duration)
	// 通过时先签 cookie，再把**真实 exp** 登记进运行态会话（面板据此显示放行
	// 剩余/到期）；失败路径不签 cookie，传零时刻。
	var cookieValue string
	var exp time.Time
	if sliderOK {
		cookieValue, exp = signCookie([]byte(h.Secret), ip, r.UserAgent(), time.Duration(h.TTLMinutes)*time.Minute)
	}
	if p == nil {
		markChallengeInvalid(puzzleID)
	} else {
		markChallengeAttempt(puzzleID, sliderOK, sliderOK, exp)
	}
	if !sliderOK {
		humanStats.Fails.Add(1)
		reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "fail")
		// 区分「可重试」与「拼图失效」：attempts_left>0 表示拼图仍在，客户端可
		// 原地重试；耗尽（left=0）即删拼图（与「失败 3 次强制换图」一致），
		// retryable=false，客户端 reload 换新图。attempts_left 服务端权威。
		attemptsLeft := 0
		if p != nil {
			attemptsLeft = sliderMaxAttempts - p.attempts // p 为锁内值快照，读无竞争
			if attemptsLeft < 0 {
				attemptsLeft = 0
			}
			if attemptsLeft == 0 {
				sliderPuzzlesMu.Lock()
				delete(sliderPuzzles, puzzleID)
				sliderPuzzlesMu.Unlock()
			}
		}
		retryable := attemptsLeft > 0
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"ok":false,"retryable":%t,"attempts_left":%d}`, retryable, attemptsLeft)
		return
	}
	// 成功一次性消费：删除拼图，杜绝 TTL 内重放同一 id 再发 cookie。
	sliderPuzzlesMu.Lock()
	delete(sliderPuzzles, puzzleID)
	sliderPuzzlesMu.Unlock()
	// cookie 已在上方签发（exp 已登记进运行态会话），此处只写出响应头。
	// 代理 TLS 终止场景 r.TLS=nil：XFP=https 只增 Secure 不减（伪造方向
	// 无害——最坏让 cookie 仅在 HTTPS 发送，不削弱任何安全属性）。
	secure := ""
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		secure = "; Secure"
	}
	w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s; Path=/; HttpOnly; SameSite=Lax; Expires=%s%s", cookieName, cookieValue, exp.UTC().Format(http.TimeFormat), secure))
	humanStats.Passes.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "pass")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func atoiSafe(s string) int {
	v := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(s), "%d", &v)
	return v
}

// sliderWidgetHTML 自定义挑战页的滑块组件（{{human_verify_widget}} 替换目标）。
// 与内置页共用同一组件（消除两套视觉/交互）；内联样式隔离（类名前缀 lb-hv-）。
// 交互（2026-11-13 用户裁定）：Pointer Events + setPointerCapture（鼠标/触摸统一，
// 移出窗口仍跟踪）、pointercancel/blur 重置、键盘可达（方向键/Enter）、失败原地
// 重试（服务端 retryable/attempts_left 权威）、接近缺口高亮（不泄露精确答案、不吸附）、
// 窄宿主缩放（坐标除以 scale，提交逻辑 px 不变）。安全口径不变：TTL/3 次上限/
// ±3px 容差/轨迹校验全在服务端。
const sliderWidgetHTML = `<div class="lb-hv-widget" style="width:240px;max-width:100%%;margin:18px auto 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif">
<style>
.lb-hv-widget *{box-sizing:border-box}
.lb-hv-widget .lb-hv-puzzle{position:relative;width:240px;height:134px;margin:0 auto 14px;overflow:hidden}
.lb-hv-widget .lb-hv-puzzle>svg{display:block;width:240px;height:134px;border-radius:0}
.lb-hv-widget .lb-hv-piece{position:absolute;top:60px;left:6px;cursor:grab;line-height:0;touch-action:none}
.lb-hv-widget .lb-hv-piece:active{cursor:grabbing}
.lb-hv-widget .lb-hv-track{position:relative;width:240px;height:34px;background:#eef2f7;border:1px solid #dbe4f0;border-radius:0;user-select:none;touch-action:none;overflow:hidden}
.lb-hv-widget .lb-hv-fill{position:absolute;left:0;top:0;bottom:0;background:rgba(37,99,235,.16);width:0;transition:background .15s}
.lb-hv-widget .lb-hv-hint{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:12px;color:#94a3b8;pointer-events:none;transition:opacity .2s}
.lb-hv-widget .lb-hv-handle{position:absolute;top:50%%;left:2px;transform:translateY(-50%%);width:34px;height:28px;background:#2563eb;color:#fff;border-radius:0;display:flex;align-items:center;justify-content:center;cursor:grab;box-shadow:0 2px 6px rgba(37,99,235,.25);transition:background .15s,opacity .15s;touch-action:none}
.lb-hv-widget .lb-hv-handle:hover{background:#1d4ed8}
.lb-hv-widget .lb-hv-handle:active{cursor:grabbing;background:#1e40af}
.lb-hv-widget .lb-hv-handle:focus-visible{outline:2px solid #1d4ed8;outline-offset:2px}
.lb-hv-widget .lb-hv-handle svg{width:16px;height:16px}
.lb-hv-widget.lb-hv-near .lb-hv-handle{background:#1d4ed8}
.lb-hv-widget.lb-hv-near .lb-hv-fill{background:rgba(37,99,235,.30)}
.lb-hv-widget.lb-hv-busy .lb-hv-handle{opacity:.6;pointer-events:none}
.lb-hv-widget.lb-hv-ok .lb-hv-fill{background:rgba(21,128,61,.18)}
.lb-hv-widget.lb-hv-ok .lb-hv-handle{background:#15803d}
.lb-hv-widget.lb-hv-fail .lb-hv-handle{background:#dc2626}
.lb-hv-widget .lb-hv-status{text-align:center;font-size:13px;min-height:20px;margin-top:10px;color:#64748b;transition:color .15s}
.lb-hv-widget .lb-hv-ok{color:#15803d}.lb-hv-widget .lb-hv-fail{color:#dc2626}
</style>
<div class="lb-hv-puzzle">%s<div class="lb-hv-piece" id="lbHvPiece" style="top:60px;left:6px">%s</div></div>
<div class="lb-hv-track" id="lbHvTrack"><div class="lb-hv-fill" id="lbHvFill"></div><div class="lb-hv-hint" id="lbHvHint">Drag the slider to complete the puzzle</div><div class="lb-hv-handle" id="lbHvHandle" role="slider" tabindex="0" aria-label="Slider verification" aria-valuemin="0" aria-valuemax="200" aria-valuenow="0"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 5l7 7-7 7"/><path d="M13 5l7 7-7 7"/></svg></div></div>
<div class="lb-hv-status" id="lbHvStatus" aria-live="polite"></div>
<noscript><div style="text-align:center;font-size:13px;color:#dc2626;margin-top:10px">JavaScript is required to complete verification.</div></noscript>
<script>
(function(){
var pid="%s",redirect=%s,root=document.currentScript.parentNode,h=document.getElementById("lbHvHandle"),pc=document.getElementById("lbHvPiece"),fl=document.getElementById("lbHvFill"),tr=document.getElementById("lbHvTrack"),hint=document.getElementById("lbHvHint"),st=document.getElementById("lbHvStatus");
var gapEl=tr.parentNode.querySelector("[data-lb-gap]"),gapX=gapEl?parseInt(gapEl.getAttribute("data-lb-gap"),10):null;
var drag=false,busy=false,sx=0,t0=0,pos=[],cx=0,mx=200,scale=1,raf=0,attempts=0,issuedAt=Date.now(),kbStart=0;
function measure(){var avail=root.clientWidth||240;scale=avail<240?avail/240:1;root.style.transform=scale<1?"scale("+scale+")":"";root.style.transformOrigin="top center";mx=Math.min(tr.clientWidth-(h.offsetWidth||34)-4,200)}
measure();window.addEventListener("resize",measure);
function paint(){raf=0;h.style.left=(cx+2)+"px";pc.style.left=(cx+6)+"px";fl.style.width=(cx+36)+"px";h.setAttribute("aria-valuenow",String(Math.round(cx)));if(hint)hint.style.opacity=cx>4?"0":"1";var near=gapX!==null&&Math.abs((cx+6)-gapX)<=6;root.classList.toggle("lb-hv-near",near&&drag)}
function sched(){if(!raf)raf=requestAnimationFrame(paint)}
function setX(v){cx=Math.max(0,Math.min(mx,v));sched()}
function reset(){drag=false;cx=0;pos=[];root.classList.remove("lb-hv-near","lb-hv-fail");paint()}
function down(e){if(busy)return;drag=true;sx=e.clientX;t0=Date.now();pos=[];cx=0;root.classList.remove("lb-hv-fail");if(h.setPointerCapture&&e.pointerId!==undefined){try{h.setPointerCapture(e.pointerId)}catch(_){}}e.preventDefault()}
function move(e){if(!drag||busy)return;var dx=(e.clientX-sx)/scale;setX(dx);pos.push(Math.round(cx));if(e.cancelable)e.preventDefault()}
function springBack(){var from=cx,start=Date.now();function step(){var p=Math.min(1,(Date.now()-start)/150);setX(from*(1-p)*(1-p));if(p<1)requestAnimationFrame(step);else{cx=0;paint()}}requestAnimationFrame(step)}
function submit(){if(busy)return;var dur=Date.now()-t0;
if(cx<4||dur<300){springBack();return}
busy=true;root.classList.add("lb-hv-busy");
fetch("/__lb/human/slider-verify",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},credentials:"same-origin",body:"puzzle_id="+encodeURIComponent(pid)+"&x="+(cx+6)+"&track="+pos.join(",")+"&duration_ms="+dur}).then(function(res){return res.json().catch(function(){return{ok:res.ok}})}).then(function(d){busy=false;root.classList.remove("lb-hv-busy");
if(d.ok){root.classList.add("lb-hv-ok");st.textContent="Verified";st.className="lb-hv-status lb-hv-ok";setTimeout(function(){window.location.href=redirect},400);return}
attempts++;
if(d.retryable&&attempts<3&&Date.now()-issuedAt<110000){root.classList.add("lb-hv-fail");st.textContent="Verification failed — "+(d.attempts_left!=null?d.attempts_left:Math.max(0,3-attempts))+" tries left";st.className="lb-hv-status lb-hv-fail";springBack();return}
st.textContent="Verification failed";st.className="lb-hv-status lb-hv-fail";setTimeout(function(){window.location.reload()},900)}).catch(function(){busy=false;root.classList.remove("lb-hv-busy");st.textContent="Network error";st.className="lb-hv-status lb-hv-fail"})}
function up(){if(!drag)return;drag=false;submit()}
function cancel(){if(!drag)return;drag=false;springBack()}
if(window.PointerEvent){h.addEventListener("pointerdown",down);h.addEventListener("pointermove",move);h.addEventListener("pointerup",up);h.addEventListener("pointercancel",cancel);h.addEventListener("lostpointercapture",cancel)}
else{h.addEventListener("mousedown",down);document.addEventListener("mousemove",move);document.addEventListener("mouseup",up);h.addEventListener("touchstart",function(e){down(e.touches[0])},{passive:false});document.addEventListener("touchmove",function(e){move(e.touches[0])},{passive:false});document.addEventListener("touchend",up);document.addEventListener("touchcancel",cancel)}
window.addEventListener("blur",cancel);
h.addEventListener("keydown",function(e){if(busy)return;var step=e.shiftKey?8:2,k=e.key;
if(k==="ArrowRight"||k==="ArrowLeft"||k==="Home"||k==="End"){if(!kbStart){kbStart=Date.now();t0=kbStart;pos=[]}if(k==="ArrowRight")setX(cx+step);else if(k==="ArrowLeft")setX(cx-step);else if(k==="Home")setX(0);else setX(mx);pos.push(Math.round(cx));e.preventDefault();return}
if(k==="Enter"||k===" "){if(kbStart){t0=kbStart;submit()}e.preventDefault();return}
if(k==="Escape"){kbStart=0;reset();e.preventDefault()}});
paint()})();
</script></div>`

// sliderChallengePage 滑块挑战内置回退页（英文、直角方形，与内置拦截页壳同族）。
// 复用 sliderWidgetHTML 组件（消除两套视觉/交互）；仅在策略未配挑战页时命中。
const sliderChallengePage = `<!DOCTYPE html>
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
  <div class="sub">Please complete the human verification to continue.</div>
  %s
</div>
</body>
</html>`
