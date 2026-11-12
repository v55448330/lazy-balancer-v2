package lbhuman

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 滑块验证（M2，2026-11-12）：SVG 拼图（零素材文件，服务端内存生成）+
// 轨迹合理性校验 + 签名 cookie。挑战页零外部资源、内联 JS/CSS。

const (
	sliderWidth       = 320 // 拼图区宽度 px
	sliderHeight      = 180
	sliderPieceSize   = 44 // 拼图片块边长
	sliderTolerance   = 5  // x 偏移容差 px
	sliderPuzzleTTL   = 2 * time.Minute
	sliderMaxAttempts = 3 // 失败 3 次强制换图（防爆破）
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
	usable := float64(sliderWidth - sliderPieceSize)
	minX := int(usable * 0.40)
	maxX := int(usable * 0.85)
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
	sliderPuzzlesMu.Unlock()
	return p
}

// puzzleSVG 拼图 SVG：背景（抽象渐变+几何形）+ 缺口（暗色拼图轮廓）。
func puzzleSVG(gapX int) string {
	gapY := (sliderHeight-sliderPieceSize)/2 + 10
	return fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%%" stop-color="#3b5bdb"/><stop offset="1" stop-color="#6741d9"/>
    </linearGradient>
  </defs>
  <rect width="%d" height="%d" fill="url(#bg)" rx="4"/>
  <circle cx="60" cy="50" r="28" fill="#ffffff" opacity="0.12"/>
  <circle cx="240" cy="120" r="40" fill="#ffffff" opacity="0.10"/>
  <path d="M 30 140 Q 90 100 160 130 T 290 110" stroke="#ffffff" stroke-width="2" fill="none" opacity="0.25"/>
  <path d="M %d %d h %d v %d h -%d z M %d %d a 6 6 0 0 1 12 0 v 6 h -12 z"
        fill="#1a202c" opacity="0.55"/>
</svg>`,
		sliderWidth, sliderHeight, sliderWidth, sliderHeight,
		gapX, gapY, sliderPieceSize, sliderPieceSize, sliderPieceSize,
		gapX+sliderPieceSize/2-6, gapY-6)
}

// pieceSVG 拼图片块（同轮廓，亮色描边）。
func pieceSVG() string {
	return fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">
  <path d="M 0 0 h %d v %d h -%d z M %d -6 a 6 6 0 0 1 12 0 v 6 h -12 z"
        fill="#f8f9fa" stroke="#dee2e6" stroke-width="1.5"/>
</svg>`, sliderPieceSize, sliderPieceSize+6, sliderPieceSize, sliderPieceSize+6, sliderPieceSize, sliderPieceSize/2-6)
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

// consumeSliderPuzzle 消费拼图（一次性；attempts 超上限强制失效换新）。
func consumeSliderPuzzle(id string) *sliderPuzzle {
	sliderPuzzlesMu.Lock()
	defer sliderPuzzlesMu.Unlock()
	p, ok := sliderPuzzles[id]
	if !ok {
		return nil
	}
	p.attempts++
	if p.attempts >= sliderMaxAttempts {
		delete(sliderPuzzles, id)
		return nil
	}
	return p
}

// serveSliderChallenge 滑块挑战页（内联 SVG+JS，零外部资源）。
func (h *HumanHandler) serveSliderChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	humanStats.Challenges.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "challenge")
	p := newSliderPuzzle()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	pieceTop := (sliderHeight-sliderPieceSize)/2 + 10 - 6
	redirect := html.EscapeString(r.URL.RequestURI())
	widget := fmt.Sprintf(sliderWidgetHTML, puzzleSVG(p.gapX), pieceSVG(), p.id, redirect)
	if h.ChallengePageHTML != "" && strings.Contains(h.ChallengePageHTML, "{{human_verify_widget}}") {
		_, _ = io.WriteString(w, strings.Replace(h.ChallengePageHTML, "{{human_verify_widget}}", widget, 1))
		return
	}
	_, _ = fmt.Fprintf(w, sliderChallengePage,
		sliderWidth, pieceTop, puzzleSVG(p.gapX), pieceSVG(), p.id, redirect)
}

// serveSliderVerify 滑块校验端点。
func (h *HumanHandler) serveSliderVerify(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	puzzleID := r.FormValue("puzzle_id")
	xStr := r.FormValue("x")
	trackStr := r.FormValue("track") // 逗号分隔的位移序列
	durationStr := r.FormValue("duration_ms")
	x := atoiSafe(xStr)
	duration := atoiSafe(durationStr)
	var track []int
	for _, part := range strings.Split(trackStr, ",") {
		if v := atoiSafe(strings.TrimSpace(part)); v >= 0 {
			track = append(track, v)
		}
	}
	p := consumeSliderPuzzle(puzzleID)
	if !sliderVerify(p, x, track, duration) {
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

func atoiSafe(s string) int {
	v := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(s), "%d", &v)
	return v
}

// sliderWidgetHTML 自定义挑战页的滑块组件（{{human_verify_widget}} 替换目标）。
// 与内置页同一拼图/轨道/校验逻辑；内联样式隔离（类名前缀 lb-hv- 防污染）。
const sliderWidgetHTML = `<div class="lb-hv-widget" style="max-width:360px;margin:0 auto">
<style>
.lb-hv-widget .lb-hv-puzzle{position:relative;margin-bottom:16px}
.lb-hv-widget .lb-hv-piece{position:absolute;cursor:grab}
.lb-hv-widget .lb-hv-track{position:relative;height:40px;background:#e2e8f0;border-radius:4px;user-select:none}
.lb-hv-widget .lb-hv-fill{position:absolute;left:0;top:0;bottom:0;background:#4299e1;opacity:.25;border-radius:4px;width:0}
.lb-hv-widget .lb-hv-handle{position:absolute;top:2px;left:0;width:44px;height:36px;background:#4299e1;color:#fff;border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:18px;cursor:grab}
.lb-hv-widget .lb-hv-status{text-align:center;font-size:13px;min-height:20px;margin-top:10px}
.lb-hv-widget .lb-hv-ok{color:#38a169}.lb-hv-widget .lb-hv-fail{color:#e53e3e}
</style>
<div class="lb-hv-puzzle">%s<div class="lb-hv-piece" id="lbHvPiece" style="top:66px;left:0">%s</div></div>
<div class="lb-hv-track" id="lbHvTrack"><div class="lb-hv-fill" id="lbHvFill"></div><div class="lb-hv-handle" id="lbHvHandle">⇥</div></div>
<div class="lb-hv-status" id="lbHvStatus"></div>
<script>
(function(){
var pid="%s",redirect="%s",h=document.getElementById("lbHvHandle"),pc=document.getElementById("lbHvPiece"),fl=document.getElementById("lbHvFill"),tr=document.getElementById("lbHvTrack"),st=document.getElementById("lbHvStatus"),drag=false,sx=0,t0=0,pos=[],cx=0,mx=tr.clientWidth-44;
function dn(e){drag=true;sx=(e.touches?e.touches[0].clientX:e.clientX);t0=Date.now();pos=[];cx=0;e.preventDefault()}
function mv(e){if(!drag)return;var x=(e.touches?e.touches[0].clientX:e.clientX);cx=Math.max(0,Math.min(mx,x-sx));h.style.left=cx+"px";pc.style.left=cx+"px";fl.style.width=cx+"px";pos.push(cx)}
function up(){if(!drag)return;drag=false;var dur=Date.now()-t0;
fetch("/__lb/human/slider-verify",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},credentials:"same-origin",body:"puzzle_id="+encodeURIComponent(pid)+"&x="+cx+"&track="+pos.join(",")+"&duration_ms="+dur}).then(function(res){
if(res.ok){st.textContent="验证通过 · Verified";st.className="lb-hv-status lb-hv-ok";setTimeout(function(){window.location.href=redirect},400)}else{st.textContent="验证失败 · Failed";st.className="lb-hv-status lb-hv-fail";setTimeout(function(){window.location.reload()},900)}}).catch(function(){st.textContent="网络错误 · Network error";st.className="lb-hv-status lb-hv-fail"})}
h.addEventListener("mousedown",dn);h.addEventListener("touchstart",dn,{passive:false});
document.addEventListener("mousemove",mv);document.addEventListener("touchmove",mv,{passive:false});
document.addEventListener("mouseup",up);document.addEventListener("touchend",up)})();
</script></div>`

// sliderChallengePage 滑块挑战页模板（中英双语、深色友好、直角口径）。
const sliderChallengePage = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全验证 · Security Check</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #f0f2f5; font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; }
  .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 24px rgba(0,0,0,.1); padding: 32px 28px; max-width: 400px; width: 92%%; }
  .head { text-align: center; margin-bottom: 20px; }
  .shield { font-size: 40px; margin-bottom: 8px; }
  h1 { font-size: 18px; color: #1a202c; }
  .sub { font-size: 12px; color: #718096; margin-top: 6px; }
  .puzzle { position: relative; margin: 0 auto 18px; width: %dpx; }
  .puzzle svg { display: block; }
  .piece { position: absolute; top: %dpx; left: 0; transition: none; cursor: grab; }
  .piece:active { cursor: grabbing; }
  .track { position: relative; height: 40px; background: #e2e8f0; border-radius: 4px; user-select: none; }
  .track-fill { position: absolute; left: 0; top: 0; bottom: 0; background: #4299e1; border-radius: 4px; opacity: .25; width: 0; }
  .handle { position: absolute; top: 2px; left: 0; width: 44px; height: 36px; background: #4299e1; color: #fff; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 18px; cursor: grab; }
  .handle:active { cursor: grabbing; }
  .hint { text-align: center; font-size: 12px; color: #718096; margin-top: 12px; }
  .status { text-align: center; font-size: 13px; min-height: 20px; margin-top: 10px; }
  .ok { color: #38a169; }
  .fail { color: #e53e3e; }
</style>
</head>
<body>
<div class="card">
  <div class="head">
    <div class="shield">🛡</div>
    <h1>安全验证 · Security Check</h1>
    <div class="sub">按住滑块，拖动完成拼图 · Drag the slider to complete the puzzle</div>
  </div>
  <div class="puzzle" id="puzzle">
    %s
    <div class="piece" id="piece">%s</div>
  </div>
  <div class="track" id="track">
    <div class="track-fill" id="fill"></div>
    <div class="handle" id="handle">⇥</div>
  </div>
  <div class="hint">将拼图片块拖入缺口 · Drag the piece into the gap</div>
  <div class="status" id="status"></div>
</div>
<script>
(function () {
  var puzzleID = "%s";
  var redirect = "%s";
  var handle = document.getElementById("handle");
  var piece = document.getElementById("piece");
  var fill = document.getElementById("fill");
  var trackEl = document.getElementById("track");
  var statusEl = document.getElementById("status");
  var dragging = false, startX = 0, startTime = 0, positions = [], currentX = 0;
  var maxX = trackEl.clientWidth - 44;

  function down(e) {
    dragging = true; startX = (e.touches ? e.touches[0].clientX : e.clientX);
    startTime = Date.now(); positions = []; currentX = 0;
    e.preventDefault();
  }
  function move(e) {
    if (!dragging) return;
    var cx = (e.touches ? e.touches[0].clientX : e.clientX);
    currentX = Math.max(0, Math.min(maxX, cx - startX));
    handle.style.left = currentX + "px";
    piece.style.left = currentX + "px";
    fill.style.width = currentX + "px";
    positions.push(currentX);
  }
  function up() {
    if (!dragging) return;
    dragging = false;
    var duration = Date.now() - startTime;
    fetch("/__lb/human/slider-verify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      credentials: "same-origin",
      body: "puzzle_id=" + encodeURIComponent(puzzleID) + "&x=" + currentX +
        "&track=" + positions.join(",") + "&duration_ms=" + duration
    }).then(function (res) {
      if (res.ok) {
        statusEl.textContent = "验证通过，正在跳转… Verified, redirecting…";
        statusEl.className = "status ok";
        setTimeout(function () { window.location.href = redirect; }, 400);
      } else {
        statusEl.textContent = "验证失败，请重试 · Failed, please retry";
        statusEl.className = "status fail";
        setTimeout(function () { window.location.reload(); }, 900);
      }
    }).catch(function () {
      statusEl.textContent = "网络错误，请重试 · Network error";
      statusEl.className = "status fail";
    });
  }
  handle.addEventListener("mousedown", down);
  handle.addEventListener("touchstart", down, { passive: false });
  document.addEventListener("mousemove", move);
  document.addEventListener("touchmove", move, { passive: false });
  document.addEventListener("mouseup", up);
  document.addEventListener("touchend", up);
})();
</script>
</body>
</html>`
