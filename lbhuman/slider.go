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
	sliderWidth       = 240 // 拼图区宽度 px
	sliderHeight      = 134
	sliderPieceSize   = 34 // 拼图片块边长
	sliderTolerance   = 3  // x 偏移容差 px（收紧：视觉偏差不再轻易通过）
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
	sliderPuzzlesMu.Unlock()
	return p
}

// puzzleSVG 拼图 SVG：背景（抽象渐变+几何形）+ 缺口（暗色拼图轮廓）。
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
  <path d="M 0 0 H 96 L 0 64 Z" fill="#ffffff" opacity="0.06"/>
  <rect x="%d" y="%d" width="%d" height="%d" fill="#0b1220" opacity="0.58" stroke="#ffffff" stroke-opacity="0.55" stroke-width="1.5" stroke-dasharray="4 3"/>
</svg>`,
		sliderWidth, sliderHeight, sliderWidth, sliderHeight,
		gapX, gapY, sliderPieceSize, sliderPieceSize)
}

// pieceSVG 拼图片块（同轮廓，亮色描边）。
func pieceSVG() string {
	return fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">
  <defs><filter id="lbHvShadow" x="-30%%" y="-30%%" width="160%%" height="160%%"><feDropShadow dx="0" dy="2" stdDeviation="2" flood-color="#0f172a" flood-opacity=".25"/></filter></defs>
  <rect width="%d" height="%d" fill="#ffffff" fill-opacity="0.95" filter="url(#lbHvShadow)"/>
</svg>`, sliderPieceSize, sliderPieceSize, sliderPieceSize, sliderPieceSize)
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
	pieceTop := (sliderHeight-sliderPieceSize)/2 + 10
	redirect := html.EscapeString(r.URL.RequestURI())
	widget := fmt.Sprintf(sliderWidgetHTML, puzzleSVG(p.gapX), pieceSVG(), p.id, redirect)
	if h.ChallengePageHTML != "" && strings.Contains(h.ChallengePageHTML, "{{human_verify_widget}}") {
		_, _ = io.WriteString(w, strings.Replace(h.ChallengePageHTML, "{{human_verify_widget}}", widget, 1))
		return
	}
	_, _ = fmt.Fprintf(w, sliderChallengePage,
		sliderWidth, sliderHeight, pieceTop, puzzleSVG(p.gapX), pieceSVG(), p.id, redirect)
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
const sliderWidgetHTML = `<div class="lb-hv-widget" style="width:240px;max-width:100%%;margin:0 auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif">
<style>
.lb-hv-widget *{box-sizing:border-box}
.lb-hv-widget .lb-hv-puzzle{position:relative;width:240px;height:134px;margin:0 auto 14px}
.lb-hv-widget .lb-hv-puzzle>svg{display:block;width:240px;height:134px;border-radius:0}
.lb-hv-widget .lb-hv-piece{position:absolute;top:60px;left:0;cursor:grab;line-height:0}
.lb-hv-widget .lb-hv-piece:active{cursor:grabbing}
.lb-hv-widget .lb-hv-track{position:relative;width:240px;height:34px;background:#eef2f7;border:1px solid #dbe4f0;border-radius:0;user-select:none;touch-action:none;overflow:hidden}
.lb-hv-widget .lb-hv-fill{position:absolute;left:0;top:0;bottom:0;background:#2563eb;opacity:.16;width:0}
.lb-hv-widget .lb-hv-handle{position:absolute;top:3px;left:2px;width:34px;height:28px;background:#2563eb;color:#fff;border-radius:0;display:flex;align-items:center;justify-content:center;font-size:18px;cursor:grab;box-shadow:0 2px 6px rgba(37,99,235,.25)}
.lb-hv-widget .lb-hv-handle:active{cursor:grabbing}
.lb-hv-widget .lb-hv-status{text-align:center;font-size:13px;min-height:20px;margin-top:10px;color:#64748b}
.lb-hv-widget .lb-hv-ok{color:#15803d}.lb-hv-widget .lb-hv-fail{color:#dc2626}
</style>
<div class="lb-hv-puzzle">%s<div class="lb-hv-piece" id="lbHvPiece" style="top:60px;left:0">%s</div></div>
<div class="lb-hv-track" id="lbHvTrack"><div class="lb-hv-fill" id="lbHvFill"></div><div class="lb-hv-handle" id="lbHvHandle">⇥</div></div>
<div class="lb-hv-status" id="lbHvStatus"></div>
<script>
(function(){
var pid="%s",redirect="%s",h=document.getElementById("lbHvHandle"),pc=document.getElementById("lbHvPiece"),fl=document.getElementById("lbHvFill"),tr=document.getElementById("lbHvTrack"),st=document.getElementById("lbHvStatus"),drag=false,sx=0,t0=0,pos=[],cx=0,mx=tr.clientWidth-(h.offsetWidth||34)-4;
function dn(e){drag=true;sx=(e.touches?e.touches[0].clientX:e.clientX);t0=Date.now();pos=[];cx=0;e.preventDefault()}
function mv(e){if(!drag)return;var x=(e.touches?e.touches[0].clientX:e.clientX);cx=Math.max(0,Math.min(mx,x-sx));h.style.left=(cx+2)+"px";pc.style.left=cx+"px";fl.style.width=(cx+2)+"px";pos.push(cx)}
function up(){if(!drag)return;drag=false;var dur=Date.now()-t0;
fetch("/__lb/human/slider-verify",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},credentials:"same-origin",body:"puzzle_id="+encodeURIComponent(pid)+"&x="+cx+"&track="+pos.join(",")+"&duration_ms="+dur}).then(function(res){
if(res.ok){st.textContent="Verified";st.className="lb-hv-status lb-hv-ok";setTimeout(function(){window.location.href=redirect},400)}else{st.textContent="Verification failed";st.className="lb-hv-status lb-hv-fail";setTimeout(function(){window.location.reload()},900)}}).catch(function(){st.textContent="Network error";st.className="lb-hv-status lb-hv-fail"})}
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
  .puzzle { position: relative; margin: 0 auto 18px; width: %dpx; height: %dpx; }
  .puzzle svg { display: block; }
  .piece { position: absolute; top: %dpx; left: 0; transition: none; cursor: grab; }
  .piece:active { cursor: grabbing; }
  .track { position: relative; height: 34px; background: #e2e8f0; border-radius: 0; user-select: none; }
  .track-fill { position: absolute; left: 0; top: 0; bottom: 0; background: #4299e1; border-radius: 0; opacity: .25; width: 0; }
  .handle { position: absolute; top: 3px; left: 2px; width: 34px; height: 28px; background: #4299e1; color: #fff; border-radius: 0; display: flex; align-items: center; justify-content: center; font-size: 18px; cursor: grab; }
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
  var maxX = trackEl.clientWidth - (handle.offsetWidth || 34) - 4;

  function down(e) {
    dragging = true; startX = (e.touches ? e.touches[0].clientX : e.clientX);
    startTime = Date.now(); positions = []; currentX = 0;
    e.preventDefault();
  }
  function move(e) {
    if (!dragging) return;
    var cx = (e.touches ? e.touches[0].clientX : e.clientX);
    currentX = Math.max(0, Math.min(maxX, cx - startX));
    handle.style.left = (currentX + 2) + "px";
    piece.style.left = currentX + "px";
    fill.style.width = (currentX + 2) + "px";
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
        statusEl.textContent = "Verified, redirecting…";
        statusEl.className = "status ok";
        setTimeout(function () { window.location.href = redirect; }, 400);
      } else {
        statusEl.textContent = "Verification failed, please retry";
        statusEl.className = "status fail";
        setTimeout(function () { window.location.reload(); }, 900);
      }
    }).catch(function () {
      statusEl.textContent = "Network error";
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
