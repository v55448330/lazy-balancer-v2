package lbhuman

// 会话级封禁执法点（自动封禁 NAT 态会话封禁的 HTTP 执法出口）：
//
// 数据源：面板侧 services 写 <data_dir>/autoban-session-bans.json（原子落盘，
// 载荷 {"bans":[{"key":"归一IP|指纹","expires_at_ms":unix毫秒}]}），本模块按
// stat 热感知读取（mtime/size 变化即重读，与 crawler-ip-lists.json 同族交换
// 契约；无 Caddy 重载）。路径缺省 /app/data/autoban-session-bans.json，自定义
// data_dir 经渲染配置键 session_ban_file 下发（Provision 应用）。
//
// 执法语义：ServeHTTP 入口按「归一 IP×会话指纹」查封禁——命中直接 403 拒绝
// （不发挑战、不放行，即使持有效 cookie：封禁不是「未验证」）。未命中走现有
// 挑战链。无指纹请求不受会话封禁影响（IP 级执法仍由名单通道承担，L4 不动）。
// 条目自带 expires_at_ms，到期即自动解封（不依赖面板清理节拍）。
//
// fail-open：交换文件缺席/损坏不阻断正常请求（执法数据源故障 ≠ 全站拒绝）；
// 本地态：只读本机文件，无跨节点拉取（会话封禁不集群同步）。

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// defaultSessionBanFile 交换文件容器默认路径（与面板侧
// services.defaultAutobanSessionBanFile 逐字节一致——跨进程契约双锚，
// 改一侧必须同步另一侧）。
const defaultSessionBanFile = "/app/data/autoban-session-bans.json"

// sessionBanFile 交换文件当前路径（Provision 应用配置键；包级单值
// last-writer-wins，与 crawlerIPListFile 同族——渲染侧保证全部规则同值）。
var sessionBanFile = defaultSessionBanFile

// sessionBanStatInterval stat 热感知最小间隔（执法点热路径每请求一次
// stat 的节流窗；窗口内直接用缓存集合。与 @ipListFast ≤1s 热感知同量级）。
var sessionBanStatInterval = time.Second

// sessionBanCache 交换文件运行期缓存（stat 代际 + 生效键集）。
var sessionBanCache struct {
	mu        sync.Mutex
	filePath  string
	modTime   time.Time
	size      int64
	checkedAt time.Time
	bans      map[string]int64 // 复合键 → expires_at_ms（含到期条目，读时判定）
	loaded    bool
}

// sessionBanPayload 交换载荷形态（面板侧 AutobanSessionBanSnapshot 同契约）。
type sessionBanPayload struct {
	Bans []struct {
		Key         string `json:"key"`
		ExpiresAtMS int64  `json:"expires_at_ms"`
	} `json:"bans"`
}

// setSessionBanFilePath 应用配置路径（Provision；空值忽略）。路径变化时
// 重置缓存——否则旧路径的成功快照在 stat 节流窗内继续服役。
func setSessionBanFilePath(path string) {
	if path == "" {
		return
	}
	sessionBanCache.mu.Lock()
	defer sessionBanCache.mu.Unlock()
	if sessionBanFile != path {
		sessionBanFile = path
		sessionBanCache.loaded = false
		sessionBanCache.bans = nil
	}
}

// sessionBanLookup 查会话封禁：命中返回 true。fail-open——文件缺席/损坏/
// 读失败一律按无封禁处理（不阻断正常请求）。到期条目读时过滤（expires_at_ms
// <= now 即解封，无需面板清理）。
func sessionBanLookup(ip, fingerprint string) bool {
	if fingerprint == "" {
		return false // 无会话标识：无法归属会话，IP 级执法走名单通道
	}
	key := normalizeIP(ip) + "|" + fingerprint
	now := timeNow()
	sessionBanCache.mu.Lock()
	defer sessionBanCache.mu.Unlock()
	if !sessionBanCache.loaded || sessionBanCache.filePath != sessionBanFile || now.Sub(sessionBanCache.checkedAt) >= sessionBanStatInterval {
		sessionBanRefreshLocked(now)
	}
	exp, ok := sessionBanCache.bans[key]
	return ok && exp > now.UnixMilli()
}

// sessionBanRefreshLocked stat 热感知重读（调用方持缓存锁）。代际未变
// （mtime+size 同）只刷新检查时刻；变化即重读。读失败保留旧集合 fail-stale
// 一个节流窗后按空集合 fail-open（与名单加载器同族：短暂故障不抖执法）。
func sessionBanRefreshLocked(now time.Time) {
	path := sessionBanFile
	sessionBanCache.checkedAt = now
	info, err := os.Stat(path)
	if err != nil {
		// 缺席/不可 stat：空集合（fail-open）。面板尚未产生过封禁是常态。
		sessionBanCache.filePath = path
		sessionBanCache.bans = nil
		sessionBanCache.loaded = true
		sessionBanCache.modTime, sessionBanCache.size = time.Time{}, 0
		return
	}
	if sessionBanCache.loaded && sessionBanCache.filePath == path &&
		info.ModTime().Equal(sessionBanCache.modTime) && info.Size() == sessionBanCache.size {
		return // 代际未变：缓存命中
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return // 读失败：保留旧集合（fail-stale），下一节流窗重试
	}
	var payload sessionBanPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		// 损坏载荷：按空集合 fail-open（半截写入窗口由原子落盘消除，
		// 此处兜底带外污染）。
		caddy.Log().Named("lb_human").Sugar().Warnf("session ban exchange file corrupt, failing open: %s: %v", path, err)
		sessionBanCache.filePath = path
		sessionBanCache.bans = nil
		sessionBanCache.loaded = true
		sessionBanCache.modTime, sessionBanCache.size = info.ModTime(), info.Size()
		return
	}
	bans := make(map[string]int64, len(payload.Bans))
	for _, b := range payload.Bans {
		// 键形门：复合身份（归一 IP|指纹）才采信——裸 IP 不是会话封禁。
		if i := strings.IndexByte(b.Key, '|'); i > 0 && i < len(b.Key)-1 {
			bans[b.Key] = b.ExpiresAtMS
		}
	}
	sessionBanCache.filePath = path
	sessionBanCache.bans = bans
	sessionBanCache.loaded = true
	sessionBanCache.modTime, sessionBanCache.size = info.ModTime(), info.Size()
}

// serveSessionBanned 会话封禁拒绝响应：恒 403（封禁不是挑战——不发
// X-Human-Challenge、不发挑战页）。浏览器导航给最小 HTML 拒绝态，
// API/XHR 给 JSON（code=session_banned，与挑战链的 API 分流同形）。
func serveSessionBanned(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isIdempotentMethod(r.Method) && !wantsJSONRequest(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>This session has been blocked by the automatic ban policy.</p></body></html>"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	payload, _ := json.Marshal(map[string]string{
		"code":    "session_banned",
		"message": "this session has been blocked by the automatic ban policy",
	})
	_, _ = w.Write(payload)
}

// resetSessionBanCacheForTest 清空执法缓存（测试隔离）。
func resetSessionBanCacheForTest() {
	sessionBanCache.mu.Lock()
	defer sessionBanCache.mu.Unlock()
	sessionBanCache.filePath = ""
	sessionBanCache.bans = nil
	sessionBanCache.loaded = false
	sessionBanCache.modTime, sessionBanCache.size = time.Time{}, 0
	sessionBanCache.checkedAt = time.Time{}
}
