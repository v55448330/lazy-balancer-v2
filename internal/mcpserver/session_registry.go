package mcpserver

// MCP 会话注册表：有状态会话的网关侧登记（mcp_sessions 行）、每请求活性刷
// 新、管理端强制断开与通知实时推送。
//
// 形态：mcp-go Streamable HTTP 挂自定义 SessionIdManager（生成形如
// mcp-session-<hex> 的会话 ID 并在 initialize 响应头回传；Validate 只拒绝已
// 被强制断开的 ID，未知 ID 放行——与 mcp-go StatelessGenerating 同语义，跨
// 进程重启的旧 ID 不至于锁死客户端，真正的存续判定在 MCP 层注册表）。会话
// 属主（user/key/IP/UA）由网关在认证链解析后经 context 注入，本包在
// initialize 响应捕获会话 ID 时落 mcp_sessions 行；每请求（携带会话头的）刷
// last_seen，投递 Daemon 的 30 分钟清理（notify.cleanupExpiredMCPSessions）
// 负责超时回收。强制断开 = 会话管理器标记终止（后续请求 404）+ MCP 层注销
// （推送不再命中）+ 删行，三处同一入口 DisconnectSession。
//
// 边界：网关仅挂载了 POST /mcp（历史部署面未变），服务器→客户端通知在该会
// 话的下一 POST 响应以 SSE 升级形态冲刷（mcp-go 内建行为），无独立 GET 监听
// 流；实时推送因此不承诺网络层即时到达，承诺「会话下一次交互即达」。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// mcpSessionIDHeader 与 mcp-go HeaderKeySessionID 同值（避免为常量引整个
// server 包公开面的读法漂移，字面量由钉测对齐）。
const mcpSessionIDHeader = "Mcp-Session-Id"

// sessionOwnerContext 是网关 apiKeyAuth 已解析的会话属主属性（initialize 落
// 行时取用；缺失时行仍落，属主列记 0——mcpserver 单测/独立挂载形态）。
type sessionOwnerContext struct {
	userID    int64
	keyID     int64
	ip        string
	userAgent string
}

type sessionOwnerKey struct{}

// WithSessionOwner 附加网关已解析的会话属主属性（仅 apiKeyAuth 认证成功的
// 请求注入；JWT/未认证请求不携带）。
func WithSessionOwner(ctx context.Context, userID, keyID int64, ip, userAgent string) context.Context {
	return context.WithValue(ctx, sessionOwnerKey{}, sessionOwnerContext{userID: userID, keyID: keyID, ip: ip, userAgent: userAgent})
}

// sessionOwnerFromContext 取回属主属性；ok=false 表示未注入。
func sessionOwnerFromContext(ctx context.Context) (sessionOwnerContext, bool) {
	value, ok := ctx.Value(sessionOwnerKey{}).(sessionOwnerContext)
	return value, ok
}

// terminatedSessionRetention 是终止标记的保留上限（个）。标记只增不删时内存
// 按进程生命周期内的累计终止登记数增长；超过上限即 FIFO 淘汰最旧的标记。
const terminatedSessionRetention = 65536

// terminatingSessionManager 是有状态会话管理器：生成会话 ID；Validate 仅拒绝
// 被强制断开的 ID。空 ID 放行——无会话头的单发请求（历史无状态客户端与
// mcpserver 单测直发 tools/call）按原路径继续可用；未知但格式合法的 ID 同样
// 放行（mcp-go StatelessGenerating 语义），不存在的会话在 MCP 层本就无注册。
//
// 终止标记有界：只保留最近 terminatedSessionRetention 个，满员后 FIFO 淘汰最
// 旧。取舍——被淘汰的旧 ID 不再被终止标记拒绝：持它的请求此后回到「未知
// ID 放行」路径，与从未被断开过的任意 ID 同待遇。登记来源不止强制断开：
// mcp-go 的空闲清扫与关停同样调用 Terminate，普通会话流失也会推进环——
// 淘汰发生在同进程内其后累计 terminatedSessionRetention 次终止登记之后。
// MCP 层注销与删会话行在断开当场完成，不受淘汰影响；会话 ID 不是凭据
// （每个请求仍过 API Key 认证），被淘汰的 ID 拿不到任何新权限。
type terminatingSessionManager struct {
	mu         sync.Mutex
	terminated map[string]struct{} // 保留中的终止标记

	// fifo 是终止标记的插入序环形缓冲：第 i 次插入落在 i % len(fifo)，满员
	// 后该位正是最旧的标记（淘汰即覆盖）。首次 Terminate 时才分配——从未
	// 登记过终止的部署不占这块内存。next 是累计插入次数（下一个写入序号）。
	fifo []string
	next uint64
}

func newTerminatingSessionManager() *terminatingSessionManager {
	return &terminatingSessionManager{terminated: make(map[string]struct{})}
}

func (m *terminatingSessionManager) Generate() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// 随机源失败：会话 ID 退化为时间戳串（唯一性弱化但仍非空——空 ID 会
		// 让 mcp-go 不回传会话头，推送链路整体失效）。crypto/rand 失败实践中
		// 仅见于系统级故障。
		return "mcp-session-fallback-" + hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))
	}
	return "mcp-session-" + hex.EncodeToString(buf)
}

func (m *terminatingSessionManager) Validate(sessionID string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, terminated := m.terminated[sessionID]
	return terminated, nil
}

// Terminate 登记终止标记。重复终止幂等：已登记的 ID 不占新额度、不改插入序
// （否则环形缓冲会持有同一 ID 的两个位，淘汰旧位时误删仍是近期的标记）。
func (m *terminatingSessionManager) Terminate(sessionID string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.terminated[sessionID]; ok {
		return false, nil
	}
	if m.fifo == nil {
		m.fifo = make([]string, terminatedSessionRetention)
	}
	slot := m.next % terminatedSessionRetention
	if len(m.terminated) == terminatedSessionRetention {
		delete(m.terminated, m.fifo[slot])
	}
	m.terminated[sessionID] = struct{}{}
	m.fifo[slot] = sessionID
	m.next++
	return false, nil
}

// terminatedCount 返回保留中的终止标记数（恒不超过 terminatedSessionRetention）。
func (m *terminatingSessionManager) terminatedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.terminated)
}

// activeSessionManager 进程内唯一会话管理器（SetupRouter 装配单例；测试多次
// 装配共享同一实例——终止标记仅随显式断开增长且有界，无跨测试误伤面）。
var activeSessionManager = newTerminatingSessionManager()

// pushTargetServer 进程内唯一 MCP 装配（推送目标；最后一次装配覆盖，与
// SetNonAdminForbiddenRoutes 同口径）。
var pushTargetServer atomic.Pointer[server.MCPServer]

// serveWithSessionRegistry 包住传输层 handler：进站刷 last_seen（携带会话头
// 的请求），出站捕获 initialize 响应头落会话行。响应头在 handler 返回后仍可
// 读（WriteHeader 前已定值），捕获不需要包 ResponseWriter。
func serveWithSessionRegistry(writer http.ResponseWriter, request *http.Request, next http.Handler) {
	if sessionID := request.Header.Get(mcpSessionIDHeader); sessionID != "" {
		touchMCPSessionLastSeen(sessionID)
	}
	next.ServeHTTP(writer, request)
	if sessionID := writer.Header().Get(mcpSessionIDHeader); sessionID != "" {
		registerMCPSession(sessionID, request)
	}
}

// nowStamp 会话时间列统一 UTC「YYYY-MM-DD HH:MM:SS」——与 SQLite
// datetime('now') 同形，字符串比较才能和 notify.cleanupExpiredMCPSessions 的
// 30 分钟清理及在线判定对齐。
func nowStamp() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

// registerMCPSession 落会话行（INSERT OR REPLACE：会话 ID 进程内唯一，重装
// 配/重启后的同 ID 理论不复现，幂等兜底）。
func registerMCPSession(sessionID string, request *http.Request) {
	if db.DB == nil {
		return
	}
	owner, _ := sessionOwnerFromContext(request.Context())
	stamp := nowStamp()
	_, _ = db.DB.Exec(`INSERT OR REPLACE INTO mcp_sessions
		(session_id, user_id, api_key_id, ip, user_agent, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?)`,
		sessionID, owner.userID, owner.keyID, owner.ip, owner.userAgent, stamp, stamp)
}

// touchMCPSessionLastSeen 每请求刷活性（行不存在时无操作）。
func touchMCPSessionLastSeen(sessionID string) {
	if db.DB == nil {
		return
	}
	_, _ = db.DB.Exec(`UPDATE mcp_sessions SET last_seen=? WHERE session_id=?`, nowStamp(), sessionID)
}

// DisconnectSession 强制断开：会话管理器标记终止（后续请求 404 Session
// terminated）→ MCP 层注销（推送不再命中该会话）→ 删会话行。deleted=false
// 且 err=nil 表示会话行本就不存在（幂等清理）；err 非 nil 仅会话行删除失败
// （管理器与 MCP 层注销已生效）。
func DisconnectSession(sessionID string) (deleted bool, err error) {
	if sessionID == "" {
		return false, nil
	}
	_, _ = activeSessionManager.Terminate(sessionID)
	if srv := pushTargetServer.Load(); srv != nil {
		srv.UnregisterSession(context.Background(), sessionID)
	}
	if db.DB == nil {
		return false, nil
	}
	result, err := db.DB.Exec(`DELETE FROM mcp_sessions WHERE session_id=?`, sessionID)
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// MCPSwitchEnabled 全局开关（notify_settings KV 表键 notify.mcp_enabled，值
// 恒 '1'/'0' 文本）。表/行缺失或读失败按启用——开关是便利层，故障锁死既有
// Agent 接入不可取；命中行时仅 '1' 启用（'0'/异常字符串一律停用，与写侧只
// 落 '1'/'0' 对称，避免意外值 fail-open）。
func MCPSwitchEnabled() bool {
	if db.DB == nil {
		return true
	}
	var value string
	if err := db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key='notify.mcp_enabled'`).Scan(&value); err != nil {
		return true
	}
	return value == "1"
}

// registerNotifyPush 注册实时推送实现：按用户在线会话（30 分钟内有活动）逐
// 会话投递 notifications/message。级别按 MCP LoggingLevel 映射（critical→
// critical，warn→warning，其余 info）；会话未注册（仅 REST 直发、无
// initialize 握手）时 Send 返回 ErrSessionNotFound，按不可达跳过。全局开关停
// 用时不推。
func registerNotifyPush(mcpServer *server.MCPServer) {
	pushTargetServer.Store(mcpServer)
	notify.RegisterPushHook(func(userID int64, msg notify.Message) {
		pushToUserSessions(mcpServer, userID, msg)
	})
}

// pushToUserSessions 单用户推送（hook 协程内执行；逐会话 best-effort）。
func pushToUserSessions(mcpServer *server.MCPServer, userID int64, msg notify.Message) {
	if db.DB == nil || mcpServer == nil || !MCPSwitchEnabled() {
		return
	}
	rows, err := db.DB.Query(`SELECT session_id FROM mcp_sessions
		WHERE user_id=? AND last_seen >= datetime('now', '-30 minutes')`, userID)
	if err != nil {
		return
	}
	defer rows.Close()
	var sessionIDs []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err == nil {
			sessionIDs = append(sessionIDs, sessionID)
		}
	}
	if len(sessionIDs) == 0 {
		return
	}
	data := msg.Title
	if msg.Body != "" {
		data = msg.Title + "\n" + msg.Body
	}
	params := map[string]any{"level": mcpLogLevel(msg.Level), "data": data}
	for _, sessionID := range sessionIDs {
		_ = mcpServer.SendNotificationToSpecificClient(sessionID, "notifications/message", params)
	}
}

// mcpLogLevel 通知级别 → MCP LoggingLevel。
func mcpLogLevel(level string) string {
	switch level {
	case "warn":
		return "warning"
	case "critical":
		return "critical"
	default:
		return "info"
	}
}

// recordToolStat 工具调用统计（mcp_tool_stats 按日×工具×Key upsert）：
// errors 只计 IsError 结果与转发失败，不计传输外恒错形态以外的成功调用。
// 属主 Key 缺失（单测/独立挂载无网关注入）记 key_id=0。日期取本机时区——
// 统计口径与面板「今日」一致（会话表时间列的 UTC 口径只服务 30 分钟
// 在线判定，两者互不引用）。失败静默：统计是旁路观测面，不得反压工具调用。
func recordToolStat(ctx context.Context, tool string, failed bool) {
	if db.DB == nil {
		return
	}
	keyID := int64(0)
	if owner, ok := sessionOwnerFromContext(ctx); ok {
		keyID = owner.keyID
	}
	date := time.Now().Format("2006-01-02")
	errs := 0
	if failed {
		errs = 1
	}
	_, _ = db.DB.Exec(`INSERT INTO mcp_tool_stats(date, tool, key_id, calls, errors)
		VALUES (?,?,?,1,?)
		ON CONFLICT(date, tool, key_id)
		DO UPDATE SET calls=calls+1, errors=errors+excluded.errors`,
		date, tool, keyID, errs)
}
