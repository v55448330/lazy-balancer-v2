package handlers

// 安全事件 IPC 服务端（B 形态主路径的面板侧）：Caddy 进程内的审计写插件把
// 原始 audit JSON 行经 Unix socket 投递给本服务端，由面板入库（Caddy 永不
// 直连数据库）。socket 路径/端点/命名契约与写侧逐字镜像——caddygeoip 为
// 独立 module 不可 import services，契约常量为双包逐字镜像而非「单一真源」
// （如实描述），双侧钉测锁定一致
// （SecurityEventsIPCSocketPath / SecurityEventsIPCIngestPath）。
//
// 语义要点：
//   - 204 只在 DB commit 完成之后返回（写侧据此判定该批无需 spool）；
//   - 依赖未就绪（数据库句柄缺失）或入库失败一律 5xx——写侧按可重试处理并把
//     整批落 fallback spool，由采集任务补采；
//   - 请求体过大 413 / 读失败 400 表示「该批不可入库」，写侧不 spool（避免毒批
//     无限重试）；
//   - socket 权限 0600、仅本机（Unix domain socket 天然不到网络）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	sqlite "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// SecurityEventsIPCServer 是 UDS 上的最小 HTTP 服务端（两个入库端点：
// WAF audit 批入库 + 人机事件摄入）。
type SecurityEventsIPCServer struct {
	server   *http.Server
	listener net.Listener
	path     string
}

// SecurityEventsEventsIngestHandler 处理一批换行分隔 audit JSON 的入库请求。
// 独立成方法便于测试直接驱动（不经过真 socket）。
func (s *SecurityEventsIPCServer) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, services.SecurityEventsIPCMaxBodyBytes())
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "security events batch too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read security events batch: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 入库过程与请求生命周期解耦：写侧连接超时/断开不得让一批事件在半途中止
	// （半批提交后写侧仍会把整批 spool，重试幂等但平白放大重复量）。批次本身
	// 有界（body 上限 8MiB），最坏占用有界。
	ctx := context.WithoutCancel(r.Context())
	ingested, ierr := services.IngestSecurityEventBatch(ctx, raw)
	if ierr != nil {
		code := http.StatusInternalServerError
		if errors.Is(ierr, services.ErrSecurityEventsIngestUnavailable) || securityEventsIngestErrorRetryable(ierr) {
			code = http.StatusServiceUnavailable
		}
		http.Error(w, "security events ingest failed: "+ierr.Error(), code)
		return
	}
	// 仅当整批消费完成（commit 完成）才回 204——写侧以 204 作为「无需 spool」
	// 的唯一判据。新增行数经响应头回传，便于写侧与排障核对（非契约字段）。
	w.Header().Set("X-Lb-Security-Events-Ingested", strconv.Itoa(ingested))
	w.WriteHeader(http.StatusNoContent)
}

// sqlite 扩展错误码的低 8 位为主码（>0xff 为扩展位）；仅用主码判定。
const (
	sqliteIngestCodeBusy   = 5  // SQLITE_BUSY（含 SQLITE_BUSY_SNAPSHOT 等扩展）
	sqliteIngestCodeLocked = 6  // SQLITE_LOCKED（含 SQLITE_LOCKED_SHAREDCACHE）
	sqliteIngestCodeIOErr  = 10 // SQLITE_IOERR（临时 IO 故障族）
	sqliteIngestCodeFull   = 13 // SQLITE_FULL（磁盘满——空间回收后可重试）
)

// securityEventsIngestErrorRetryable 判定入库错误是否属「可重试」类（SQLite
// busy/locked、临时 IO 故障）：可重试 → 503，写侧落 spool 稍后补采。
// 优先按驱动类型化错误码判定（glebarez/go-sqlite 的 *sqlite.Error 经
// errors.As 穿透 database/sql 与 fmt.Errorf 包装链，与 db.isCorruptionError
// 同模式）；字符串兜底只认真实锁/IO 措辞——裸 "busy"/"locked" 单词过宽，
// 规则文本/URI 回显含这两个词会把永久失败误判可重试（毒批无限 spool 重试）。
func securityEventsIngestErrorRetryable(err error) bool {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() & 0xff {
		case sqliteIngestCodeBusy, sqliteIngestCodeLocked, sqliteIngestCodeIOErr, sqliteIngestCodeFull:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"database is locked", "database is busy", "disk i/o error", "no space left"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// 人机事件直写字段上限（单源导出）：client_ip/rule_id/method 由 IPC 写侧
// 直接投递原始值、绕过 WAF 管线（管线路已按头/体/URI/rule_msg 截断），无上限
// 时一条人机行可携带任意长身份/方法串污染事件日志、按规则归因与自动封禁
// 身份键。上限取远大于合法值的宽松界，且**不追加截断标记**——IP/规则 id 追加
// 标记会破坏身份可比较性（与 uri/rule_msg 的可见标记口径不同）。
const (
	HumanEventClientIPCapBytes = 64
	HumanEventRuleIDCapBytes   = 128
	HumanEventMethodCapBytes   = 16
)

// ClipHumanEventField 人机事件字段裁剪单源（按 UTF-8 边界回退，不追加标记）；
// 返回裁剪后值与是否发生裁剪（调用方据此 warn 留痕，不静默改值）。
func ClipHumanEventField(value string, capBytes int) (string, bool) {
	if len(value) <= capBytes {
		return value, false
	}
	cut := capBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut], true
}

// humanEventAttribution 人机事件归属（rule/policy 快照）。挑战事件由
// lb_human 按规则发放；入库时回填实际负载规则与 CC 属主策略（stage2 优先，
// mixed 存量属主兜底——渲染层按内容特征选属主，不看 policy_type），触发详情
// 才不会把合法的 CC 挑战事件误标成“无策略归属”。
type humanEventAttribution struct {
	policyID   int
	ruleName   string
	policyName string
}

func lookupHumanEventAttribution(ruleID string) humanEventAttribution {
	if db.DB == nil || strings.TrimSpace(ruleID) == "" {
		return humanEventAttribution{}
	}
	var a humanEventAttribution
	err := db.DB.QueryRow(`SELECT COALESCE(r.name,''), CASE WHEN p.id IS NOT NULL THEN b.policy_id ELSE 0 END, CASE WHEN p.id IS NOT NULL THEN p.name ELSE '' END
		FROM lb_rules r
		LEFT JOIN security_policy_bindings b ON b.rule_caddy_id=r.caddy_id
		LEFT JOIN security_policies p ON p.id=b.policy_id AND p.policy_type IN ('stage2','mixed')
		WHERE r.caddy_id=?
		ORDER BY CASE WHEN p.policy_type='stage2' THEN 0 WHEN p.policy_type='mixed' THEN 1 ELSE 2 END, b.rank, b.policy_id
		LIMIT 1`, ruleID).Scan(&a.ruleName, &a.policyID, &a.policyName)
	if err != nil {
		return humanEventAttribution{}
	}
	return a
}

// handleIngestHuman 人机验证事件摄入（POST /security-events/ingest-human）：
// 紧凑 JSON 行（ts/rule_id/client_ip/method/uri/kind/reason），直写 security_events
// （event_type=human；challenge/fail 落库 action=challenged、rate_reject 落库
// action=blocked/rule=cc_rate_reject、pass 跳过不落库、未知 kind 跳过+warn 留痕）。
// anomaly_score 不写（恒 0）：人机通道无 coraza 评分段，也不走 WAF 管线的
// 固定语义补分（429 存量补 6 仅属 coraza 审计形态）——危险等级展示对 CC 事件
// 不承载语义，评分口径分叉的如实披露见 services/securityevents.go 补分注释。
// 独立于 coraza 审计 tailer——人机事件非 coraza 形态，不经攻击归因管线。
func (s *SecurityEventsIPCServer) handleIngestHuman(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	type humanEventRow struct {
		Ts       int64  `json:"ts"`
		RuleID   string `json:"rule_id"`
		ClientIP string `json:"client_ip"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
		UA       string `json:"ua"`     // 写侧已停止发射（人机不携带 UA 契约）；解析仅向后兼容旧版在途批，落库不消费
		Kind     string `json:"kind"`   // challenge | pass | fail | rate_reject（未知 kind 跳过不落库+warn）
		Reason   string `json:"reason"` // CC 触发原因（session_anomaly/rps_spike/4xx_ratio；非 CC 触发空）
	}
	var rows []humanEventRow
	if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
		// 超限 body 与 handleIngest 同口径：*http.MaxBytesError → 413（4xx=该批
		// 不可入库，写侧不 spool），其余解析错误才是 400。json.Decoder 原样回传
		// body 读取错误（encoding/json refill），errors.As 可命中。
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "human event batch too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad human event batch: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(rows) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if db.MetricsDB == nil {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	// 行级准入（单源）：pass（放行结果不落库）、未知 kind（带外脏数据/旧版本
	// 残余形态）与缺失 ts/client_ip 的行（无法定位时间/身份——落库会把 1970
	// 时间与空 IP 写进事件日志，污染按时间排序/按日统计与自动封禁身份）一律
	// 跳过并 warn 留痕。INSERT/通知/喂入三处消费同一准入集——旧实现只在落库
	// 循环跳过，通知循环仍会对被跳过的行发 CC 触发，指向不存在的事件。
	accepted := make([]humanEventRow, 0, len(rows))
	for _, row := range rows {
		if row.Kind == "pass" {
			continue
		}
		// 未知 kind 不得静默落 challenged 污染事件日志与自动封禁喂入——
		// 与 pass 同口径跳过，响亮 warn 留痕。
		if row.Kind != "challenge" && row.Kind != "fail" && row.Kind != "rate_reject" {
			services.Logf("warn", "安全事件 IPC 收到未知 kind，跳过不落库: kind=%q rule_id=%s ip=%s", row.Kind, row.RuleID, row.ClientIP)
			continue
		}
		if row.Ts <= 0 || strings.TrimSpace(row.ClientIP) == "" {
			services.Logf("warn", "安全事件 IPC 人机事件缺少 ts/client_ip，跳过不落库: kind=%q rule_id=%s ip=%q ts=%d", row.Kind, row.RuleID, row.ClientIP, row.Ts)
			continue
		}
		// 直写字段上限（单源见 HumanEvent*CapBytes）：身份/方法串无上限会污染
		// 事件日志与自动封禁身份键；裁剪留痕（不静默改值）。
		clipped := false
		if v, ok := ClipHumanEventField(row.ClientIP, HumanEventClientIPCapBytes); ok {
			row.ClientIP, clipped = v, true
		}
		if v, ok := ClipHumanEventField(row.RuleID, HumanEventRuleIDCapBytes); ok {
			row.RuleID, clipped = v, true
		}
		if v, ok := ClipHumanEventField(row.Method, HumanEventMethodCapBytes); ok {
			row.Method, clipped = v, true
		}
		if clipped {
			services.Logf("warn", "安全事件 IPC 人机事件字段超限已裁剪（client_ip≤%d/rule_id≤%d/method≤%d 字节）: kind=%q ip=%s rule_id=%s",
				HumanEventClientIPCapBytes, HumanEventRuleIDCapBytes, HumanEventMethodCapBytes, row.Kind, row.ClientIP, row.RuleID)
		}
		accepted = append(accepted, row)
	}
	if len(accepted) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	attributions := map[string]humanEventAttribution{}
	for _, row := range accepted {
		if _, ok := attributions[row.RuleID]; !ok {
			attributions[row.RuleID] = lookupHumanEventAttribution(row.RuleID)
		}
	}
	ctx := context.WithoutCancel(r.Context())
	tx, err := db.MetricsDB.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "human event tx: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	// 批最旧插入分钟（rollup 回退通知用）：只统计真实落库行（pass/未知 kind
	// 跳过），与 WAF 批 processPass 的 batchOldestMinute 同口径。
	// 结果语义（2026-11-13 用户裁定）：挑战成功（pass）是放行结果，不是安全
	// 事件——不落库（避免污染事件日志/统计）；发放/失败逐请求落库，action=
	// challenged，不计入拦截/检测/攻击面。通过率由 admin 计数承载。
	var oldestInsert time.Time
	for _, row := range accepted {
		action := "challenged"
		rule := "human_challenge"
		if row.Kind == "fail" {
			rule = "human_failed"
		}
		// CC reject（429 限流拒绝）=拦截事件：action=blocked、rule=cc_rate_reject
		//（与自动封禁 blocked 口径映射同源）；event_type 仍 human（人机通道）。
		if row.Kind == "rate_reject" {
			action = "blocked"
			rule = "cc_rate_reject"
		}
		attr := attributions[row.RuleID]
		ruleName := attr.ruleName
		if ruleName == "" {
			ruleName = "人机验证"
		}
		// event_time 与全管线同口径：定宽 UTC 秒字符串（WAF 写侧
		// securityEventsUnixTimestampUTC 同布局）。直接绑 time.Time 会被
		// glebarez/go-sqlite 驱动按默认布局落出毫秒+时区后缀形态
		// （2006-01-02 15:04:05.999999999-07:00），破坏读侧字符串窗口
		// 比较/同秒边界/保留期清理的契约。
		ts := time.UnixMilli(row.Ts).UTC().Format("2006-01-02 15:04:05")
		// rule_msg 携带 CC 触发原因（事件详情可读）；非 CC 触发保持原形态。
		ruleMsg := "人机验证 " + row.Kind
		if row.Kind == "rate_reject" {
			ruleMsg = "限流拒绝（429）"
		}
		if label := services.AutobanCCTriggerReasonLabel(row.Reason); label != "" {
			ruleMsg += "（" + label + "）"
		}
		// 字段上限与 WAF 管线路同源（直写绕过管线但单行体积契约不变）：
		// uri/rule_msg 超限按 UTF-8 边界截断并追加标记，避免一条人机行
		// 可达 ~1MiB、与保留摘要披露的「单行最大约 64KiB」失真。
		ruleMsg = services.SecurityEventsClipRuleMsgField(ruleMsg)
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name, policy_name)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			ts, row.RuleID, attr.policyID, row.ClientIP, row.Method, services.SecurityEventsClipURIField(row.URI), "human", rule, ruleMsg, action, ruleName, attr.policyName); err != nil {
			http.Error(w, "human event insert: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if at := time.UnixMilli(row.Ts).UTC(); oldestInsert.IsZero() || at.Before(oldestInsert) {
			oldestInsert = at
		}
	}
	if err := tx.Commit(); err != nil {
		db.RollbackLeakedTx(db.MetricsDB, db.MetricsPoolMaxOpen)
		http.Error(w, "human event commit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// 通知挂钩（提交成功后逐行评估；fire-and-forget，绝不影响响应）：
	//   - rate_reject=拦截事件 → 拦截聚合（首条立即告警+窗口聚合）；
	//   - 携带 CC 触发原因（reason 非空）=evalCC 触发后路径 → CC 触发事件
	//     （级联抑制/逐 IP 去抖在 notify 包内收敛，同 IP 10 分钟窗口去重）。
	for _, row := range accepted {
		attr := attributions[row.RuleID]
		if row.Kind == "rate_reject" {
			notify.RecordBlockedEvent(attr.ruleName)
		}
		// challenge/fail 落库 action=challenged → 计入已开启的拦截聚合窗口。
		if row.Kind == "challenge" || row.Kind == "fail" {
			notify.RecordChallengeEvent()
		}
		if label := services.AutobanCCTriggerReasonLabel(row.Reason); label != "" {
			notify.PublishCCTriggered(row.ClientIP, label)
		}
	}
	// 迟到插入回退通知（与 WAF 批同构）：积压超过修复窗的分钟若无此通知，
	// rollup 水位已过、增量重固扫不到，大屏/总览对该分钟永久少计。纯插入批
	// reclassify=nil（迟到行 id 单调更大，增量即可覆盖）；零落库批不通知。
	if !oldestInsert.IsZero() {
		services.NotifySecurityEventsRollupRewrite(oldestInsert.Truncate(time.Minute), nil)
	}
	// 挑战发放/失败计入自动封禁（按口径维度成员资格，2026-11-13 用户裁定）：
	// 提交成功后按批喂入（配置每批只读一次，与 WAF 批路径同构），窗口/阈值
	// 与 WAF 事件共用；主节点/启用/口径门在 services 内收敛。挑战通过永不计。
	feed := make([]services.HumanObserveItem, 0, len(accepted))
	for _, row := range accepted {
		feed = append(feed, services.HumanObserveItem{IP: row.ClientIP, Kind: row.Kind, Reason: row.Reason, At: time.UnixMilli(row.Ts).UTC()})
	}
	services.ObserveHumanEvents(feed)
	w.WriteHeader(http.StatusNoContent)
}

// StartSecurityEventsIPCServer 在契约 socket 上启动入库服务端：目录缺失时
// 创建（0700）、陈旧 socket 清理、socket 权限 0600。返回的 *Server 由调用方
// 在关停时 Stop（移除 socket 文件）。
func StartSecurityEventsIPCServer() (*SecurityEventsIPCServer, error) {
	path := services.SecurityEventsIPCSocketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建安全事件 IPC 目录失败: %w", err)
	}
	// 陈旧 socket 清理：只删 socket 类型，绝不删普通文件（路径被误配成数据
	// 文件时宁可启动失败）。
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("安全事件 IPC 路径已被非 socket 文件占用: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("清理陈旧安全事件 IPC socket 失败: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("检查安全事件 IPC socket 失败: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("监听安全事件 IPC socket 失败: %w", err)
	}
	// 仅本机同用户可写：0600（写侧与面板同用户/同容器）。
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("设置安全事件 IPC socket 权限失败: %w", err)
	}
	s := &SecurityEventsIPCServer{listener: ln, path: path}
	// Handler 引用 s 自身的方法：先建 s 再装 server（同一指针）。
	s.server = &http.Server{
		Handler:           http.HandlerFunc(s.ingestRouter),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if serr := s.server.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			services.Logf("error", "安全事件 IPC 服务异常退出（Caddy 将回退 spool 补采）: %v", serr)
		}
	}()
	services.Logf("info", "安全事件 IPC 服务已启动: %s %s", path, services.SecurityEventsIPCIngestPath)
	return s, nil
}

// ingestRouter 只接受契约端点（其余 404）：最小暴露面。
func (s *SecurityEventsIPCServer) ingestRouter(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case services.SecurityEventsIPCIngestPath:
		s.handleIngest(w, r)
	case services.SecurityEventsIPCIngestHumanPath:
		s.handleIngestHuman(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Stop 关闭服务端并移除 socket 文件（关停预算由调用方给）。
func (s *SecurityEventsIPCServer) Stop(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	if s.path != "" {
		_ = os.Remove(s.path)
	}
	return err
}
