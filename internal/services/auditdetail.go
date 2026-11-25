package services

import (
	"encoding/json"
	"fmt"
	"strings"

	"lazy-balancer-v2/internal/i18n"
)

// auditResultTextMap 是审计结果码 → 中文渲染的唯一事实源
// 由 switch 改为 map，供 audit_result_text_test.go 以 AST/字面量互检钉住
// 「AuditResultPart 字面量实参集合 ⊆ 映射键集」——新增结果码漏映射即测试红）。
// 未收录码在 AuditResultText 中原样返回（保留英文兜底），但落库前应补映射。
var auditResultTextMap = map[string]string{
	"tx_rolled_back":      "单事务已回滚，零写入",
	"success":             "成功",
	"failed":              "失败",
	"failure":             "失败",
	"partial":             "部分成功",
	"max_attempts":        "达到最大重试次数",
	"missing_material":    "证书数据缺失",
	"queued":              "已重新排队",
	"deployment_retry":    "等待恢复部署",
	"requested":           "已触发",
	"skipped":             "已跳过",
	"invalid_request":     "请求格式错误",
	"invalid_ticket":      "登录票据无效或已过期",
	"invalid_signature":   "登录票据签名错误",
	"expired":             "登录票据已过期",
	"replay":              "登录票据已使用",
	"user_unavailable":    "登录票据用户不存在或已禁用",
	"database_error":      "数据库错误",
	"invalid_credentials": "用户名或密码错误",
	"credentials_invalid": "凭证无效",
	"internal_error":      "系统内部错误",
	"enabled":             "已启用",
	"disabled":            "已禁用",
	"approved":            "已通过",
	"rejected":            "已拒绝",
	"created":             "已创建",
	"reregistered":        "已重新注册",
	"not_found":           "对象不存在",
	// 集群角色端点装配缺失出口（cluster_mode.go 503）：explicit 路由中间件
	// 不代记 5xx，handler 留痕时以本码归因「服务未初始化」类拒绝。
	"service_unavailable":  "服务不可用",
	"missing_domain":       "缺少测试域名",
	"unknown_provider":     "未知提供商",
	"provider_error":       "提供商错误",
	"missing_acme_email":   "缺少 ACME 邮箱",
	"invalid_config":       "配置无效",
	"register_failed":      "注册失败",
	"storage_corrupted":    "存储数据损坏",
	"applied_or_no_change": "同步完成或无变更",
	"sync_failed":          "同步失败",
	"io_error":             "文件写入失败",
	"query_failed":         "查询失败",
	"scan_failed":          "行读取失败",
	"iterate_failed":       "迭代读取失败",
	"warning":              "警告",
	// 部署失败的状态回写本身失败（瞬时 DB 故障/CAS 冲突）：任务转入簿记
	// 补写 + 重试登记，审计必须能读懂这个结果码。
	"status_writeback_failed": "状态回写失败",
	// 证书任务「重试被阻止」终态（certificates.go 经局部
	// auditFailure 闭包以动态实参传入，字面量扫描钉测覆盖不到——本码曾因此
	// 渲染成英文 blocked）。
	"blocked": "重试被阻止",
	// 证书签发命中「规则当前态已变更」冲突（同一 auditFailure 闭包动态实参，
	// 曾因映射表与钉测清单双缺而渲染成英文 conflict）。
	"conflict":           "状态冲突",
	"deleted_unverified": "已删除（结果未确认）",
	// 证书任务重试/删除失败出口（AuditPolicyExplicit 路由无中间件自动审计，
	// 失败/被拒尝试按固定归因补记）。
	"import_in_progress": "配置导入进行中",
	"invalid_id":         "任务标识无效",
	"job_not_found":      "任务不存在",
	"cooldown":           "冷却中",
	"permanent":          "永久不可重试",
	// 手动重签越过失败冷却的提示码（certjobs.go 成功通道提示行）
	// 起以字面量进入 AuditResultPart，TestAuditResultText_literalArgsCovered
	// 钉住映射——此前经 auditFailureWithRule 动态实参逃过扫描，落英文码）。
	"cooldown_override":       "越过失败冷却",
	"ca_cooldown":             "CA 冷却中",
	"deployment_retry_failed": "部署重试失败",
	"queue_unavailable":       "队列不可用",
	"enqueue_failed":          "入队失败",
	"status_read_failed":      "读取状态失败",
	"state_changed":           "状态已变更",
	"in_flight":               "任务在执行中",
	"not_retryable":           "暂不可重试",
	"rule_state_read_failed":  "读取规则状态失败",
	"guarded_active_rule":     "规则仍启用",
	"disable_failed":          "禁用任务失败",
	"disable_verify_failed":   "禁用结果校验失败",
	"delete_failed":           "删除任务失败",
}

// auditDynamicResultCodes 是「动态实参」进入 AuditResultPart 的结果码取值域
// （字面量扫描钉测 audit_result_text_test.go 的 literalArgsCovered 天然覆盖
// 不到变量/闭包/函数返回值实参）。本清单是这些码的唯一事实源：
//   - 新增动态结果码必须在此登记，并在 auditResultTextMap 补中文映射，
//     否则审计详情渲染成英文内部标识（blocked、conflict 两次前车之鉴）；
//   - handlers 侧 auditFailure 闭包的字面量实参另由 AST 扫描兜底
//     （TestAuditResultText_auditFailureLiteralsRegistered），新增码未登记即红；
//   - 「result := "..." 后把变量传给 auditFailure/AuditResultPart」的赋值链路
//     由 TestAuditResultText_dynamicAssignmentsRegistered 收集（字面量扫描与
//     auditFailure 扫描的双盲区，query_failed 曾因此漏登记），未登记即红；
//   - 守护测试直接遍历本清单，不再在测试里手写第二份清单（手写清单曾漏
//     conflict，映射表与测试同步漂移）。
var auditDynamicResultCodes = []string{
	// handlers/certificates.go IssueCertificate 的 auditFailure 闭包
	"blocked", "conflict", "failed", "invalid_request", "skipped",
	// handlers/caproviders.go 测试 CA 提供商的结果码
	"provider_error", "not_found", "missing_acme_email", "invalid_config", "register_failed",
	// handlers/users.go 修改用户状态
	"enabled", "disabled",
	// handlers/cluster_ticket.go 登录票据失败归因
	"database_error", "invalid_ticket", "invalid_signature", "expired", "replay", "user_unavailable",
	// handlers/certjobs.go 证书任务重试/删除失败出口（retryCertJobByID 的
	// auditFailure/auditFailureWithRule 与 DeleteCertJob 的 auditFailure 均以
	// 动态实参进入 AuditResultPart）。query_failed 是 DeleteCertJob 查询失败
	// 分支的变量赋值取值（result := "query_failed"）——字面量扫描与
	// auditFailure 字面量扫描都看不见，由动态赋值链路用例兜底。
	"job_not_found", "cooldown", "permanent", "ca_cooldown", "deployment_retry_failed",
	"queue_unavailable", "enqueue_failed", "status_read_failed", "state_changed",
	"in_flight", "not_retryable", "rule_state_read_failed", "guarded_active_rule",
	"disable_failed", "disable_verify_failed", "delete_failed", "query_failed",
	// handlers/cluster_status.go ReportClusterNode 的 recordDetached 闭包
	// （脱离请求的失败/拒绝/成功三态；主节点门拒绝先解码再判，故结果码
	// 由分支计算后以动态实参进入 AuditResultPart）
	"success",
}

func AuditResultText(result string) string {
	if text, ok := auditResultTextMap[result]; ok {
		return text
	}
	return result
}

// 审计明细的键化模型（方案 C 第 2/3 步，2026-11-25 用户批准）。
//
// 明细 = 有序的若干「段」，每段是「已登记词条键 + 若干槽位参数」。落库形态：
//   - audit_log.detail_key    = 段键以 AuditDetailKeySeparator 连接（空=无明细）；
//   - audit_log.detail_params = JSON 二维字符串数组，与段一一对应（每段的槽位值）；
//   - audit_log.detail        = 中文母本文本（历史行只读展示 + 检索兜底）。
//
// 英文由前端词条按段键渲染（web/src/i18n/apiMessages.ts，与 message_key 同机制），
// 后端不按请求语言翻译。段键一律来自 internal/i18n 目录（audit.*），登记见
// catalog_audit_detail.go；新增段键必须登记 zh（英文译文归前端
// web/src/locales/apiMessages.en.json），漏登记会被
// audit_detail_keys_test.go 判红。
const AuditDetailKeySeparator = "|"

// AuditPart 是明细中的一段：词条键 + 槽位参数（保留原值，供中文母本按模板渲染；
// 落库时逐槽位格式化为字符串）。
type AuditPart struct {
	key  string
	args []any
}

// Key 返回段键（i18n 词条键）。
func (part AuditPart) Key() string { return part.key }

// Text 返回该段的中文母本文本。未登记的词条键原样返回（fail-visible，便于定位
// 漏登记，而不是静默丢段）。槽位里嵌套的段按其自身母本渲染。
func (part AuditPart) Text() string {
	text, _ := i18n.Text(part.key, renderAuditArgs(part.args)...)
	return text
}

// Params 返回该段的槽位参数（逐个格式化为字符串）。嵌套段编码为
// {"k":段键,"a":[槽位...]}、段列表编码为该对象的 JSON 数组，供前端递归渲染；
// 空段返回空切片而非 nil，保证 detail_params 的段数与段键数恒等（前端按下标
// 对齐）。
func (part AuditPart) Params() []string {
	params := make([]string, len(part.args))
	for index, arg := range part.args {
		switch nested := arg.(type) {
		case AuditPart:
			params[index] = nested.encode()
		case []AuditPart:
			encoded := make([]string, len(nested))
			for i, item := range nested {
				encoded[i] = item.encode()
			}
			params[index] = "[" + strings.Join(encoded, ",") + "]"
		default:
			params[index] = fmt.Sprint(arg)
		}
	}
	return params
}

// encode 把段编码成前端可识别的嵌套参数形态。
func (part AuditPart) encode() string {
	payload := struct {
		Key    string   `json:"k"`
		Params []string `json:"a"`
	}{Key: part.key, Params: part.Params()}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return part.Text()
	}
	return string(encoded)
}

// renderAuditArgs 把槽位里的嵌套段/段列表换成其中文母本，供 fmt 渲染（段列表
// 按明细同一分隔符连接）。
func renderAuditArgs(args []any) []any {
	rendered := make([]any, len(args))
	for index, arg := range args {
		switch nested := arg.(type) {
		case AuditPart:
			rendered[index] = nested.Text()
		case []AuditPart:
			texts := make([]string, 0, len(nested))
			for _, item := range nested {
				texts = append(texts, item.Text())
			}
			rendered[index] = joinChineseParts(texts)
		default:
			rendered[index] = arg
		}
	}
	return rendered
}

// AuditDetail 是审计明细的写侧值。字段不可导出：键、参数、母本文本三者必须由
// 构造函数一并产出，避免调用方只改其一造成键与文本分叉。
type AuditDetail struct {
	key    string
	params [][]string
	text   string
}

// Key 返回段键连接串（空表示无明细）。
func (detail AuditDetail) Key() string { return detail.key }

// Params 返回每段的槽位参数。
func (detail AuditDetail) Params() [][]string { return detail.params }

// Text 返回中文母本文本（落 detail 列）。
func (detail AuditDetail) Text() string { return detail.text }

// Identity 返回明细的键化身份（段键 + JSON 参数）：用于按「同一条明细」做
// 去重/节流，与落库的 detail_key + detail_params 同源。无键明细回落母本文本
// （历史形态的节流判据）。
func (detail AuditDetail) Identity() string {
	if detail.key == "" {
		return detail.text
	}
	encoded, err := json.Marshal(detail.params)
	if err != nil {
		return detail.key + "|" + detail.text
	}
	return detail.key + "|" + string(encoded)
}

// IsZero 报告明细是否为空（无段且无文本）。
func (detail AuditDetail) IsZero() bool { return detail.key == "" && detail.text == "" }

// FormatAuditDetail 把若干段拼成一条明细：段键连接、参数逐段归集、母本文本按
// 中文分号连接。渲染为空的段（如空错误文本）整体丢弃——与历史「空片段不占位」
// 口径一致。
func FormatAuditDetail(parts ...AuditPart) AuditDetail {
	keys := make([]string, 0, len(parts))
	params := make([][]string, 0, len(parts))
	texts := make([]string, 0, len(parts))
	for _, part := range parts {
		text := part.Text()
		if text == "" {
			continue
		}
		keys = append(keys, part.Key())
		params = append(params, part.Params())
		texts = append(texts, text)
	}
	if len(keys) == 0 {
		return AuditDetail{}
	}
	return AuditDetail{key: strings.Join(keys, AuditDetailKeySeparator), params: params, text: joinChineseParts(texts)}
}

// AppendAuditDetail 在既有明细后追加若干段（明细自身作为一段被保留）。
func AppendAuditDetail(detail AuditDetail, parts ...AuditPart) AuditDetail {
	extra := FormatAuditDetail(parts...)
	if extra.IsZero() {
		return detail
	}
	if detail.IsZero() {
		return extra
	}
	keys := detail.key
	if extra.key != "" {
		if keys != "" {
			keys += AuditDetailKeySeparator
		}
		keys += extra.key
	}
	params := make([][]string, 0, len(detail.params)+len(extra.params))
	params = append(params, detail.params...)
	params = append(params, extra.params...)
	texts := make([]string, 0, 2)
	if detail.text != "" {
		texts = append(texts, detail.text)
	}
	if extra.text != "" {
		texts = append(texts, extra.text)
	}
	return AuditDetail{key: keys, params: params, text: joinChineseParts(texts)}
}

// AuditRawPart 是一段不可翻译的原文（对端错误体、标识、名字等数据）。这类内容
// 不属于界面文案，英文界面按原样展示。
func AuditRawPart(text string) AuditPart {
	return AuditPart{key: "audit.rawPart", args: []any{text}}
}

// AuditTextPart 是一段已登记词条：键必须是字符串字面量（写点守卫
// audit_detail_keys_test.go 按 AST 扫字面量实参），槽位数与词条模板一致。
func AuditTextPart(key string, args ...any) AuditPart {
	return AuditPart{key: key, args: args}
}

// AuditRawDetail 只含一段原文的明细（无文案可翻译的写点用）。
func AuditRawDetail(text string) AuditDetail {
	return FormatAuditDetail(AuditRawPart(text))
}

// AuditTextDetail 只含一段词条的明细。
func AuditTextDetail(key string, args ...any) AuditDetail {
	return FormatAuditDetail(AuditTextPart(key, args...))
}

// auditCamelSuffix 把稳定码（下划线分隔）转成词条键尾部的驼峰形态：
// invalid_credentials → InvalidCredentials。
func auditCamelSuffix(code string) string {
	var b strings.Builder
	for _, piece := range strings.Split(code, "_") {
		if piece == "" {
			continue
		}
		b.WriteString(strings.ToUpper(piece[:1]))
		b.WriteString(piece[1:])
	}
	return b.String()
}

// auditResultCatalogueKey 是结果码的词条键（audit.result<CamelCode>）。
func auditResultCatalogueKey(code string) string {
	return "audit.result" + auditCamelSuffix(code)
}

// auditSourceCatalogueKey 是来源码的词条键（audit.source<CamelCode>）。
func auditSourceCatalogueKey(code string) string {
	return "audit.source" + auditCamelSuffix(code)
}

// AuditResultPart 是「结果：<结果码文本>」段。已收录的结果码各有独立词条（前端按
// 键直接渲染目标语言），未收录的码走 audit.resultUnmapped 并原样展示码——与改造
// 前的「未收录码原样输出」一致。
func AuditResultPart(result string) AuditPart {
	if _, ok := auditResultTextMap[result]; ok {
		return AuditPart{key: auditResultCatalogueKey(result)}
	}
	return AuditPart{key: "audit.resultUnmapped", args: []any{result}}
}

func joinChineseParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, part := range parts[1:] {
		result += "；" + part
	}
	return result
}

// AuditUserPart 用户标识段(2026-09-11 裁定):用户相关审计详情显示完整标识
// 「用户 12（zhang）」;用户名空回退「用户 12」(不可解析场景)。
func AuditUserPart(id int, username string) AuditPart {
	if username == "" {
		return AuditPart{key: "audit.userPart", args: []any{id}}
	}
	return AuditPart{key: "audit.userNamedPart", args: []any{id, username}}
}

func AuditJobPart(jobID int) AuditPart {
	return AuditPart{key: "audit.jobPart", args: []any{jobID}}
}

func AuditRulePart(ruleID string) AuditPart {
	return AuditPart{key: "audit.rulePart", args: []any{ruleID}}
}

// auditSourceTextMap 是审计来源码 → 中文渲染的唯一事实源（历史
// 由 switch 改为 map，供 audit_result_text_test.go 以 AST 字面量互检钉住「来源码
// 字面量集合 ⊆ 映射键集」）。此前 switch 形态没有任何覆盖钉，生产者传入的
// runtime_reconcile/runtime_sweep/promote_or_startup 三个来源长期落 default，
// 操作审计详情直接渲染英文内部标识。
// 未收录码在 AuditSourcePart 中原样返回（保留英文兜底，便于定位漏映射）。
var auditSourceTextMap = map[string]string{
	"certificate_issued":      "来源：证书签发",
	"startup_materialization": "来源：启动恢复",
	"ca_cooldown":             "来源：CA 冷却结束",
	"startup_recovery":        "来源：启动恢复",
	"renewal":                 "来源：自动续签",
	// "manual"：词汇表预留项——全仓当前无生产者（手动操作类来源码未落审计），
	// 保留键以便未来接入时不改渲染层。
	"manual":            "来源：手动操作",
	"rule_create":       "来源：创建规则",
	"rule_update":       "来源：更新规则",
	"rule_delete":       "来源：删除规则",
	"rule_enable":       "来源：启用规则",
	"rule_disable":      "来源：禁用规则",
	"ip2region_update":  "来源：IP 库更新",
	"crs_update":        "来源：CRS 规则库更新",
	"threat_update":     "来源：威胁情报库更新",
	"crawlerbot_update": "来源：爬虫地址库更新",
	"autoban":           "来源：自动封禁名单",
	// 运行时/升主补建来源：生产者一直在传，此前全落
	// default → 操作审计详情显示「来源：runtime_sweep」等英文内部标识。
	"runtime_reconcile":    "来源：运行时对账",
	"runtime_sweep":        "来源：运行时清扫",
	"promote_or_startup":   "来源：升主或启动补建",
	"first_issuance_retry": "来源：首次签发重试",
	// 部署生命周期行缺证书材料（ACME 下载完成后进程退出）：补扫重新排队签发。
	"deployment_material_lost": "来源：证书材料丢失",
	// 已签发行的材料 SAN 不覆盖当前域名（域改写/CA 返回错误集合）：对账重签。
	"san_mismatch": "来源：SAN 不覆盖",
	// 签发执行期发现任务域名与规则当前域名不匹配（并发兜底）：退役旧任务。
	"domain_mismatch": "来源：规则域名变更",
	// 配置导入/还原提交链：备份携带的 waiting_ca 存量在 finish 阶段保窗归一
	// 为 failed 的留痕行（handlers/config_backup.go 导入归一审计）。
	"config_import": "来源：配置导入",
}

// AuditSourcePart 是「来源：<来源码文本>」段；未收录的码走 audit.sourceUnmapped
// 并原样展示码（fail-visible，便于定位漏映射）。
func AuditSourcePart(source string) AuditPart {
	if _, ok := auditSourceTextMap[source]; ok {
		return AuditPart{key: auditSourceCatalogueKey(source)}
	}
	return AuditPart{key: "audit.sourceUnmapped", args: []any{source}}
}

// auditText 按词条渲染中文母本（供同时要写运行日志与审计两处的调用点复用，
// 避免日志与审计文案分叉）。未登记的键原样返回。
func auditText(key string, args ...any) string {
	text, _ := i18n.Text(key, args...)
	return text
}

// libUpdateAuditDetail 是数据类更新族（IP 库/CRS/威胁情报库/爬虫地址库）的结果
// 明细：状态码 → 词条段，触发方式与附加消息作为槽位。状态文案在词条里，不在
// 代码里拼（英文界面按状态渲染）。
//
// 状态码取值域是各族 Status 常量的字符串值（success/failed/skipped/cancelled
// 以及各族的中间态），未知码走 audit.libUpdateUnknown 并原样展示码。
func libUpdateAuditDetail(status, trigger, message string) AuditDetail {
	switch status {
	case "success":
		return AuditTextDetail("audit.libUpdateSuccess", trigger, message)
	case "failed":
		return AuditTextDetail("audit.libUpdateFailed", trigger, message)
	case "skipped":
		return AuditTextDetail("audit.libUpdateSkipped", trigger, message)
	case "cancelled":
		return AuditTextDetail("audit.libUpdateCancelled", trigger, message)
	case "idle":
		return AuditTextDetail("audit.libUpdateIdle", trigger, message)
	case "checking":
		return AuditTextDetail("audit.libUpdateChecking", trigger, message)
	case "downloading":
		return AuditTextDetail("audit.libUpdateDownloading", trigger, message)
	case "installing":
		return AuditTextDetail("audit.libUpdateInstalling", trigger, message)
	case "reloading":
		return AuditTextDetail("audit.libUpdateReloading", trigger, message)
	}
	return AuditTextDetail("audit.libUpdateUnknown", status, trigger, message)
}

// libUpdateNothingDueDetail 是「零到期源」空轮的明细（与常态成功轮区分）。
func libUpdateNothingDueDetail(trigger string) AuditDetail {
	return AuditTextDetail("audit.libUpdateNothingDue", trigger)
}

// recordSystemReloadAudit 数据类更新（IP 库/CRS）触发的真实 Caddy 重载统一
// 留痕（system 归因，裁定 2026-09-07；对齐 certissuer/集群同步口径）。
func recordSystemReloadAudit(source string, err error) {
	if err != nil {
		// 审计 detail 是全员可见面：传输失败错误含 admin 端点原文，剥离后再落盘
		// （服务端日志由调用方的 Logf 保留原文）。
		RecordAuditLog("system", "重载失败", "Caddy服务", FormatAuditDetail(AuditSourcePart(source), AuditRawPart(RedactCaddyAdminEndpoint(err.Error()))), "")
		return
	}
	RecordAuditLog("system", "重载", "Caddy服务", FormatAuditDetail(AuditSourcePart(source), AuditResultPart("success")), "")
}
