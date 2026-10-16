package services

type AuditPolicy int

const (
	AuditPolicySkip AuditPolicy = iota
	AuditPolicyGeneric
	AuditPolicyExplicit
)

var auditRoutePolicies = map[string]AuditPolicy{
	"POST /api/v1/auth/login":        AuditPolicyExplicit,
	"POST /api/v1/auth/ticket-login": AuditPolicyExplicit,
	// v2.1.8 MFA：公开 verify 与登录同语义（挑战令牌即凭据，handler 已细分记录
	// 认证拒绝/登录成功）；自助端点 handler 显式记录启用/禁用（用户认证对象）；
	// recovery-codes 重生成成功由 handler 显式记录「生成/恢复码」（S-8，2026-09-05
	// 审计裁定——纯会话门下旧码全作废+明文下发登录可用凭证，须留痕）；setup/
	// status/verify-step 为读或内部动作不产生审计（Generic 中间件映射为空 →
	// 不记录——R66 D-N3 后的收敛形态）；admin reset handler 记录「重置/用户认证」。
	"POST /api/v1/auth/mfa/verify":         AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/setup":          AuditPolicySkip,
	"GET /api/v1/auth/mfa/status":          AuditPolicySkip,
	"POST /api/v1/auth/mfa/activate":       AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/disable":        AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/recovery-codes": AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/verify-step":    AuditPolicySkip,
	"POST /api/v1/users/:id/mfa/reset":     AuditPolicyExplicit,
	"POST /api/v1/auth/logout":             AuditPolicyExplicit,
	"POST /api/v1/auth/setup":              AuditPolicyExplicit,
	// R72 CORE-F2：/mcp 条目运行时冗余——auditMiddleware 为根级中间件（先于
	// v1 组注册）会对 /mcp 分类，但缺省返回同为 AuditPolicySkip；保留本条目作
	// 「有意跳过」显式登记——契约测试 TestSetupRouter_writeRoutesHaveExplicit-
	// AuditClassification 要求每条写路由显式分类（intentionalSkip 断言
	// IsAuditedWriteRoute 命中本表），删除将落入「默认分类」漂移告警。MCP 写
	// 操作审计由内部转发重入的 REST 层各自显式记录承担。
	"POST /api/v1/mcp":                            AuditPolicySkip,
	"POST /api/v1/users":                          AuditPolicyExplicit,
	"PUT /api/v1/users/:id":                       AuditPolicyExplicit,
	"PUT /api/v1/users/:id/status":                AuditPolicyExplicit,
	"POST /api/v1/users/:id/reset-password":       AuditPolicyExplicit,
	"DELETE /api/v1/users/:id":                    AuditPolicyExplicit,
	"PATCH /api/v1/users/me":                      AuditPolicyExplicit,
	"POST /api/v1/users/me/api-keys":              AuditPolicyExplicit,
	"PATCH /api/v1/users/me/api-keys/:id":         AuditPolicyExplicit,
	"DELETE /api/v1/users/me/api-keys/:id":        AuditPolicyExplicit,
	"POST /api/v1/api-keys":                       AuditPolicyExplicit,
	"PATCH /api/v1/api-keys/:id/status":           AuditPolicyExplicit,
	"DELETE /api/v1/api-keys/:id":                 AuditPolicyExplicit,
	"PUT /api/v1/ca-providers/:id":                AuditPolicyExplicit,
	"POST /api/v1/ca-providers/:id/test":          AuditPolicyExplicit,
	"POST /api/v1/cluster/register":               AuditPolicyExplicit,
	"POST /api/v1/cluster/registration/confirm":   AuditPolicySkip,
	"POST /api/v1/cluster/register-tokens":        AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/approve":      AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/reject":       AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/login-ticket": AuditPolicyExplicit,
	"PUT /api/v1/cluster/nodes/:id/access-url":    AuditPolicyExplicit,
	// C-3：主节点侧单节点 pin 重置（handler 显式记录「清除节点证书指纹」审计）。
	"POST /api/v1/cluster/nodes/:id/forget-pin": AuditPolicyExplicit,
	// 服务控制（主节点侧 handler 显式记录节点名/动作/结果；从节点机器接口由
	// handler 全路径记录含失败的「服务控制」审计，中间件不复记）。
	"POST /api/v1/cluster/nodes/:id/service": AuditPolicyExplicit,
	"POST /api/v1/cluster/service-control":   AuditPolicySkip,
	"DELETE /api/v1/cluster/nodes/:id":       AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/report":      AuditPolicySkip,
	"POST /api/v1/cluster/mode":              AuditPolicyExplicit,
	"POST /api/v1/cluster/promote":           AuditPolicyExplicit,
	"POST /api/v1/cluster/sync/pull":         AuditPolicyExplicit,
	"POST /api/v1/cluster/forget-pins":       AuditPolicyExplicit,
	"PUT /api/v1/cluster/settings":           AuditPolicyExplicit,
	// OIDC 认证集成(v2.3.0):配置写操作显式审计(handler 内已留痕,分类为显式)
	"PUT /api/v1/settings/oidc":       AuditPolicyExplicit,
	"DELETE /api/v1/settings/oidc":    AuditPolicyExplicit,
	"POST /api/v1/settings/oidc/test": AuditPolicyExplicit,
	// 威胁大屏本站坐标自动检测（v4）：出站探测 handler 显式留痕（成功/失败）
	"POST /api/v1/security/overview/threat-screen/site-detect": AuditPolicyExplicit,
	// 自动备份（v2.3.x）：设置/手动备份/删除/还原 handler 均显式留痕
	//（还原由 importConfigBackupCore 以「还原」动作记审计）。
	"PUT /api/v1/settings/auto-backup":     AuditPolicyExplicit,
	"POST /api/v1/auto-backup/run":         AuditPolicyExplicit,
	"DELETE /api/v1/auto-backup/:id":       AuditPolicyExplicit,
	"POST /api/v1/auto-backup/:id/restore": AuditPolicyExplicit,
	"POST /api/v1/config/preview":          AuditPolicySkip,
	"POST /api/v1/config/import/validate":  AuditPolicySkip,
	"PUT /api/v1/config":                   AuditPolicyExplicit,
	"PUT /api/v1/admin-tls":                AuditPolicyExplicit,
	"POST /api/v1/admin-tls/inspect":       AuditPolicySkip,
	"POST /api/v1/system/restart":          AuditPolicyGeneric,
	// 任务监控（v2.3.4）：toggle/cancel/control 三操作 handler 均显式留痕。
	// 任务触发（U1-P3-1，第 67 轮）：升为 Explicit——Skip 前提「任务体 defer
	// 单记」随 v2.0 可触发族扩容失效（R63 时仅 3 自记族，现 12 族中 7 族任务体
	// 零审计：log-cleanup/audit-retention/security-events-retention/
	// cert-renewal-scan/cert-reconcile/cert-manual-poll/cert-waiting-ca）。
	// handler 按 TaskTriggerSelfRecordsAudit 分流：非自记族显式补记「触发」，
	// 自记族跳过（保 U1-P3-2 任务体单记裁定，operator 经 RunContext 归人）。
	"POST /api/v1/system/tasks/:id/trigger": AuditPolicyExplicit,
	"POST /api/v1/system/tasks/:id/toggle":  AuditPolicyExplicit,
	"POST /api/v1/system/tasks/:id/cancel":  AuditPolicyExplicit,
	"POST /api/v1/system/tasks/:id/control": AuditPolicyExplicit,
	"POST /api/v1/config/reload":            AuditPolicyGeneric,
	// R69 C-N3-c：validate 经 /load 真实加载候选配置（handler 成功后回弹权威
	// 配置）——不再豁免审计，handler 显式记录校验三态。
	"POST /api/v1/config/validate":                        AuditPolicyExplicit,
	"POST /api/v1/rules/cert-info":                        AuditPolicySkip,
	"POST /api/v1/rules":                                  AuditPolicyExplicit,
	"PUT /api/v1/rules/:caddy_id":                         AuditPolicyExplicit,
	"DELETE /api/v1/rules/:caddy_id":                      AuditPolicyExplicit,
	"POST /api/v1/rules/:caddy_id/enable":                 AuditPolicyExplicit,
	"POST /api/v1/rules/:caddy_id/disable":                AuditPolicyExplicit,
	"POST /api/v1/rules/:caddy_id/duplicate":              AuditPolicyExplicit,
	"POST /api/v1/rules/batch-block-pages":                AuditPolicyExplicit,
	"POST /api/v1/certificate-configs":                    AuditPolicyExplicit,
	"PUT /api/v1/certificate-configs/:id":                 AuditPolicyExplicit,
	"DELETE /api/v1/certificate-configs/:id":              AuditPolicyExplicit,
	"POST /api/v1/certificate-configs/test":               AuditPolicyExplicit,
	"POST /api/v1/certificate-configs/:id/test":           AuditPolicyExplicit,
	"PUT /api/v1/caddy/config":                            AuditPolicyExplicit,
	"POST /api/v1/config/import":                          AuditPolicyExplicit,
	"POST /api/v1/config/import/v1":                       AuditPolicyExplicit,
	"POST /api/v1/caddy/start":                            AuditPolicyGeneric,
	"POST /api/v1/caddy/stop":                             AuditPolicyGeneric,
	"POST /api/v1/caddy/restart":                          AuditPolicyGeneric,
	"POST /api/v1/certificates/issue":                     AuditPolicyExplicit,
	"POST /api/v1/certificates/parse":                     AuditPolicySkip,
	"POST /api/v1/certificates/jobs/current":              AuditPolicySkip,
	"POST /api/v1/certificates/jobs/:id/retry":            AuditPolicyExplicit,
	"DELETE /api/v1/certificates/jobs/:id":                AuditPolicyExplicit,
	"POST /api/v1/security/policies":                      AuditPolicyExplicit,
	"PUT /api/v1/security/policies/:id":                   AuditPolicyExplicit,
	"DELETE /api/v1/security/policies/:id":                AuditPolicyExplicit,
	"POST /api/v1/security/policies/:id/bind":             AuditPolicyExplicit,
	"POST /api/v1/security/policies/:id/bindings/bulk":    AuditPolicyExplicit,
	"DELETE /api/v1/security/policies/:id/bind/:caddy_id": AuditPolicyExplicit,
	"PUT /api/v1/security/rules/:caddy_id/policies":       AuditPolicyExplicit,
	"POST /api/v1/security/policies/batch-bind":           AuditPolicyExplicit,
	"POST /api/v1/security/policies/:id/split":            AuditPolicyExplicit,
	"PUT /api/v1/security/crs/auto-update":                AuditPolicyExplicit,
	"PUT /api/v1/security/crs/schedule":                   AuditPolicyExplicit,
	// 三库手动更新端点：审计由任务体 defer 单记（2026-09-29 用户裁定 + U1-P3-2
	// 收敛——handler 补记已撤，operator 经 RunContext 归人）——中间件不记。
	"POST /api/v1/security/crs/update":             AuditPolicySkip,
	"PUT /api/v1/security/ip2region/auto-update":   AuditPolicyExplicit,
	"PUT /api/v1/security/ip2region/schedule":      AuditPolicyExplicit,
	"POST /api/v1/security/ip2region/update":       AuditPolicySkip,
	"POST /api/v1/security/custom-rules":           AuditPolicyExplicit,
	"PUT /api/v1/security/custom-rules/:id":        AuditPolicyExplicit,
	"DELETE /api/v1/security/custom-rules/:id":     AuditPolicyExplicit,
	"POST /api/v1/security/block-pages":            AuditPolicyExplicit,
	"PUT /api/v1/security/block-pages/:id":         AuditPolicyExplicit,
	"DELETE /api/v1/security/block-pages/:id":      AuditPolicyExplicit,
	"POST /api/v1/security/ip-lists":               AuditPolicyExplicit,
	"PUT /api/v1/security/ip-lists/:id":            AuditPolicyExplicit,
	"DELETE /api/v1/security/ip-lists/:id":         AuditPolicyExplicit,
	"POST /api/v1/security/ip-lists/:id/ips":       AuditPolicyExplicit,
	"POST /api/v1/security/ip-lists/:id/remove-ip": AuditPolicyExplicit,
	// 自动封禁（F73-A）：配置写 handler 显式留痕（「更新」，含调度联动）。
	"PUT /api/v1/security/autoban": AuditPolicyExplicit,
	// 威胁情报库（v2.3.x）：handler 显式记录（开关/手动更新/导出）。
	"PUT /api/v1/security/threat-lib/auto-update": AuditPolicyExplicit,
	"PUT /api/v1/security/threat-lib/schedule":    AuditPolicyExplicit,
	"PUT /api/v1/security/threat-lib/:id/flags":   AuditPolicyExplicit,
	"POST /api/v1/security/threat-lib/update":     AuditPolicySkip,
	// 爬虫地址库（v2.3.8）：flags handler 显式记录；手动触发由任务体 defer 自记。
	"PUT /api/v1/security/crawler-lib/:id/flags":   AuditPolicyExplicit,
	"PUT /api/v1/security/crawler-lib/auto-update": AuditPolicyExplicit,
	"PUT /api/v1/security/crawler-lib/schedule":    AuditPolicyExplicit,
	"POST /api/v1/security/crawler-lib/update":     AuditPolicySkip,
}

var readOnlyWriteRoutes = map[string]struct{}{
	"POST /api/v1/ca-providers/:id/test": {},

	"POST /api/v1/certificate-configs/:id/test": {},
	"POST /api/v1/certificates/jobs/current":    {},
	"POST /api/v1/certificate-configs/test":     {},
	"POST /api/v1/certificates/parse":           {},
	"POST /api/v1/config/import/validate":       {},
	"POST /api/v1/config/preview":               {},
	// 2026-09-10 裁定(全项目审计·权限模型执行缺口,同日用户终裁):仅移除
	// admin-tls/inspect——上传/解析管理面 TLS 证书属管理面编辑流,非管理员禁用。
	// certificate-configs 两条测试与 ca-providers/:id/test 经用户裁定开放给
	// 非管理员(读探测语义,不落库);三守卫对 inspect 恢复完整写面校验。
	// 审计 I-2：POST /config/validate 已移出只读豁免——该端点实际执行真实
	// Caddy /load（?validate=true 参数被 Caddy v2.11.4 静默忽略，校验成功即
	// 调用方配置成为运行配置），只读 API key/从节点/MFA 豁免均可触发真实
	// 配置加载；移除后三守卫（apiKeyReadOnlyGuard/mfaStepUpGuard/readOnlyGuard）
	// 同步恢复完整写权限校验。
	// R68 B-F3：移除 "POST /api/v1/mcp"——/mcp 挂载早于本组 Use(apiKeyReadOnlyGuard)
	// 等中间件（Gin 对 group 中间件链做注册期快照），该条目无任何运行时消费者；
	// MCP 写控制实际由内部转发重入跳完整重跑只读/从节点/管理员守卫承担。
	// R39-7(C3):OIDC 发现探测为读语义(完整 discovery+JWKS 可达性探测,失败
	// 仅记审计不落库配置)——与上面 certificate-configs/ca-providers 测试探针
	// 同口径(2026-09-10 裁定先例),只读 API Key 放行。
	"POST /api/v1/settings/oidc/test": {},
	"POST /api/v1/rules/cert-info":    {},
}

func ClassifyAuditRoute(method, path string) AuditPolicy {
	if policy, ok := auditRoutePolicies[method+" "+path]; ok {
		return policy
	}
	return AuditPolicySkip
}

// taskTriggerSelfAuditIDs 手动触发审计自记族（U1-P3-1，第 67 轮）：
//   - threat/crs/ip2region：manager run 的 defer 每轮单记（2026-09-29 用户裁定
//   - R62 U1-P3-2 收敛），operator 经 RunContext 归人；
//   - auto-backup：备份执行器（handlers/autobackup.go）按结果记「备份/备份失败」；
//   - startup:config-load：runConfigLoad 载入审计（启动与手动同体）。
//
// 其余 7 个可手动触发族（log-cleanup/audit-retention/security-events-retention/
// cert-renewal-scan/cert-reconcile/cert-manual-poll/cert-waiting-ca）任务体零
// RecordAuditLog，由 trigger handler 显式补记。新增可触发族时必须评估本集合
// （任务体自记 → 加入；否则 handler 自动补记）。
var taskTriggerSelfAuditIDs = map[string]struct{}{
	"threat":              {},
	"crs":                 {},
	"ip2region":           {},
	"crawlerbot-update":   {},
	"auto-backup":         {},
	"startup:config-load": {},
}

// TaskTriggerSelfRecordsAudit 报告任务族的任务体是否自记手动触发审计——
// trigger handler 据此分流：自记族不复记（单记裁定），非自记族补记「触发」。
func TaskTriggerSelfRecordsAudit(id string) bool {
	_, ok := taskTriggerSelfAuditIDs[id]
	return ok
}

func IsAuditedWriteRoute(method, path string) bool {
	_, exists := auditRoutePolicies[method+" "+path]
	return exists
}

func IsReadOnlyWriteRoute(method, path string) bool {
	_, exists := readOnlyWriteRoutes[method+" "+path]
	return exists
}

func HasExplicitAuditEvent(method, path string) bool {
	// F63-B5e2-4:从 auditRoutePolicies 派生(原 100+ 路径手抄 switch 与
	// 策略表双清单——漏改时中间件静默降级 Generic 复记语义)
	return auditRoutePolicies[method+" "+path] == AuditPolicyExplicit
}
