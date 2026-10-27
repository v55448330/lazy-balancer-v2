package services

// 审计路由分类：AuditPolicyExplicit 由 handler 亲自记录、
// AuditPolicyGeneric 由 auditMiddleware 生成通用行、AuditPolicySkip 明确不留痕。
//
// 通用审计不覆盖 4xx（auditMiddleware 在 400≤status<500 时直接返回）：
//   - 401/403/428/429 由各守卫经 recordAuthenticationRejection 留痕
//     （含限流去重），不是留白；
//   - 400/409（参数错误、导入与集群写冲突）在 handler 未显式记录时**没有**
//     通用审计行——权威痕迹在访问日志与具体 handler 的显式事件里。
//
// 这是有意口径：4xx 是「请求未生效」，逐条入操作审计会淹没真实业务拒绝面；
// 若某个 409 代表真实业务拒绝且需要操作审计，应由该 handler 显式记录。
type AuditPolicy int

const (
	AuditPolicySkip AuditPolicy = iota
	AuditPolicyGeneric
	AuditPolicyExplicit
)

// 集群注册链终结点（从节点持久化集群令牌后清除一次性注册密钥）登记为
// AuditPolicyExplicit：与 register/approve 对称，handler 显式记录「确认/确认
// 失败」——事后可证明某节点何时消费了注册密钥。
var auditRoutePolicies = map[string]AuditPolicy{
	"POST /api/v1/auth/login":        AuditPolicyExplicit,
	"POST /api/v1/auth/ticket-login": AuditPolicyExplicit,
	// v2.1.8 MFA：公开 verify 与登录同语义（挑战令牌即凭据，handler 已细分记录
	// 认证拒绝/登录成功）；自助端点 handler 显式记录启用/禁用（用户认证对象）；
	// recovery-codes 重生成成功由 handler 显式记录「生成/恢复码」（2026-09-05
	// 审计裁定——纯会话门下旧码全作废+明文下发登录可用凭证，须留痕）；setup
	// 已升 Explicit（重绑时 handler 记录「重新绑定/用户认证」的 pending 密钥
	// 轮换，首绑不记——由 activate 记「启用」）；verify-step 为内部动作，显式
	// 登记 Skip 以固定契约；admin reset handler 记录「重置/用户认证」。读端点
	//（如 GET /auth/mfa/status）走默认 Skip，不登记——本表只承载写路由的显式
	// 分类。
	"POST /api/v1/auth/mfa/verify":         AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/setup":          AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/activate":       AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/disable":        AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/recovery-codes": AuditPolicyExplicit,
	"POST /api/v1/auth/mfa/verify-step":    AuditPolicySkip,
	"POST /api/v1/users/:id/mfa/reset":     AuditPolicyExplicit,
	"POST /api/v1/auth/logout":             AuditPolicyExplicit,
	"POST /api/v1/auth/setup":              AuditPolicyExplicit,
	// /mcp 条目运行时冗余——auditMiddleware 为根级中间件（先于
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
	"POST /api/v1/cluster/registration/confirm":   AuditPolicyExplicit,
	"POST /api/v1/cluster/register-tokens":        AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/approve":      AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/reject":       AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/login-ticket": AuditPolicyExplicit,
	"PUT /api/v1/cluster/nodes/:id/access-url":    AuditPolicyExplicit,
	"PUT /api/v1/cluster/nodes/:id/site":          AuditPolicyExplicit,
	// 主节点侧单节点 pin 重置（handler 显式记录「清除节点证书指纹」审计）。
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
	// 大屏流量采集租约：UI 生命周期内部动作（打开申请/关闭释放），
	// 高频且无安全语义，显式跳过审计。
	"POST /api/v1/security/overview/threat-screen/collector":   AuditPolicySkip,
	"DELETE /api/v1/security/overview/threat-screen/collector": AuditPolicySkip,
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
	// 任务触发：升为 Explicit——Skip 前提「任务体 defer
	// 单记」随 v2.0 可触发族扩容失效（时仅 3 自记族，现 12 族中 7 族任务体
	// 零审计：log-cleanup/audit-retention/security-events-retention/
	// cert-renewal-scan/cert-reconcile/cert-manual-poll/cert-waiting-ca）。
	// handler 按 TaskTriggerSelfRecordsAudit 分流：非自记族显式补记「触发」，
	// 自记族跳过（保 任务体单记裁定，operator 经 RunContext 归人）。
	"POST /api/v1/system/tasks/:id/trigger": AuditPolicyExplicit,
	"POST /api/v1/system/tasks/:id/toggle":  AuditPolicyExplicit,
	"POST /api/v1/system/tasks/:id/cancel":  AuditPolicyExplicit,
	"POST /api/v1/system/tasks/:id/control": AuditPolicyExplicit,
	"POST /api/v1/config/reload":            AuditPolicyGeneric,
	// c：validate 经 /load 真实加载候选配置（handler 成功后回弹权威
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
	// 三库手动更新端点：审计由任务体 defer 单记（2026-09-29 用户裁定 +
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
	// 自动封禁：配置写 handler 显式留痕（「更新」，含调度联动）。
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
	"POST /api/v1/certificates/jobs/current": {},
	"POST /api/v1/certificates/parse":        {},
	"POST /api/v1/config/import/validate":    {},
	"POST /api/v1/config/preview":            {},
	// 2026-09-10 裁定(全项目审计·权限模型执行缺口,同日用户终裁):仅移除
	// admin-tls/inspect——上传/解析管理面 TLS 证书属管理面编辑流,非管理员禁用。
	// certificate-configs 两条 test 路由已移出
	// 只读白名单——providers.Validate 会真实 Present+CleanUp DNS TXT 记录（非读
	// 探测语义），从节点/只读 API Key 不得触发；三守卫（apiKeyReadOnlyGuard/
	// mfaStepUpGuard/readOnlyGuard）对两条恢复完整写权限校验。
	// ca-providers/:id/test 同步移出——ZeroSSL 提供商
	// 缺 EAB 时 TestCAProviderWithContext 会调 AutoProvisionZeroSSLEAB 申请 EAB
	// 并 UPDATE ca_providers.credentials，原「仅探测
	// ACME 目录/账户可达性」的豁免前提不成立；三守卫同样恢复完整写权限校验。
	// POST /config/validate 已移出只读豁免——该端点实际执行真实
	// Caddy /load（?validate=true 参数被 Caddy v2.11.4 静默忽略，校验成功即
	// 调用方配置成为运行配置），只读 API key/从节点/MFA 豁免均可触发真实
	// 配置加载；移除后三守卫（apiKeyReadOnlyGuard/mfaStepUpGuard/readOnlyGuard）
	// 同步恢复完整写权限校验。
	// 移除 "POST /api/v1/mcp"——/mcp 挂载早于本组 Use(apiKeyReadOnlyGuard)
	// 等中间件（Gin 对 group 中间件链做注册期快照），该条目无任何运行时消费者；
	// MCP 写控制实际由内部转发重入跳完整重跑只读/从节点/管理员守卫承担。
	// OIDC 发现探测为读语义(完整 discovery+JWKS 可达性探测,失败
	// 仅记审计不落库配置),只读 API Key 放行。
	"POST /api/v1/settings/oidc/test": {},
	"POST /api/v1/rules/cert-info":    {},
	// 大屏流量/逐请求光流采集租约是**纯本机内存**
	// 开关（无 DB 写、无集群同步副作用），却被只读守卫按写方法拦截——只读
	// 用户/从节点的大屏流量卡片永远为空且前端静默吞 403。与 GET 同属读展示
	// 能力，三守卫（apiKeyReadOnlyGuard/mfaStepUpGuard/readOnlyGuard）放行。
	"POST /api/v1/security/overview/threat-screen/collector":   {},
	"DELETE /api/v1/security/overview/threat-screen/collector": {},
}

func ClassifyAuditRoute(method, path string) AuditPolicy {
	if policy, ok := auditRoutePolicies[method+" "+path]; ok {
		return policy
	}
	return AuditPolicySkip
}

// taskTriggerSelfAuditIDs 手动触发审计自记族
//   - threat/crs/ip2region：manager run 的 defer 每轮单记（2026-09-29 用户裁定
//     收敛），operator 经 RunContext 归人；
//   - crawlerbot-update：源更新入口 defer 自记（crawler_update.go）；
//   - auto-backup：备份执行器（handlers/autobackup.go）按结果记「备份/备份失败」；
//   - startup:config-load：runConfigLoad 载入审计（启动与手动同体）。
//
// 其余 10 个可手动触发族（config-watchdog/log-cleanup/audit-retention/
// security-events-retention/metrics-orphan-cleanup/cert-renewal-scan/
// cert-reconcile/cert-manual-poll/cert-waiting-ca/autoban）任务体零
// RecordAuditLog，由 trigger handler 显式补记。新增可触发族时必须评估本集合
// （任务体自记 → 加入；否则 handler 自动补记）；清单与
// audit_policy_test.go 的可手动触发族断言同源，两处必须同步。
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
	// 从 auditRoutePolicies 派生(原 100+ 路径手抄 switch 与
	// 策略表双清单——漏改时中间件静默降级 Generic 复记语义)
	return auditRoutePolicies[method+" "+path] == AuditPolicyExplicit
}
