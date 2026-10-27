package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// importValidationDeps 备份校验链的外部依赖。
//
// DB 供行级数值类型门与安全策略/ACME 引用的 live 回退读取（nil 时按旧脚手架
// 语义跳过/不回落 live）；ValidateRuleListenPort 叠加本进程实际面板监听口与
// Caddy admin 口，省略时退回包级默认管理口（与 validateV2BackupRules 同口径）。
type importValidationDeps struct {
	DB                     *sql.DB
	ValidateRuleListenPort func(protocol string, port int) error
}

// importValidationOptions 两条调用路径（导入提交/导入预览）的差异项。
//
// LbbakPayload 为 lbbak 包内文件条目（纯 JSON 为 nil）——决定威胁源保留本地、
// 版本表随文件缺失剔除、CRS 规则树是否同批替换；RequestedSections 为
// ?sections= 请求值（缺省时沿用备份体内 sections）。
type importValidationOptions struct {
	LbbakPayload      *lbbakPayload
	RequestedSections string
}

// importValidationResult 校验链产出事实与告警（校验/归一/软跳过的写回已落在
// 被校验的备份上）。链本身不产生审计副作用——审计动作由调用方按这些事实决定
// （预览只读不落审计，因此不可放进链内）。
type importValidationResult struct {
	UsedLegacyChecksum bool
	// NoIntegrityChecksum v1 史前备份完全不含完整性校验和（比旧格式校验和
	// 更弱）——导入照常但必须披露；预览侧转为 warning。
	NoIntegrityChecksum     bool
	SectionTables           map[string]bool
	IncludeGlobal           bool
	SkipWarnings            []string
	DisabledConflicts       []disabledRuleConflict
	CRSTreeReplaced         bool
	ACMEDanglingImported    int
	CertJobProviderWarnings []string
	AutobanClampNotes       []string
	// ConfigClampNotes 全局配置数值归一事实（越界/非法形态被钳制的键）——
	// 链内唯一归一点，预览与导入共用，双路径可见。
	ConfigClampNotes []string
	// CertJobDanglingWarnings 证书任务 CA 提供商悬挂/禁用的两档告警——链内
	// 单源产出，预览直接透传（导入在锁内以事务视图重算同一判据，文案共用）。
	CertJobDanglingWarnings []string
	WAFMetadataSkipped      bool
	WAFCRSMetadataSkipped   bool
	WAFXdbMetadataSkipped   bool
}

// importValidationChain 校验链的执行上下文：备份按指针就地改写（与两条生产
// 路径的既有语义一致），调用方差异项由 opts 表达。
type importValidationChain struct {
	ctx    context.Context
	deps   importValidationDeps
	backup *configBackup
	opts   importValidationOptions
	result importValidationResult
	// exportedTables 备份原始携带表集的快照——verifyBackupIntegrity 会回填
	// 缺失表（校验均匀性），「缺席=保留本地」语义依赖回填前的真实表集。
	exportedTables map[string]bool
	// backupCarriedCertTables 备份原本是否携带 cert 表——反向悬挂降级仅对
	// 「从未携带」开放；携带却被分类丢弃时维持硬拒绝。
	backupCarriedCertTables bool
}

// importValidationStep 校验链的一道门。门名进入组成清单
// （TestImportValidationChain_gateComposition_lockedToProduction），
// 新增门必须追加到 importValidationSteps，否则该用例变红。
type importValidationStep struct {
	name string
	run  func(*importValidationChain) error
}

// importValidationSteps 生产导入/预览共用的唯一权威门序。新增校验必须加在
// 对应位置并同步组成清单用例——任何调用方（含测试）都不得自行编排子集门。
var importValidationSteps = []importValidationStep{
	{"备份表集快照", (*importValidationChain).snapshotExportedTables},
	{"完整性校验", (*importValidationChain).verifyIntegrity},
	{"分类选择解析", (*importValidationChain).resolveSectionSelection},
	{"回填表缺席还原", (*importValidationChain).dropBackfilledTables},
	{"分类过滤", (*importValidationChain).filterSections},
	{"过滤后零导入判据", (*importValidationChain).assertFilteredScopeHasContent},
	{"软跳过准备", (*importValidationChain).prepareSkips},
	{"版本状态归一", (*importValidationChain).normalizeVersionUpdateStatuses},
	{"行级结构门", (*importValidationChain).validateRows},
	{"空用户表门", (*importValidationChain).rejectEmptyUsersTable},
	{"规则库元数据剔除", (*importValidationChain).skipMissingWAFMetadata},
	{"证书任务状态门", (*importValidationChain).validateCertJobStatuses},
	{"剔除后零导入判据", (*importValidationChain).assertSkippedScopeHasContent},
	{"拦截页内容类型归一", (*importValidationChain).normalizeBlockPageContentTypes},
	{"规则域名归一", (*importValidationChain).canonicalizeRuleDomains},
	{"冲突规则置禁用", (*importValidationChain).disableRuleConflicts},
	{"规则引用校验", (*importValidationChain).validateRuleReferences},
	{"规则形态校验", (*importValidationChain).validateRules},
	{"安全策略校验", (*importValidationChain).validateSecurityPolicies},
	{"TLS 形态校验", (*importValidationChain).validateTLSShape},
	{"证书任务不变量", (*importValidationChain).validateCertJobs},
	{"证书任务提供商悬挂", (*importValidationChain).validateCertJobProviderDangling},
	{"管理端 TLS 门", (*importValidationChain).validateAdminTLS},
	{"自动封禁配置门", (*importValidationChain).validateAutobanConfig},
	{"全局配置数值归一", (*importValidationChain).normalizeGlobalConfigNumbers},
	{"受信代理配置门", (*importValidationChain).validateTrustedProxyConfig},
	{"运行期设置门", (*importValidationChain).validateRuntimeSettings},
	{"自动备份设置门", (*importValidationChain).validateAutoBackupConfig},
}

// validateImportBackupChain 执行完整校验链并返回调用方继续编排所需的事实。
// 首个失败门原样返回其错误（文案与既有导入 400 / 预览 valid=false 共用），
// 同时返回失败前已确定的产出（例如旧格式校验和/版本表剔除事实），使调用方
// 的审计留痕与门序无关——历史导入在后续门失败时同样会记这些警告。
//
// 门序不变量（与生产导入行为一一对应，改动即行为变更）：
//   - 完整性校验先于 sections 过滤（v3 校验和覆盖体内 sections）；
//   - 行级结构门在分类过滤与软跳过之后（未选/已跳分类的坏行不误拒整包）；
//   - 规则库元数据剔除在行级门之后（其 auto_update 列已被行级门消费）；
//   - 冲突置禁用先于规则形态/TLS/任务不变量（将被禁用的规则不参与运行态校验）。
func validateImportBackupChain(ctx context.Context, deps importValidationDeps, backup *configBackup, opts importValidationOptions) (importValidationResult, error) {
	chain := &importValidationChain{ctx: ctx, deps: deps, backup: backup, opts: opts}
	for _, step := range importValidationSteps {
		if err := step.run(chain); err != nil {
			return chain.result, err
		}
	}
	return chain.result, nil
}

func (ch *importValidationChain) snapshotExportedTables() error {
	ch.exportedTables = make(map[string]bool, len(ch.backup.Tables))
	for table := range ch.backup.Tables {
		ch.exportedTables[table] = true
	}
	// 备份原本是否携带 cert 表——反向悬挂降级仅对「从未携带」开放；
	// 携带却被分类丢弃时维持硬拒绝。
	ch.backupCarriedCertTables = ch.exportedTables["certificate_configs"] || ch.exportedTables["ca_providers"]
	return nil
}

func (ch *importValidationChain) verifyIntegrity() error {
	integrity, err := verifyBackupIntegrity(*ch.backup)
	if err != nil {
		return err
	}
	ch.result.UsedLegacyChecksum = integrity.LegacyChecksum
	ch.result.NoIntegrityChecksum = integrity.NoChecksum
	return nil
}

func (ch *importValidationChain) resolveSectionSelection() error {
	return resolveImportSectionSelection(ch.backup, ch.opts.RequestedSections)
}

func (ch *importValidationChain) dropBackfilledTables() error {
	// verifyBackupIntegrity 把缺失表回填为空切片（校验均匀性），此处还原
	// 「缺席」语义——分类导出不含的表不得被当作「清空本地表」应用。
	for table := range ch.backup.Tables {
		if !ch.exportedTables[table] {
			delete(ch.backup.Tables, table)
		}
	}
	return nil
}

func (ch *importValidationChain) filterSections() error {
	sectionTables, includeGlobal, ok := configBackupSectionTables(ch.backup.Sections)
	if !ok {
		return errors.New("未知的配置分类")
	}
	ch.result.SectionTables = sectionTables
	ch.result.IncludeGlobal = includeGlobal
	for table := range ch.backup.Tables {
		if !sectionTables[table] {
			delete(ch.backup.Tables, table)
		}
	}
	if !includeGlobal {
		ch.backup.Config = nil
	}
	return nil
}

func (ch *importValidationChain) assertFilteredScopeHasContent() error {
	return assertImportScopeHasContent(ch.backup.Tables, ch.result.IncludeGlobal, ch.backup.Sections, importScopeFiltered)
}

func (ch *importValidationChain) prepareSkips() error {
	warnings, err := prepareV2BackupSkips(ch.backup, ch.opts.LbbakPayload, ch.result.SectionTables)
	if err != nil {
		return err
	}
	ch.result.SkipWarnings = append(ch.result.SkipWarnings, warnings...)
	return nil
}

func (ch *importValidationChain) normalizeVersionUpdateStatuses() error {
	ch.result.SkipWarnings = append(ch.result.SkipWarnings, normalizeImportedVersionUpdateStatuses(ch.backup.Tables)...)
	return nil
}

func (ch *importValidationChain) validateRows() error {
	return validateV2BackupRows(ch.ctx, ch.deps.DB, *ch.backup)
}

func (ch *importValidationChain) rejectEmptyUsersTable() error {
	// users 键存在且为空数组=导入将清空全部账户（合法导出恒携带 ≥1 启用
	// 管理员；键缺席的分类导出已在上一步按缺席删除，不受影响）。
	if rows, ok := ch.backup.Tables["users"]; ok && len(rows) == 0 {
		return errors.New("备份 users 表为空，导入将清空全部账户，已拒绝")
	}
	return nil
}

func (ch *importValidationChain) skipMissingWAFMetadata() error {
	// 规则库数据库分类要求文件本体（lbbak）：无文件却勾选该分类时剔除其版本
	// 表，防记录与文件分叉。纯 JSON 备份不可能携带数据文件，版本表恒跳过。
	if !ch.result.SectionTables["security_crs_version"] {
		return nil
	}
	crsMissing := ch.opts.LbbakPayload == nil || ch.opts.LbbakPayload.CRSTarGz == nil
	xdbMissing := ch.opts.LbbakPayload == nil || ch.opts.LbbakPayload.Xdb == nil
	switch {
	case crsMissing && xdbMissing:
		for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
			delete(ch.backup.Tables, table)
		}
		ch.result.WAFMetadataSkipped = true
	case crsMissing:
		delete(ch.backup.Tables, "security_crs_version")
		ch.result.WAFCRSMetadataSkipped = true
	case xdbMissing:
		delete(ch.backup.Tables, "security_ip2region_version")
		ch.result.WAFXdbMetadataSkipped = true
	}
	return nil
}

func (ch *importValidationChain) validateCertJobStatuses() error {
	return validateV2BackupCertJobStatuses(ch.backup.Tables)
}

func (ch *importValidationChain) assertSkippedScopeHasContent() error {
	// 软跳过/剔除步之后仍有内容可落库——否则继续提交会「成功但零写入」。
	return assertImportScopeHasContent(ch.backup.Tables, ch.result.IncludeGlobal, ch.backup.Sections, importScopeSkipped)
}

func (ch *importValidationChain) normalizeBlockPageContentTypes() error {
	normalizeBlockPageContentTypes(ch.backup.Tables)
	return nil
}

func (ch *importValidationChain) canonicalizeRuleDomains() error {
	// 冲突键依赖规范化域名；与 validateV2BackupRules 同口径（幂等）。
	canonicalizeBackupRuleDomains(ch.backup.Tables["lb_rules"])
	return nil
}

func (ch *importValidationChain) disableRuleConflicts() error {
	ch.result.DisabledConflicts = disableV2RuleConflicts(ch.backup.Tables["lb_rules"])
	return nil
}

func (ch *importValidationChain) validateRuleReferences() error {
	return validateBackupRuleReferences(ch.backup.Tables)
}

func (ch *importValidationChain) validateRules() error {
	var portGate func(string, int) error
	if ch.deps.ValidateRuleListenPort != nil {
		portGate = ch.deps.ValidateRuleListenPort
	}
	// 可选端口门以可变参数传入：nil 时退回包级默认管理口。
	return validateV2BackupRules(ch.backup.Tables, portGate)
}

func (ch *importValidationChain) validateSecurityPolicies() error {
	// 本次导入同时替换 CRS 规则树时，组号/规则 ID 的存在性以导入后规则树
	// 为准（live 索引不是同一代）——降级为形状校验并告警。
	ch.result.CRSTreeReplaced = ch.result.SectionTables["security_crs_version"] &&
		ch.opts.LbbakPayload != nil && ch.opts.LbbakPayload.CRSTarGz != nil
	var querier tableQuerier
	if ch.deps.DB != nil {
		querier = ch.deps.DB
	}
	return validateV2BackupSecurityPoliciesWithQuerier(ch.ctx, ch.backup.Tables, ch.result.CRSTreeReplaced, querier)
}

func (ch *importValidationChain) validateTLSShape() error {
	// 「导规则不导 cert 配置且备份从未携带 cert 表」方向按 live 解析失败的
	// ACME 引用降级为悬挂警告（携带却被分类丢弃时维持硬拒绝）。
	softLiveACMERefs := ch.result.SectionTables["lb_rules"] &&
		!ch.result.SectionTables["certificate_configs"] && !ch.result.SectionTables["ca_providers"] &&
		!ch.backupCarriedCertTables
	dangling, err := validateV2BackupTLSShapeSoft(ch.backup.Tables, softLiveACMERefs)
	if err != nil {
		return err
	}
	ch.result.ACMEDanglingImported = dangling
	return nil
}

func (ch *importValidationChain) validateCertJobs() error {
	warnings, err := validateV2BackupCertJobs(ch.backup.Tables)
	if err != nil {
		return err
	}
	ch.result.CertJobProviderWarnings = warnings
	return nil
}

// validateCertJobProviderDangling 证书任务 CA 提供商悬挂预检（链内单源）：
// 「系统数据」替换 CA 提供商/证书配置而证书任务未随包时，live 任务行的显式
// 提供商引用可能已禁用（真实失败面）或整行缺失（回落自愈）。两档语义必须
// 分开计数与措辞，混为「续签将失败」对缺失子集是过度断言。只告警不阻断
// （「缺席=保留本地」语义不变）；统计失败同样只作告警（纯可观测性）。
func (ch *importValidationChain) validateCertJobProviderDangling() error {
	if ch.deps.DB == nil {
		return nil
	}
	disabled, missing, err := certJobProviderDanglingCounts(ch.ctx, ch.deps.DB, ch.backup.Tables, ch.result.SectionTables)
	if err != nil {
		services.Logf("warn", "配置预览/导入：证书任务 CA 提供商悬挂统计失败: %v", err)
		ch.result.CertJobDanglingWarnings = append(ch.result.CertJobDanglingWarnings, "证书任务 CA 提供商悬挂统计未完成（读取失败）："+err.Error())
		return nil
	}
	ch.result.CertJobDanglingWarnings = certJobProviderDanglingWarnings(disabled, missing)
	return nil
}

func (ch *importValidationChain) validateAdminTLS() error {
	// 坏配置会使下次启动进程退出（崩溃循环），整包拒绝保持零写入语义。
	return validateV2BackupAdminTLS(ch.backup.Config)
}

func (ch *importValidationChain) validateAutobanConfig() error {
	notes, err := validateV2BackupAutobanConfig(ch.backup.Config)
	if err != nil {
		return err
	}
	ch.result.AutobanClampNotes = notes
	return nil
}

// normalizeGlobalConfigNumbers 全局配置数值归一（链内唯一归一点）。
// 此前钳制在导入 core 内链外执行：预览对同一份备份返回 valid 且无警告，导入
// 后值却被静默改写（预览「可提交」在值域层面不成立）。搬进链后两条路径共用
// 同一实现与同一组文案，预览 warnings 与导入审计/响应自然同源。
func (ch *importValidationChain) normalizeGlobalConfigNumbers() error {
	notes := clampBackupConfigInts(ch.backup.Config)
	// request_body_max_size_mb 专用归一带值回显；超过 Coraza 1GiB
	// 上限与保存侧一致拒绝，非法/非正历史形态仍归治理默认 128。
	if value, exists := ch.backup.Config["request_body_max_size_mb"]; exists {
		n, integerShape := backupInteger(value)
		if integerShape && n > maxRequestBodySizeMB {
			return fmt.Errorf("request_body_max_size_mb 必须在 1-%d MB 之间", maxRequestBodySizeMB)
		}
		normalized := normalizeBackupRequestBodyMB(value, 1, db.DefaultRequestBodyMaxSizeMB)
		ch.backup.Config["request_body_max_size_mb"] = normalized
		if !integerShape {
			notes = append(notes, fmt.Sprintf("request_body_max_size_mb 非法形态（%v），已归一为 %d", value, normalized))
		} else if n <= 0 {
			notes = append(notes, fmt.Sprintf("request_body_max_size_mb 越界（%d），已钳位为 %d", n, normalized))
		}
	}
	ch.result.ConfigClampNotes = notes
	return nil
}

func (ch *importValidationChain) validateTrustedProxyConfig() error {
	return validateV2BackupTrustedProxyConfig(ch.backup.Config, ch.backup.Tables)
}

func (ch *importValidationChain) validateRuntimeSettings() error {
	return validateV2BackupRuntimeSettings(ch.backup.Config, ch.backup.Tables)
}

func (ch *importValidationChain) validateAutoBackupConfig() error {
	return validateV2BackupAutoBackupConfig(ch.backup.Config)
}
