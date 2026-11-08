import { hasOwn } from './hasOwn.ts'
import { tSafe as t } from '../i18n/tSafe.ts'

/**
 * 导入/还原预览摘要的展示标签单源（i18n：标签走 views.impexp 词条键，
 * zh 直出与原字面量逐字等价；键↔zh 对表钉测见 tests/importPreview.spec.ts）。
 *
 * 后端校验响应的 summary 以**表名**为键（internal/handlers/config_import_v1.go
 * 遍历 backup.Tables 逐个 len(rows)），表集即 configBackupTables
 * （internal/handlers/config_backup.go）的 18 张表。前端曾只覆盖其中 12 个键，
 * 其余按 `labels[key] || key` 回退——用户会在预览里看到
 * 「security_policies·3」「path_rules·2」这类内部表名，无法判断覆盖范围。
 *
 * 覆盖完整性由 tests/importPreview.spec.ts 跨栈钉住（解析 Go 的
 * configBackupTables 与本节键集比对），新增表时必须同时补标签。
 */
const IMPORT_SUMMARY_LABELS: Readonly<Record<string, string>> = {
  // 负载均衡
  lb_rules: t('common.app.views.impexp.tblLbRules'),
  upstreams: t('common.app.views.impexp.tblUpstreams'),
  path_rules: t('common.app.views.impexp.tblPathRules'),
  // 凭证与证书
  users: t('common.app.views.impexp.tblUsers'),
  api_keys: t('common.app.views.impexp.tblApiKeys'),
  ca_providers: t('common.app.views.impexp.tblCaProviders'),
  certificate_configs: t('common.app.views.impexp.tblDnsProviders'),
  cert_jobs: t('common.app.views.impexp.tblCertJobs'),
  // 安全防护
  security_policies: t('common.app.views.impexp.tblSecurityPolicies'),
  security_policy_bindings: t('common.app.views.impexp.tblPolicyBindings'),
  security_custom_rules: t('common.app.views.impexp.tblCustomRules'),
  security_block_pages: t('common.app.views.impexp.tblBlockPages'),
  security_ip_lists: t('common.app.views.impexp.tblIpLists'),
  security_crs_version: t('common.app.views.impexp.tblCrsVersion'),
  security_ip2region_version: t('common.app.views.impexp.tblIp2regionVersion'),
  security_threat_sources: t('common.app.views.impexp.tblThreatSources'),
  security_crawler_sources: t('common.app.views.impexp.tblCrawlerSources'),
  // 集群
  nodes: t('common.app.views.impexp.tblNodes'),
  // 旧版预览的派生键（非表名）：保留以免旧响应回退成英文键
  rules: t('common.app.views.impexp.tblRules'),
  tls_rules: t('common.app.views.impexp.tblTlsRules'),
}

/** 摘要键的中文标签；未知键回退原键（fail-visible：新表未登记时立刻可见）。
 *  键来自后端 summary 的任意字符串，必须先过 hasOwn——裸下标会把原型链上的
 *  constructor/toString 当命中（truthy，绕过回退）。 */
export const importSummaryLabel = (key: string): string =>
  hasOwn(IMPORT_SUMMARY_LABELS, key) ? IMPORT_SUMMARY_LABELS[key] : key
