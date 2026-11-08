// MFA 弹框「受保护操作范围」清单单源：与 middleware.go 的 mfaStepUpGuard 挂载面
// （admin/business 两组级）及 readOnlyWriteRoutes 豁免清单逐族对齐。新增写端点族
// 必须同步入列（否则弹框会低估受保护范围），测试按本清单反查缺失项。
// i18n：title/items 走 views.mfa 词条键（zh 母本与键的逐条对表钉测见
// tests/mfaErrors.spec.ts 的清单词条化用例）——键化后 zh 直出与原字面量逐字等价，
// mfaErrors.spec 的族锚点运行时断言不受影响。

import { tSafe as t } from '../i18n/tSafe.ts'

// 形状只作下方清单的元素类型——全仓零外部消费，不导出（避免视图绕开清单
// 单源自行构造受保护操作集合）。
interface MfaScopeGroup {
  title: string
  items: string[]
}

export const MFA_SCOPE_GROUPS: MfaScopeGroup[] = [
  {
    title: t('common.app.views.mfa.scopeGroupRules'),
    items: [t('common.app.views.mfa.scopeCreate'), t('common.app.views.mfa.scopeEdit'), t('common.app.views.mfa.scopeDelete'), t('common.app.views.mfa.scopeEnable'), t('common.app.views.mfa.scopeDisable'), t('common.app.views.mfa.scopeDuplicate')],
  },
  {
    title: t('common.app.views.mfa.scopeGroupCertDns'),
    items: [t('common.app.views.mfa.scopeDnsConfigCrud'), t('common.app.views.mfa.scopeCertConfigCrud'), t('common.app.views.mfa.scopeDnsCredentialTest'), t('common.app.views.mfa.scopeCaProviderChangeTest'), t('common.app.views.mfa.scopeTriggerIssue'), t('common.app.views.mfa.scopeCertJobRetryDelete')],
  },
  {
    title: t('common.app.views.mfa.scopeGroupSecurity'),
    items: [t('common.app.views.mfa.scopeSecurityPolicyCrud'), t('common.app.views.mfa.scopeCustomRuleCrud'), t('common.app.views.mfa.scopeBlockPageCrud'), t('common.app.views.mfa.scopeIpListCrud'), t('common.app.views.mfa.scopeLibUpdate'), t('common.app.views.mfa.scopeThreatCrawlerUpdate'), t('common.app.views.mfa.scopeAutobanConfig')],
  },
  {
    title: t('common.app.views.mfa.scopeGroupUsersKeys'),
    items: [t('common.app.views.mfa.scopeUserCrud'), t('common.app.views.mfa.scopeProfileUpdate'), t('common.app.views.mfa.scopeApiKeyMgmt'), t('common.app.views.mfa.scopeMfaReset'), t('common.app.views.mfa.scopeRecoveryCodes')],
  },
  {
    title: t('common.app.views.mfa.scopeGroupSystem'),
    items: [t('common.app.views.mfa.scopeSettingsSave'), t('common.app.views.mfa.scopeConfigReloadValidate'), t('common.app.views.mfa.scopeConfigImport'), t('common.app.views.mfa.scopeConfigExportBackup'), t('common.app.views.mfa.scopeAdminTls'), t('common.app.views.mfa.scopeOidcConfig'), t('common.app.views.mfa.scopeCaddyService'), t('common.app.views.mfa.scopeRawCaddyOverwrite'), t('common.app.views.mfa.scopeTaskMonitor'), t('common.app.views.mfa.scopeSystemRestart')],
  },
  {
    title: t('common.app.views.mfa.scopeGroupCluster'),
    items: [t('common.app.views.mfa.scopeNodeApproval'), t('common.app.views.mfa.scopeAccessUrl'), t('common.app.views.mfa.scopeNodeSite'), t('common.app.views.mfa.scopeNodeService'), t('common.app.views.mfa.scopeForgetPin'), t('common.app.views.mfa.scopeRegisterToken'), t('common.app.views.mfa.scopeModeSwitch'), t('common.app.views.mfa.scopeManualSync'), t('common.app.views.mfa.scopeClusterSync'), t('common.app.views.mfa.scopeReplicaLogin')],
  },
]
