// 未被任何 spec 引用但承担跨栈/注入面的工具单源：
//   - caddyDefaults：访问日志格式模板末行必须与后端强制注入行逐字一致
//     （落库格式 ≠ 实际生效格式会让用户以为脱敏没生效）；
//   - escape / highlight：HTML 注入面的兜底转义；
//   - branding：footerHtml 的默认/自定义分支与转义。
//
// branding 依赖 api.ts（element-plus 字节级依赖），用替身加载；highlight 顶层
// 导入 Prism CSS（node 不可加载），兜底分支用源码钉。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, registerModuleHooks, repoCode, section } from './_helpers.ts'
import type * as BrandingModule from '../src/utils/branding.ts'
import { STUB_API } from './_stubs.ts'
import { DEFAULT_ACCESS_LOG_FORMAT } from '../src/utils/caddyDefaults.ts'
import { escapeHtml } from '../src/utils/escape.ts'
import { formatBytes } from '../src/utils/formatBytes.ts'
import { ingestionWarningMessage } from '../src/utils/ingestionHealth.ts'

const g = globalThis as unknown as { __gets: unknown[]; __get: (url: string, config?: unknown) => Promise<unknown> }
g.__gets = []
registerModuleHooks({ '@/utils/api': STUB_API })

test('默认访问日志格式末行与后端脱敏注入行逐字一致（跨栈钉）', () => {
  const go = repoCode('internal/handlers/caddy.go')
  // 后端脱敏行不再写字面量：路径从 internal/accesslog 单源派生（引擎 filter 精确
  // 匹配 http.Header 的规范化键名，任何手写拼写副本都可能悄悄漂移成不命中）。
  assert.match(go, /var accessLogRedactionLine = accesslog\.APIKeyHeaderPath\(\) \+ " -> delete"/, '后端脱敏行必须从 accesslog 单源派生')
  const paths = repoCode('internal/accesslog/paths.go')
  assert.match(paths, /textproto\.CanonicalMIMEHeaderKey\(APIKeyHeaderName\)/, '脱敏路径必须由头名规范化派生（禁止手写字面量）')
  const lines = DEFAULT_ACCESS_LOG_FORMAT.split('\n')
  assert.equal(lines[lines.length - 1], 'request>headers>X-Api-Key -> delete', '模板末行必须是引擎真正命中的规范化键形态')
  // 落库归一与启动迁移消费同一单源：db.go 追加规范行、并以大小写不敏感谓词移除
  // 既有行（旧模板的字面量拼写与规范拼写是同一个 HTTP 头，不得留两行）。
  const db = repoCode('internal/db/db.go')
  assert.match(db, /apiKeyPath := accesslog\.APIKeyHeaderPath\(\)/, 'db.go 迁移的脱敏路径必须取单源')
  assert.match(db, /apiKeyPath\+\s*" -> delete"/, 'db.go 迁移必须追加 delete 动作（与模板末行同形）')
  assert.match(db, /accesslog\.IsAPIKeyPath\(parts\[0\]\)/, 'db.go 迁移必须用大小写不敏感谓词移除既有行')
  assert.match(go, /accesslog\.IsAPIKeyPath\(r\.Path\)/, '写侧归一必须用同一谓词识别既有行')
  // 字面量只允许出现在单源包内部（APIKeyHeaderName 与 IsAPIKeyPath 的比较基准）。
  for (const [name, source] of [
    ['internal/handlers/caddy.go', go],
    ['internal/db/db.go', db],
  ] as const) {
    const literal = [...source.matchAll(/request>headers>X-API-Key/g)].length
    assert.equal(literal, 0, `${name} 不得再出现脱敏路径字面量（单源在 internal/accesslog）`)
  }
})

test('escapeHtml 覆盖五个 HTML 危险字符（含引号属性上下文）', () => {
  assert.equal(escapeHtml(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;')
  assert.equal(escapeHtml('plain'), 'plain')
})

test('highlight 的 Prism 异常兜底必须转义（注入面不得回退原文）', () => {
  const highlight = code('src/utils/highlight.ts')
  const catchBlock = section(highlight, '} catch {', '\n  }\n}')
  assert.match(catchBlock, /return escapeHtml\(content\)/, '兜底必须走共享 escapeHtml，不得返回原文')
  // Prism.languages 是普通对象：原型键（constructor 等）直接下标会拿到函数当
  // grammar → 每帧抛错并被兜底吞掉（高亮静默丢失），必须走自有属性守卫。
  assert.match(highlight, /hasOwn\(Prism\.languages, lang\)/, 'grammar 查表必须做原型键守卫')
})

// 品牌状态（appName/footerText/footerUsesDefault）是模块单例：两个用例各自
// 加载独立实例（查询串区分），否则「默认态」断言隐含依赖文件内用例执行顺序。
const freshBranding = (tag: string): Promise<typeof BrandingModule> =>
  import(`../src/utils/branding.ts?case=${tag}`)

// 默认页脚文案以生产常量为准（含版权年份）——用例里再抄一份年份会随发版
// 漂移，且抄来的年份与被测值同源即失去鉴别力。
const brandingSource = code('src/utils/branding.ts')
const defaultFooterText = brandingSource.match(/const footerText = ref\('([^']*)'\)/)?.[1]

test('branding 预取失败：静默回落默认页脚与默认标题，不抛给调用方', async (t) => {
  // /branding 是装饰性预取：失败时页脚/标题保持默认（不得弹全局错误 toast）。
  const branding = await freshBranding('prefetch-fail')
  const host = globalThis as { document?: unknown }
  const previousDocument = host.document
  const documentStub = { title: '' }
  host.document = documentStub
  t.after(() => {
    if (previousDocument === undefined) Reflect.deleteProperty(host, 'document')
    else host.document = previousDocument
  })
  let seenConfig: unknown
  g.__get = async (_url: string, config?: unknown) => {
    seenConfig = config
    throw new Error('network down')
  }
  await branding.loadBranding()
  assert.deepEqual(seenConfig, { silent: true }, '装饰性预取必须 silent——失败不得弹全局错误提示')
  assert.ok(defaultFooterText, '生产默认页脚文案必须可从源码解析')
  assert.ok(branding.footerHtml.value.startsWith(defaultFooterText), `失败后必须是默认页脚文案（期望以 ${defaultFooterText} 开头）`)
  assert.match(branding.footerHtml.value, /class="footer-link"/, '失败后仍是默认页脚（带仓库链接）')
  assert.equal(branding.appName.value, 'Lazy Balancer', '失败后产品名保持默认')
  assert.equal(documentStub.title, 'Lazy Balancer V2', '失败后标题仍写默认产品名')
})

test('displayThreatScreenMode：仅 globe 保留，其余（含缺失/未知库值）归一为地图', async () => {
  const { displayThreatScreenMode } = await import('../src/utils/configValues.ts')
  assert.equal(displayThreatScreenMode('globe'), 'globe')
  assert.equal(displayThreatScreenMode('map'), 'map')
  for (const value of ['3d', '', 'GLOBE', ' globe', null, undefined]) {
    assert.equal(displayThreatScreenMode(value), 'map', `${String(value)} 必须展示为地图`)
  }
  // 库值非法不得把大屏留在空态/抛错：三处生产消费同走单源
  for (const path of ['src/views/Settings.vue', 'src/views/settings/BasicSettings.vue', 'src/views/security/ThreatScreen.vue']) {
    assert.match(code(path), /displayThreatScreenMode\(/, `${path} 必须走展示口径单源`)
  }
})

test('branding.footerHtml：默认加 GitHub 链接、自定义仅转义文本', async (t) => {
  // 先加载模块（vue runtime-dom 在无 document 时初始化），再注入 host——先注入
  // 半成品 document 会让 runtime-dom 的探测代码调用不存在的 createElement。
  const branding = await freshBranding('footer-branches')
  const host = globalThis as { document?: unknown }
  const previousDocument = host.document
  const documentStub = { title: '' }
  host.document = documentStub
  // 与 threatHotPathCaching 同范式：假 DOM 不得留给同进程其它用例
  // （node --test --test-isolation=none 下会污染 Vue 的 DOM 探测）。
  t.after(() => {
    if (previousDocument === undefined) Reflect.deleteProperty(host, 'document')
    else host.document = previousDocument
    assert.equal(host.document, previousDocument, 'document 替身必须还原')
  })

  // 默认分支（footer_uses_default 未关闭）：带 GitHub 外链
  const defaultHtml = branding.footerHtml.value
  assert.match(defaultHtml, /class="footer-link"/)
  assert.match(defaultHtml, /github\.com/, '默认页脚必须含仓库链接')

  // 自定义分支：后端声明 footer_uses_default=false → 不加链接，且文本转义
  g.__get = async () => ({ data: { footer_text: '<b>x & y</b>', footer_uses_default: false, app_name: 'Corp' } })
  await branding.loadBranding()
  const customHtml = branding.footerHtml.value
  assert.equal(customHtml, '&lt;b&gt;x &amp; y&lt;/b&gt;')
  assert.doesNotMatch(customHtml, /footer-link/, '自定义页脚不得追加 GitHub 链接')
  assert.equal(documentStub.title, 'Corp V2')
})

// 字节格式化此前有两份实现：api.ts 的 formatBytes（两位小数、到 TB）与
// ingestionHealth 的私有 humanBytes（一位小数、到 GB）——同一份 1,500,000
// 字节在日志占用条与采集告警里显示 1.43 MB / 1.5 MB。实现下沉到零依赖
// utils/formatBytes，所有展示点共用。
test('字节格式化单源：精度/量级与跨调用点一致性', () => {
  assert.equal(formatBytes(0), '0 B')
  assert.equal(formatBytes(-1), '0 B', '负值/非法同零值口径')
  assert.equal(formatBytes(Number.NaN), '0 B')
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(1024), '1 KB', '整值不补小数位（parseFloat 去尾零）')
  assert.equal(formatBytes(1_500_000), '1.43 MB')
  assert.equal(formatBytes(1024 ** 3), '1 GB')
  assert.equal(formatBytes(1024 ** 4), '1 TB')
  assert.equal(formatBytes(1024 ** 5), '1024 TB', '量级上限到 TB（不再自造更大单位）')

  // 跨调用点：采集健康位的丢失体量必须与同一函数同精度（不得再有一份私有实现）
  const skipped = ingestionWarningMessage({
    observed: true,
    healthy: false,
    consecutive_failures: 0,
    skipped_regions: 2,
    skipped_bytes: 1_500_000,
  })
  assert.ok(skipped.includes(`累计 ${formatBytes(1_500_000)}`), '摄取告警必须复用 formatBytes 的精度')
})

test('字节格式化不得再有第二份实现（api.ts / ingestionHealth 只消费单源）', () => {
  assert.doesNotMatch(code('src/utils/api.ts'), /function formatBytes/, 'api.ts 不再持有实现')
  assert.doesNotMatch(code('src/utils/ingestionHealth.ts'), /function humanBytes/, '摄取健康位不再私有实现')
  assert.match(code('src/utils/ingestionHealth.ts'), /import \{ formatBytes as humanBytes \} from '\.\/formatBytes\.ts'/)
  // 视图/组件一律从 utils/formatBytes 取（api.ts 会拖入 axios/element-plus 依赖链）
  for (const file of [
    'src/components/LogStorageBar.vue',
    'src/views/Dashboard.vue',
    'src/views/settings/BasicSettings.vue',
    'src/views/security/SecurityRules.vue',
    'src/views/security/SecurityBlockPages.vue',
  ]) {
    assert.match(code(file), /import \{ formatBytes \} from '@\/utils\/formatBytes'/, `${file} 必须引用字节格式化单源`)
    assert.doesNotMatch(code(file), /formatBytes[^,\n]*\}\s*from '@\/utils\/api'/, `${file} 不得再从 api.ts 取 formatBytes`)
  }
})

// 导出面 = 消费面：只有定义处使用的常量/类型不得挂 export（零消费导出会诱导
// 外部直接构造内部形状，且删改时误以为有契约）。此处把已收敛的清单钉成回归
// 守卫——新增零消费导出由评审按同一口径处理，不由本清单自动扩展。
test('零外部消费的符号不得再导出（导出面 = 消费面）', () => {
  const cases: Array<[string, string]> = [
    ['src/composables/useCrsRuleIndex.ts', 'CrsRuleIndexEntry'],
    ['src/composables/useSettingsDraft.ts', 'StagedAdminTlsCert'],
    ['src/utils/settingsPages.ts', 'SETTINGS_TABS_CONSUMING_CONFIG'],
    ['src/utils/certJobColumns.ts', 'CERT_JOB_COLUMN_HIDE_ORDER'],
    ['src/utils/adminTlsGate.ts', 'AdminTlsStoredCertState'],
    ['src/utils/adminTlsGate.ts', 'AdminTlsDialogCertState'],
    ['src/utils/apiFailure.ts', 'AuthFailureKind'],
    ['src/utils/apiFailure.ts', 'AuthFailureInput'],
    ['src/utils/apiFailure.ts', 'MfaStepUpCoordinator'],
    ['src/utils/apiFailure.ts', 'MfaGraceNoticeHandle'],
    ['src/utils/apiFailure.ts', 'MfaGraceTracker'],
    ['src/utils/apiKeyWhitelist.ts', 'SerializedWhitelist'],
    ['src/utils/auditLogFilters.ts', 'AuditLogFilterState'],
    ['src/utils/autobanStatus.ts', 'AutobanEffectivenessView'],
    ['src/utils/bulkApplyResult.ts', 'BulkResponseLike'],
    ['src/utils/caddyConfigPayload.ts', 'CaddyAccessLogSettings'],
    ['src/utils/caddyConfigPayload.ts', 'CaddyConfigPayload'],
    ['src/utils/certJobExpiry.ts', 'CertJobExpiryFields'],
    ['src/utils/certJobStatus.ts', 'CertJobStatusTone'],
    ['src/utils/certQueue.ts', 'CertQueueCounts'],
    ['src/utils/clusterSyncSwitches.ts', 'ClusterSyncSwitch'],
    ['src/utils/clusterUrl.ts', 'ClusterUrlValidationOptions'],
    ['src/utils/clusterWriteGate.ts', 'ClusterWriteGateInput'],
    ['src/utils/configValues.ts', 'ThreatScreenMode'],
    ['src/utils/importFailure.ts', 'ImportFailureReport'],
    ['src/utils/importPreview.ts', 'ImportPreviewResult'],
    ['src/utils/importPreview.ts', 'ImportPreviewSessionOptions'],
    ['src/utils/lazyOnce.ts', 'LazyLoader'],
    ['src/utils/logStatCap.ts', 'LogStatBucket'],
    ['src/utils/policyPayload.ts', 'PolicyPayload'],
    ['src/utils/rateLimitBlocks.ts', 'RateLimitBlockHost'],
    ['src/utils/restart.ts', 'reloadAfterRestart'],
    ['src/utils/restart.ts', 'RestartServiceOptions'],
    ['src/utils/ruleWizard.ts', 'StageBlockPageOverrideState'],
    ['src/utils/securityLibraries.ts', 'LibraryTagType'],
    ['src/utils/securityLibraries.ts', 'LibrarySummary'],
    ['src/utils/securityLibraries.ts', 'LibraryHealthTag'],
    ['src/utils/securityStages.ts', 'RuleStagePages'],
    ['src/utils/securityStages.ts', 'StageRow'],
    ['src/utils/securityStages.ts', 'StageDetailEntry'],
    ['src/utils/securityStages.ts', 'StageCustomRuleDetail'],
    ['src/utils/securityStages.ts', 'StagePolicyDetails'],
    ['src/utils/securityStages.ts', 'CrsFilenameInfo'],
    ['src/utils/securityStages.ts', 'StageOverride'],
    ['src/utils/securityStages.ts', 'TrustHitMode'],
    ['src/utils/securityStages.ts', 'EventDetailRefScope'],
    ['src/utils/securityStages.ts', 'BlockPageEffective'],
    ['src/utils/securityStages.ts', 'BlockPageStageCapability'],
    ['src/utils/sessionSingleFlight.ts', 'SessionSingleFlight'],
    ['src/utils/sessionSingleFlight.ts', 'SessionSingleFlightOptions'],
    ['src/utils/siteLocation.ts', 'SiteLocationChoice'],
    ['src/utils/siteLocation.ts', 'NodeSiteFormValue'],
    ['src/utils/strategyLabels.ts', 'StrategyCardOption'],
    ['src/utils/threatFlowRules.ts', 'AdaptiveSampleState'],
    ['src/utils/threatFlowRules.ts', 'AdaptiveSampleOutcome'],
    ['src/utils/threatFlowRules.ts', 'FlowArcPlan'],
    ['src/utils/threatFlowRules.ts', 'FlowArcGroupLike'],
    ['src/utils/threatFlowRules.ts', 'FlowEventPlanInput'],
    ['src/utils/threatGlobe.ts', 'DotLatLng'],
    ['src/utils/threatProjection.ts', 'SpherePickCamera'],
    ['src/utils/threatScene.ts', 'HoverLayerTransform'],
    ['src/utils/threatScreenMetrics.ts', 'TrafficDeltaResult'],
    ['src/utils/threatShared.ts', 'PolysBounds'],
    ['src/utils/threatShared.ts', 'ProvinceGridDot'],
    ['src/utils/triggeredFilter.ts', 'TriggeredCategory'],
    ['src/utils/trustRemoval.ts', 'TrustRemovalList'],
    ['src/utils/trustRemoval.ts', 'TrustRemovalPlan'],
    ['src/utils/trustedProxyRanges.ts', 'TrustedProxyExpansion'],
    ['src/utils/updaterName.ts', 'UpdaterUserLike'],
  ]
  for (const [file, symbol] of cases) {
    const text = code(file)
    // 声明前置 export 的四种形态 + 复导出/默认导出：只认前三种会让
    // `export { X }` 复导出静默把零消费符号重新公开（守卫盲区）。
    const reopened = [
      new RegExp(`export\\s+(?:const|type|interface|enum|namespace)\\s+${symbol}\\b`),
      new RegExp(`export\\s*\\{[^}]*\\b${symbol}\\b[^}]*\\}`),
      new RegExp(`export\\s+default\\s+${symbol}\\b`),
    ]
    for (const pattern of reopened) {
      assert.doesNotMatch(text, pattern, `${file} 的 ${symbol} 零外部消费，不得对外导出`)
    }
    assert.match(text, new RegExp(`(?:^|\\n)(?:const|type|interface)\\s+${symbol}\\b`), `${symbol} 仍须在本模块内定义`)
  }
})

// CRS 规则索引响应里后端还带 version，但前端零读：声明不消费的字段会诱导
// 调用方以为这是版本数据源（版本展示走 /security/crs/status 的独立字段）。
test('CRS 规则索引响应类型只声明消费面（version 不再声明）', () => {
  const src = code('src/composables/useCrsRuleIndex.ts')
  const data = section(src, 'interface CrsRuleIndexData {', '\n}')
  assert.match(data, /rules: CrsRuleIndexEntry\[\]/)
  assert.doesNotMatch(data, /\bversion\b/, '零消费字段不得留在响应类型里')
})
