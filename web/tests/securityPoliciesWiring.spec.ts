// 策略页接线钉：引用名单共享缓存（self + 共绑 peer）、迁移预演第二类跳过风险、
// G3 判定单源、状态码选项单源、CRS 文件名解析单源、爬虫引擎空集语义、注释口径。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, member, section } from './_helpers.ts'
import { STAGE_BLOCK_STATUS_OPTIONS, hasStage3Features, parseCrsFilename, parseUnknownStrings } from '../src/utils/securityStages.ts'

const page = code('src/views/security/SecurityPolicies.vue')

test('G3 谓词：mode 三态 ∪ 自定义规则引用非空（与后端 PolicyTypeFeatures 同口径）', () => {
  for (const mode of ['blocking', 'detection', 'custom_only']) {
    assert.equal(hasStage3Features(mode, 0), true, `${mode} 恒产生阶段 3`)
  }
  assert.equal(hasStage3Features('off', 1), true, '关闭模式但仍有自定义规则引用')
  assert.equal(hasStage3Features('off', 0), false)
})

test('阶段 3 chip 消费 G3 单源谓词（引用数口径，含禁用规则）', () => {
  // 切片必须按花括号配对取成员体：空白行（`'\n\n'`）作终点时，声明一旦长成
  // 多行块（块体内出现空行）就被截断，后续负断言在截断段上恒真空转。
  const chip = member(page, 'const stage3ChipOn = ')
  assert.match(chip, /hasStage3Features\(row\.mode, row\.custom_rules_ref_count/, '判定必须用引用数（与后端 G3 逐字对齐）')
  assert.match(chip, /custom_rules_ref_count \?\? row\.custom_rules_count/, '旧后端缺摘要字段时回退启用计数')
  assert.doesNotMatch(chip, /row\.has_waf/)
})

test('CRS 文件名解析单源：四位解析点全部改引 parseCrsFilename', () => {
  assert.deepEqual(parseCrsFilename('REQUEST-942-100-APPLICATION-ATTACK-SQLI.conf'), { phase: '请求', code: '42' })
  assert.deepEqual(parseCrsFilename('RESPONSE-955-100-X.conf'), { phase: '响应', code: '55' })
  assert.equal(parseCrsFilename('not-a-crs-file.conf'), null)

  for (const name of ['crsOptionCode', 'crsOptionPhase', 'crsGroupCodeOfFile']) {
    // 声明级限段（切到下一个顶层 `const`）：定长窗口会被增长后的函数挤出
    // （假红），也会越过单行箭头函数把相邻声明纳入检查面（假绿）。
    const body = section(page, `const ${name} = `, '\nconst ')
    assert.match(body, /parseCrsFilename\(/, `${name} 未走单源解析`)
    assert.doesNotMatch(body, /REQUEST\|RESPONSE/, `${name} 仍内联文件名正则`)
  }
  // CRS 组码归一已抽到 utils/crsGroups（策略页只消费），同一条解析单源要求跟着搬
  const groups = code('src/utils/crsGroups.ts')
  const normalize = section(groups, 'export const normalizeCrsGroups = ', '\n}')
  assert.match(normalize, /parseCrsFilename\(/, 'normalizeCrsGroups 未走单源解析')
  assert.doesNotMatch(normalize, /REQUEST\|RESPONSE/, 'normalizeCrsGroups 仍内联文件名正则')
  // 组选项构建（两处）同样不得再内联文件名正则
  assert.doesNotMatch(page, /\/\^\(\?:REQUEST\|RESPONSE\)-9\(\\d\{2\}\)-/i, '文件名正则不得留在视图层')
})

test('未知字符串数组解析单源（本地副本已删）', () => {
  assert.deepEqual(parseUnknownStrings(['a', ' ', 'b']), ['a', 'b'])
  assert.deepEqual(parseUnknownStrings('["a","b"]'), ['a', 'b'])
  assert.deepEqual(parseUnknownStrings(null), [])
  assert.doesNotMatch(page, /const parseUnknownStringList/, '本地同构实现不得回流')
  // 必须是包裹形态：只钉 `parseUnknownStrings(p.crs_rule_groups)` 会被
  // `normalizeCrsGroups(parseUnknownStrings(...))` 的子串命中，去掉归一仍绿。
  assert.match(
    page,
    /normalizeCrsGroups\(parseUnknownStrings\(p\.crs_rule_groups\)\)/,
    '原始取值必须经 normalizeCrsGroups（归一接线见 crsGroupNormalize.spec.ts）',
  )
})

test('引用名单取数走跨组件共享缓存（self + 共绑 peer，不再清空重下）', () => {
  const sharedImport = page.match(/import \{([^}]*)\} from '@\/utils\/securityStages'/)?.[1] ?? ''
  const imported = new Set(sharedImport.split(',').map((name) => name.trim()))
  for (const name of ['ensureSharedEntries', 'sharedEntriesCache', 'subscribeSharedEntriesCache']) {
    assert.ok(imported.has(name), `共享名单缓存必须导入 ${name}`)
  }
  assert.doesNotMatch(page, /ipListDetails/, '本地条目缓存不得回流')
  assert.doesNotMatch(page, /ensureIpListDetails/, '本地补齐函数不得回流')

  const watchBlock = section(page, 'watch([currentStep, ipACLList', 'void ensureIpListEntries')
  assert.match(watchBlock, /const coIds = coBoundPeerIds\.value/)
  assert.match(watchBlock, /if \(!coIds\.has\(p\.id\)\) continue/, 'peer refs 必须收敛为共绑集合')
  assert.doesNotMatch(watchBlock, /for \(const p of policies\.value\) \{\n\s*ids\.push/, '不得再全量汇总全部策略 refs')

  const ensure = section(page, 'const ensureIpListEntries', '\n}\n')
  assert.match(ensure, /ensureSharedEntries\(ids/)
  assert.match(ensure, /ipListEntries\.value = \{ \.\.\.sharedEntriesCache \}/, '落地后须同步本地响应式镜像')
  assert.match(page, /onUnmounted\(unregisterIpListEntries\)/, '订阅必须随组件卸载摘除')
})

test('迁移预演补「已有其他阶段 2 策略 → 将跳过」风险组', () => {
  const risk = section(page, 'const migrateStage2SkipRisk', '\n})\n')
  assert.match(risk, /migrateChildTypes\.value\.includes\('stage2'\)/, '未产出 stage2 子策略时无该风险')
  assert.match(risk, /type === 'stage2'/)
  assert.doesNotMatch(risk, /rate_limit_enabled/, '限流字段已下线，风险判定只按策略类型')
  // 模板：两处呈现（逐行标注 + 汇总横幅）。i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(page, /t\('app\.security\.policies\.migrate\.willSkip'\)/)
  assert.match(page, /t\('app\.security\.policies\.migrate\.ccPolicyRisk'/)
  assert.ok(code('src/locales/zh/security.ts').includes('将跳过（已有 stage2）'), '逐行标注原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('阶段 2 唯一风险'), '汇总横幅原文必须在 zh 母本词条中')
})

test('策略级拦截页状态码选项由共享清单派生（规则级覆盖选择器已退役）', () => {
  // 规则级阶段页覆盖编辑器已随触发归因退役；唯一状态码选择面=拦截页步骤的
  // 策略级「返回状态码」，必须继续消费共享清单。
  const statusSelect = section(page, 'v-model="form.block_status_code"', '</el-select>')
  assert.match(statusSelect, /v-for="opt in STAGE_BLOCK_STATUS_OPTIONS"/)
  assert.doesNotMatch(statusSelect, /<el-option :value="40[134]"/, '硬编码状态码不得回流')
  assert.deepEqual(STAGE_BLOCK_STATUS_OPTIONS.map((o) => o.value), [400, 401, 403, 404, 503])
  assert.doesNotMatch(page, /stage-override-status-select/, '退役的选择器不得回流')
})

test('爬虫引擎：字段缺失→默认三项，显式 "[]" 原样保留（全部引擎语义）', () => {
  const detailBlock = section(page, 'geoip_crawler_engines: d.geoip_crawler_engines', 'waf_check_response:')
  assert.match(detailBlock, /d\.geoip_crawler_engines === undefined \|\| d\.geoip_crawler_engines === ''/)
  assert.match(detailBlock, /\['googlebot', 'bingbot', 'baiduspider'\]/)
  assert.doesNotMatch(detailBlock, /length > 0 \?/, '空数组不得再被三引擎兜底改写')
})

// 拦截页「已删除」判定必须基于本次打开取到的权威快照：blockPages 只在 fetchData
// 赋值，本页加载后他端/API 新建的页面会被误判为已删除，并把表单里的
// block_page_id 静默改写成默认页（保存即落库，拦截响应体与归因随之改变）。
test('编辑策略：拦截页列表按本次打开刷新，未取到权威快照时不改写 block_page_id', () => {
  const detail = section(page, 'async function openDialog', 'const handleSave = async')
  assert.match(detail, /await Promise\.all\(\[[\s\S]{0,300}?refreshBlockPages\(openSeq\)/, '打开详情时必须与本次打开并行刷新拦截页列表')
  assert.match(detail, /&& blockPagesFresh\)/, '缺失判定必须只在权威快照落地时成立')
  assert.doesNotMatch(detail, /blockPages\.value\.length > 0 && !blockPages\.value\.some/, '列表非空不等于权威（陈旧快照不得当判据）')
  const refresh = section(page, 'const refreshBlockPages = ', 'async function openDialog')
  assert.match(refresh, /if \(openSeq !== policyDialogOpenSeq\) return false/, '过期响应必须弃用')
  assert.match(refresh, /blockPagesLoaded\.value = true/, '成功即标记快照已落地')
  assert.match(refresh, /return false/, '失败分支必须上报「无权威快照」')
})

test('带外空模式读入不得被静默改写成拦截模式', () => {
  const detail = section(page, 'async function openDialog', 'const handleSave = async')
  assert.match(detail, /ip_acl_mode: d\.ip_acl_mode \?\? ''/, 'ACL 空模式必须原样进入表单，由用户显式处理')
  assert.match(detail, /geoip_mode: d\.geoip_mode \?\? 'off'/, 'GeoIP 缺省只能归一为关闭，不得代填 deny')
  assert.doesNotMatch(detail, /ip_acl_mode: d\.ip_acl_mode \|\| 'allow'|geoip_mode: d\.geoip_mode \|\| 'deny'/)
  assert.doesNotMatch(page, /geoip_mode \?\? 'deny'/, '只读预览同样不得把未知模式展示成拦截')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(page, /geoipMode \|\| t\('app\.security\.policies\.view\.geoModeUnset'\)/, '未知模式必须显性说明')
  assert.ok(code('src/locales/zh/security.ts').includes('未配置模式'), '未知模式原文必须在 zh 母本词条中')
})

test('绑定执行序：暂存上移/下移，保存收尾随批量端点 orders 单事务应用', () => {
  // 策略顺序=执行序（用户裁定）：关联规则行内上移/下移只暂存（bindingOrderEdits），
  // 保存收尾把各规则完整有序 policy_id 列表随批量端点 orders 字段提交——
  // N 条规则一次渲染（逐规则整链 PUT 是 N×渲染+reload 的保存耗时回归，
  // v2.2.0 批量绑定同因已修过一次）；读路径返回 rank 序。
  assert.match(page, /bindingOrderEdits/, '上移/下移必须暂存（随保存统一提交）')
  const tail = section(page, 'const bindResponses', 'const mergedBind')
  assert.match(tail, /bindings\/bulk`[\s\S]{0,400}orders/, '执行序必须随批量端点 orders 单事务提交')
  assert.match(tail, /chunkForBulk\(orderEditedRules\.value/, 'orders 超上限必须分片提交')
  assert.match(tail, /policy_ids|orderedChainPolicyIds\(caddyId\)|mergeChainOrder\(/, 'orders 必须携带完整有序 policy_id 列表')
  // 单规则校验失败进 skipped 不整体拒绝：坏规则保持暂存待重试，好规则即时清标记
  assert.match(tail, /skipped/, 'skipped 必须被消费（坏规则保暂存）')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(可重试口径漂移仍必红)
  assert.match(tail, /t\('app\.security\.policies\.msg\.orderSkipped'/, 'skipped 规则必须有可重试口径')
  assert.ok(code('src/locales/zh/security.ts').includes('这些规则保持「顺序待保存」，重新点击保存可重试'), '可重试口径原文必须在 zh 母本词条中')
  assert.doesNotMatch(tail, /request\.put</, '不得回流逐规则整链 PUT（单事务批量应用）')
  assert.doesNotMatch(page, /batch-block-pages/, '规则级阶段页覆盖写路径已退役')
  // 行内按钮：上移/下移以暂存方式调整本策略在绑定链中的执行序
  assert.match(page, /moveSelfInChain\(\s*row\.caddyId, -1\s*\)/, '上移按钮必须接线暂存移动')
  assert.match(page, /moveSelfInChain\(\s*row\.caddyId, 1\s*\)/, '下移按钮必须接线暂存移动')
  const orderBar = section(page, 'class="bound-rule-order"', '</span>')
  // i18n 后按调用点定位:「顺序待保存」tag 键必须在「上移」按钮键之前（用户验收裁定）
  const tagAt = orderBar.indexOf("t('app.security.policies.bind.orderPending')")
  const upAt = orderBar.indexOf("t('app.security.policies.common.moveUp')")
  assert.ok(tagAt > -1 && upAt > tagAt, '「顺序待保存」提示必须在按钮左侧（用户验收裁定）')
  assert.match(orderBar, /bindingOrderPending\(row\.caddyId\)/)
})

test('CC 防护唯一门：选择器与提交门共用同一谓词，业务 400 不再承诺可重试', () => {
  const editor = code('src/components/SecurityBindingEditor.vue')
  // 同源谓词：规则侧编辑器与策略向导都走 securityStages.hasOtherStage2Binding
  assert.match(editor, /hasOtherStage2Binding\(current, props\.policyId/)
  assert.match(page, /hasOtherStage2Binding,/)

  const meta = section(page, 'const pickerMeta = (rule: Rule)', 'return { chain, selfPos:')
  assert.match(meta, /editorPolicyType\.value === 'stage2'/, '仅阶段 2（CC 防护）策略触发唯一门')
  assert.match(meta, /hasOtherStage2Binding\(existing, editingId\.value/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(meta, /t\('app\.security\.policies\.picker\.blockStage2'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('该规则已绑定其它 CC 防护策略（每规则仅一条），需先解绑'), '唯一门文案原文必须在 zh 母本词条中')

  // 选择器渲染/全选集合必须按 blockReason 判据（原 wouldExceed 只剩条数上限）
  assert.match(page, /:disabled="pickerMeta\(rule\)\.blockReason !== ''"/)
  assert.match(page, /v-if="pickerMeta\(rule\)\.blockReason" class="rule-binding-limit"/)
  assert.match(page, /pickerMeta\(rule\)\.blockReason === ''/)
  assert.doesNotMatch(page, /\.wouldExceed/, '按元信息单一原因判据收敛，不留双口径')

  // 提交门镜像：阶段 2 新增绑定先本地拒绝，不让「策略已落库＋绑定 400」发生
  const gate = section(page, "const stage2Conflict = editorPolicyType.value === 'stage2'", 'if (stage2Conflict.length > 0)')
  assert.match(gate, /hasOtherStage2Binding\(/)
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(page, /t\('app\.security\.policies\.msg\.stage2Conflict'/)
  assert.ok(code('src/locales/zh/security.ts').includes('请先解绑后再关联'), '解绑提示原文必须在 zh 母本词条中')

  // 绑定同步失败分档：结构性 400 不承诺「重试」，其余（网络/5xx）保留幂等重试提示。
  // i18n 后双钉:调用点钉键,zh 母本钉两句原文(分档口径漂移仍必红)
  assert.match(page, /error instanceof ApiRequestError && error\.status === 400/)
  assert.match(page, /\? t\('app\.security\.policies\.msg\.bindRejected'\)\n\s*: t\('app\.security\.policies\.msg\.bindPartialFail'\)/)
  assert.ok(code('src/locales/zh/security.ts').includes('原样重试不会成功'), '400 不承诺重试原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('重新点击保存可重试绑定（幂等）'), '幂等重试提示原文必须在 zh 母本词条中')
})

test('关联规则步骤：说明走标准提示框 + 归属汇总（裸文本长说明退役）', () => {
  const text = code('src/views/security/SecurityPolicies.vue')
  // 长说明收敛为 info-note 标准提示框一句话直白版（用户验收裁定：禁裸文本）。
  // i18n 后双钉:调用点钉键,zh 母本钉原文(任一漂移必红)
  assert.match(text, /info-note-desc">\{\{ t\('app\.security\.policies\.bind\.orderNote'\) \}\}<\/span>/)
  assert.ok(code('src/locales/zh/security.ts').includes('策略按绑定顺序依次触发，先触发的先拦截；顺序调整仅改变触发先后，不影响拦截页归属'), '归属汇总原文必须在 zh 母本词条中')
  assert.doesNotMatch(text, /多策略按绑定顺序依次评估/, '旧裸文本长说明退役')
  assert.doesNotMatch(text, /form-tip-line">多策略按绑定顺序/)
})

test('IP ACL 名单校验只作用于启用态字段（关闭后隐藏的条目不得点名）', () => {
  const validate = section(page, 'const validateIpAclList = (): boolean =>', 'const nextStep')
  assert.match(validate, /if \(form\.value\.ip_acl_enabled\) \{\n\s*const invalidEntry = ipACLList\.value\.find/)
  // 白名单空生效集不再硬阻断（用户裁定 warning-not-block）：校验函数退出门，
  // 保存流改走显性确认（确认后照常保存，与 ipListSaveGuard 先例同形态）
  assert.doesNotMatch(validate, /白名单模式下 IP 列表不能为空/, '空名单不得再在校验函数里硬阻断')
  const confirm = section(page, 'const handleSave = async () => {', 'const payload = buildPolicyPayload(')
  // i18n 后双钉:调用点钉键,zh 母本钉原文(确认文案漂移仍必红)
  assert.match(confirm, /t\('app\.security\.policies\.msg\.emptyAllowConfirm'\)/, '保存流必须先显性确认空名单后果')
  assert.ok(code('src/locales/zh/security.ts').includes('该策略关联的规则将拒绝所有请求，确定继续？'), '空名单确认原文必须在 zh 母本词条中')
  assert.match(confirm, /aclSaveCount\.value === 0/, '确认门只对空生效集触发')
  // 后端 400 门移除由 Go 侧同步落地；此处钉前端不再自设硬阻断即可。
  assert.doesNotMatch(page, /阶段页覆盖|规则级覆盖/, '退役功能文案不得回流')
})
