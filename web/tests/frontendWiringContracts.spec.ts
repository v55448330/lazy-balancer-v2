// 前端基座/设置/安全域的接线验收（每条对应一个可回归的接线点）：
// 死契约删除、表单上限与写侧门对齐、慢车道解耦、会话序号无条件自增、
// 命中索引与手势输入集同源、隐藏谓词的信任侧、大屏层级。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, codeSection, member, repoCode, section, source, webFiles } from './_helpers.ts'

test('个人资料弹框不再保留无人消费的自动聚焦契约', () => {
  const dialog = code('src/components/ProfileDialog.vue')
  assert.doesNotMatch(dialog, /focusField/, 'focusField 全仓零消费方，属残留对外契约')
  assert.doesNotMatch(dialog, /passwordInput\.value\?\.focus\(\)|displayNameInput\.value\?\.focus\(\)/, '自动聚焦分支必须删除')
  // 唯一消费方只传 v-model
  const layout = code('src/components/layout/AppLayout.vue')
  assert.match(layout, /<ProfileDialog v-model="showProfile" \/>/)
})

test('文档钉：表格标签居中的 flex 规则必须记录混合单元格省略号取舍', () => {
  const css = source('src/styles/main.css')
  const rule = section(css, '.el-table .cell:has(.el-tag) {', '}')
  assert.match(rule, /display: inline-flex/, '标签居中形态保持不变')
  const comment = section(css, '/* 表格单元格标签垂直居中', '.el-table .cell:has(.el-tag) {')
  assert.match(comment, /text-overflow 对匿名项不生效|匿名 flex 项|混合单元格/, '必须写明混合单元格失去省略号的取舍')
  assert.match(comment, /tooltip/, '必须写明可发现性（tooltip）不受影响')
})

test('文档钉：策略绑定写路径显式声明「最后写入生效」的并发口径', () => {
  const doc = section(source('src/components/SecurityBindingEditor.vue'), '// 绑定写路径的并发口径', 'const submit = async')
  assert.match(doc, /最后写入生效|后写覆盖前写/, '必须声明无乐观并发护栏')
  assert.match(doc, /版本前置条件|409/, '必须写明根治需要后端前置条件')
  // 绑定端点不接受 expected_updated_at：不得悄悄发送一个后端会忽略的字段
  const submit = section(code('src/components/SecurityBindingEditor.vue'), 'const submit = async', '\n}\n')
  assert.doesNotMatch(submit, /expected_updated_at/, '绑定端点未实现版本前置条件，不得发无用字段')
})

test('表单上限与后端写侧门对齐（证书重签天数 / HTTP 超时）', () => {
  const cert = code('src/views/settings/FreeCertificates.vue')
  assert.match(cert, /cert_renewal_days" :min="1" :max="CERT_RENEWAL_DAYS_MAX"/, '控件上限必须引用单源常量')
  assert.doesNotMatch(cert, /cert_renewal_days[^>]*:max="60"/, '60 只是建议值，不得作为硬上限（会把 API/导入写入的 61-88 静默夹回）')
  const configValues = code('src/utils/configValues.ts')
  assert.match(configValues, /export const CERT_RENEWAL_DAYS_MAX = 88/, '上限常量必须是写侧门同值')
  // 提示文案必须写清 84–88 天的真实后果：控制面已把上限提到写侧门，而扫描侧
  // 对「窗口 > 寿命 − 7 天」的配置会收敛为到期前 7 天并限频告警（旧文案描述的
  // 「反复重签」来自已删除的迟滞实现，会让用户以为窗口越大会越早开始续签）。
  assert.match(cert, /到期前 7 天/, '提示必须写明 84–88 天被收敛为到期前 7 天')
  assert.doesNotMatch(cert, /反复重签/, '不得再用已删除的旧实现形态描述收敛行为')
  // 跨栈钉：后端上界 = 规划寿命 90 − 2
  const certinfo = repoCode('internal/services/certinfo.go')
  assert.match(certinfo, /const CertRenewalLifetimeDays = 90/)
  assert.match(certinfo, /const CertRenewalDaysMax = CertRenewalLifetimeDays - 2/)

  const caddy = code('src/views/settings/CaddyGlobalSettings.vue')
  for (const field of ['http_read_timeout', 'http_write_timeout', 'http_idle_timeout']) {
    const line = caddy.split('\n').find((l) => l.includes(`v-model="settings.${field}"`))
    assert.ok(line, `${field} 控件必须存在`)
    assert.doesNotMatch(line, /:max=/, `${field} 不得硬限 86400——后端写侧门只要求 ≥1，控件夹紧会静默改写合法库值`)
    assert.match(line, /:min="1"/)
  }
  // 提示文案同步：不再是「必须为 1-86400」
  assert.doesNotMatch(caddy, /必须为 1-86400/, '提示文案不得再声称后端不存在的时间上限')
  assert.match(caddy, /必须 ≥1/)
})

test('Dashboard 慢车道健康查询不得阻塞整轮刷新', () => {
  const page = code('src/views/Dashboard.vue')
  assert.match(page, /void fetchRuleHealth\(currentRules, version, roundSignal\)/, '健康查询必须 fire-and-forget（版本守卫已足够）')
  assert.doesNotMatch(page, /await fetchRuleHealth\(currentRules, version, roundSignal\)/, 'await 会把系统指标/流量/连接一起拖慢')
  // 收尾补跑仍在函数内部 await（顺序语义必要）
  assert.match(page, /await fetchRuleHealth\(pending\.rules, pending\.version\)/, '更新版本补跑必须保持串行')
})

test('文档钉：时间戳两族的边界写在 formatDate 文档里', () => {
  const doc = section(source('src/utils/date.ts'), '/**\n * 站内时间戳有两族', 'export const formatDate')
  assert.match(doc, /UTC 存储族/)
  assert.match(doc, /task_runs/, '必须点名禁止面（配置时区墙钟族）')
  assert.match(doc, /格式化为|不得混用|formatDate/, '必须写明入口归属')
})

test('策略向导拦截页步骤纳入引用条目懒加载门', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  const gate = member(page, 'watch([currentStep, ipACLList, ipWhitelist, ipACLListRefs, ipWhitelistRefs], ')
  assert.match(gate, /step !== WIZARD_STEP\.BLOCK_PAGE/, '拦截页能力门消费合并条目数，必须预取引用条目')
})

test('文档钉：信任侧冲突警告的门控位置与注释一致（computed 内）', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  const doc = section(source('src/views/security/SecurityPolicies.vue'), '// 名单生效口径与保存语义对齐', 'const entrySourceSuffix')
  assert.doesNotMatch(doc, /仅模板\s*$/m, '注释不得声称门控只在模板层')
  assert.match(doc, /门控在 computed 内/)
  const alert = section(page, 'const whitelistSectionAlert = computed<string>(', '  if (trust.length === 0)')
  assert.match(alert, /trustEnabledInEditor\.value \? mergeIpEntries/, '实现口径：信任关闭时条目零生效，阶段 0 恒启用')
  assert.match(page, /const trustEnabledInEditor = computed\(\(\) => trustEnabledForPolicyType\(editorPolicyType\.value, ipWhitelistEnabled\.value\)\)/, '告警/预览必须复用保存载荷同一谓词')
  assert.match(page, /ipBlacklistSelf\.value, trustEnabledInEditor\.value\)\)/, 'Step 4 冲突检测的本策略允许侧同样走单源门')
})

// 同一条不变量被两份 spec 逐字重复钉住时，改动要维护两处副本，而任何一侧的
// 失效（切片形态变化、断言被弱化）都不会被另一侧发现——重复的守卫在心理上
// 提供「已覆盖」的错觉。声明级判据只留单源，消费侧各钉自己的面。
test('trustEnabledInEditor 的声明级判据只在一份 spec 里落地', () => {
  const declaration = /const trustEnabledInEditor = computed/
  const holders = webFiles('tests', ['.spec.ts']).filter((file) => declaration.test(code(file)))
  assert.deepEqual(holders, ['tests/frontendWiringContracts.spec.ts'], '声明级判据必须单源（其余 spec 只钉各自的消费面）')
})


test('威胁大屏：攻击弹框层级高于错误条堆叠，且错误条默认点击穿透', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  const toastZ = Number(page.match(/\.toasts \{[^}]*z-index: (\d+)/)?.[1] ?? 0)
  const stackZ = Number(page.match(/\.error-stack \{[^}]*z-index: (\d+)/)?.[1] ?? 0)
  assert.ok(toastZ > stackZ, `攻击弹框必须在错误条之上（toasts=${toastZ}, error-stack=${stackZ}）`)
  const stack = section(page, '.error-stack {', '}')
  assert.match(stack, /pointer-events: none/, '错误条不得拦截其下弹框点击')
  assert.match(page, /\.error-stack \.error-retry \{ pointer-events: auto; \}/, '重试按钮必须可点')
})

test('规则流程弹框会话打开即作废在途证书响应', () => {
  const dialog = code('src/components/RuleFlowDialog.vue')
  const open = member(dialog, 'const onDialogOpen = ')
  assert.match(open, /detailsSeq\+\+[\s\S]*?certSeq\+\+/, '打开时必须无条件自增证书序号（非 TLS 规则也要作废上一会话）')
  // 不钉换行/缩进形状：只要求两件事都在同一成员体内（各自独立断言）
  assert.match(open, /certSeq\+\+/, '自增证书序号必须存在')
  assert.match(open, /detailLoading\.value = false/, '自增必须与其它会话状态重置同处')
})

// ── 安全策略侧补充验收（脚注降级口径 / 拦截页注记类型门 / 列表默认 tab） ──
test('fs96-01 流程弹框阶段 1 脚注降级判定与阶段 0 模式行同源（混合策略不得漏判）', () => {
  const dialog = code('src/components/RuleFlowDialog.vue')
  const footnote = section(dialog, 'const stage1Footnote = ', '\nconst stageSub = (')
  assert.match(footnote, /hasTrustDetectionBinding\(boundIds, props\.policies\)/, '必须复用 trustHitMode 系谓词')
  assert.doesNotMatch(footnote, /policy_type === 'stage0'/, 'mixed 存量信任同样恒 DetectionOnly，等值判断会漏报降级路径')
})

test('fs96-03 拦截页注记类型门先于 block_page_id 判定（阶段 0 无页面概念）', () => {
  const notes = codeSection('src/views/security/SecurityPolicies.vue', 'const blockPageNotes = ', '\n// Step 4 已关联规则的逐条视图')
  const typeGate = notes.indexOf('if (stages.length === 0) return []')
  const unsetGate = notes.indexOf('form.value.block_page_id <= 0')
  assert.ok(typeGate > 0 && unsetGate > 0, '两处门都必须存在')
  assert.ok(typeGate < unsetGate, '阶段 0（stages 为空）必须先返回，否则永远命中「未选择自定义页面」')
  assert.match(notes, /限流拦截返回空响应体 429/, '阶段 2 专属文案不得丢')
})

test('fs96-05 策略列表默认/保存/迁移后 tab 跟随实际类型', () => {
  const page = code('src/views/security/SecurityPolicies.vue')
  const defaults = page.match(/activeTypeTab\.value = pickDefaultPolicyTab\(policyTypeCounts\.value\)/g) ?? []
  assert.equal(defaults.length, 2, '首屏与 tab 消失回落必须共用 pickDefaultPolicyTab')
  assert.match(page, /const savedType = editorPolicyType\.value[\s\S]*?activeTypeTab\.value = savedType/, '保存成功后切到本次保存类型')
  assert.match(page, /activeTypeTab\.value = createdType as SecurityPolicyType/, '迁移成功后切到第一个子策略类型')
  assert.doesNotMatch(page, /if \(!tabs\.some\(\(tab\) => tab\.type === activeTypeTab\.value\)\) activeTypeTab\.value = 'stage1'/, '硬编码回落阶段 1 必须删除')
})
