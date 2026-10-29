// 可访问入口 / 一次性凭据关闭守卫 / 前置门归因 / 横幅样式收敛的回归钉。
//
// 覆盖三族用户可感知缺口：
//   ① 键盘可达：无 href 的 <el-link> 渲染成不进 Tab 序、回车无动作的 <a>
//      （element-plus link 只在 href 存在时渲染 href，也不补 role/tabindex）；
//      锁摘要 popover 内容 teleport 到 body，键盘进不去 → 由锁图标直达流程弹框。
//   ② 一次性凭据：明文密钥/恢复码只此一次下发，ESC/X 不得静默销毁。
//   ③ 前置门归因：数据「没加载出来」不得报成「不存在」；同族横幅间距单源。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { WAF_MODE_TEXT, wafModeLabel } from '../src/utils/securityStages.ts'
import { code, cssDeclarations, openTags, section, webFiles } from './_helpers.ts'

// ── ① 键盘可达：不再有「无 href 的 el-link」散落各处 ──────────────
test('el-link 无 href 一律经 common/AccessibleLink（键盘/读屏可达）', () => {
  const wrapper = 'src/components/common/AccessibleLink.vue'
  const files = webFiles('src', ['.vue'])
  assert.ok(files.length > 40, `扫描面异常（仅 ${files.length} 个 .vue）`)
  const offenders: string[] = []
  for (const file of files) {
    if (file === wrapper) continue
    for (const match of code(file).matchAll(/<el-link\b[^>]*>/g)) {
      if (!/\shref=/.test(match[0])) offenders.push(`${file}: ${match[0].replace(/\s+/g, ' ').slice(0, 80)}`)
    }
  }
  assert.deepEqual(offenders, [], '无 href 的 el-link 键盘不可达——改用 AccessibleLink 或补 href')
})

test('AccessibleLink：role/tabindex/Enter+Space 激活 + 焦点可见', () => {
  const wrapper = code('src/components/common/AccessibleLink.vue')
  assert.match(wrapper, /role="button"/)
  assert.match(wrapper, /tabindex="0"/)
  assert.match(wrapper, /@keydown\.enter\.prevent="activate"/)
  assert.match(wrapper, /@keydown\.space\.prevent="activate"/)
  assert.match(wrapper, /target\.click\(\)/, '键盘激活必须复用调用方的 @click')
  assert.match(code('src/components/common/AccessibleLink.vue'), /\.el-link:focus-visible/)
})

test('AccessibleLink 复用键盘激活去重单源', () => {
  const wrapper = code('src/components/common/AccessibleLink.vue')
  assert.match(wrapper, /import \{ activateOnce \} from '@\/utils\/keyboardActivate'/)
  assert.match(wrapper, /activateOnce\(event, \(\) =>/)
  const activate = section(wrapper, 'const activate = ', '</script>')
  assert.doesNotMatch(activate, /event\.repeat/, '组件不得再保留第二份重复键守卫')
})

test('AccessibleLink：统一浅底，只有 primary/danger 在 hover 时使用主色文字', () => {
  const wrapper = code('src/components/common/AccessibleLink.vue')
  assert.match(wrapper, /withDefaults\(defineProps/)
  assert.match(wrapper, /underline: 'never'/)
  assert.doesNotMatch(wrapper, /readonly underline\?: boolean/)
  // CSS 断言走声明表：属性序/换行重排不假红，缺声明或改值仍红。
  const hover = cssDeclarations(wrapper, '.el-link:hover')
  assert.equal(hover.get('background'), 'var(--el-color-primary-light-9, #ecf5ff)')
  assert.equal(hover.get('text-decoration'), 'none')
  assert.ok(!hover.has('color'), 'info/success/warning/default 必须保留 Element Plus 类型色')
  assert.equal(
    cssDeclarations(wrapper, '.el-link--primary:hover, .el-link--danger:hover').get('color'),
    'var(--el-color-primary, #409eff)',
  )
  assert.equal(
    cssDeclarations(wrapper, '.el-link:active').get('background'),
    'var(--el-color-primary-light-8, #d9ecff)',
  )
})

test('负载均衡规则名 hover 不再覆盖统一样式为下划线', () => {
  const page = code('src/views/Rules.vue')
  const hover = section(page, '.rule-name-link:hover {', '}')
  assert.doesNotMatch(hover, /text-decoration:\s*underline/)
})

test('登录页恢复码切换是真正的可聚焦控件（丢失验证器时的自救入口）', () => {
  const login = code('src/views/Login.vue')
  const links = openTags(login, 'AccessibleLink')
  // 逐属性/逐处理器判定：属性序重排或增删其它属性不假红，入口缺失仍红。
  const recovery = links.find((tag) => tag.includes('type="primary"') && tag.includes('@click="mfaUseRecovery'))
  assert.ok(recovery, '恢复码切换入口缺失')
  assert.ok(recovery.includes('underline="never"'), '恢复码切换入口须为平文本外观（underline=never）')
  assert.ok(
    links.some((tag) => tag.includes('type="info"') && tag.includes('underline="never"') && tag.includes('@click="resetToPasswordStep"')),
    '「返回重新登录」入口缺失',
  )
  assert.match(login, />返回重新登录<\/AccessibleLink>/)
})

test('首屏加载遮罩：读屏可达（status+aria-live）且配色走主题变量', () => {
  const app = code('src/App.vue')
  assert.match(app, /class="app-loading" role="status" aria-live="polite"/, '加载态必须让读屏可感知')
  assert.match(app, /app-loading__spinner" aria-hidden="true"/, '装饰性 spinner 不进读屏朗读流')
  const style = section(app, '.app-loading {', '}')
  assert.match(style, /background: var\(--bg-secondary\)/, '遮罩底色须用主题变量（浅色主题一致）')
  assert.doesNotMatch(section(app, '.app-loading {', '@keyframes'), /#[0-9a-fA-F]{3,8}\b/, '遮罩样式不得新增硬编码色值')
})

// ── ② 一次性凭据：关闭必须确认已保存 ───────────────────────────
test('个人资料 MFA：响应缺 data 显性报错（静默 return = 与「没点上」不可区分）', () => {
  const profile = code('src/components/ProfileDialog.vue')
  // 报错出口收敛到 utils/requireData 单源：缺 data 抛错落到调用方 catch，
  // 文案仍为「响应异常，请重试」；两处（启用 MFA 与「验证并重置」）都必须走守卫。
  const emptyPayload = [...profile.matchAll(/requireData\(res\.data, '响应异常，请重试'\)/g)]
  assert.equal(emptyPayload.length, 2, '启用 MFA 与「验证并重置」两处都必须报错')
  assert.match(profile, /import \{ requireData \} from '@\/utils\/requireData'/)
  assert.doesNotMatch(profile, /if \(!res\.data\) return/, '静默 return 不得残留')
})

test('新建 API 密钥：明文弹框 ESC/X 关闭前二次确认（only-once 明文不可逆丢失）', () => {
  const keys = code('src/views/Keys.vue')
  assert.match(keys, /:before-close="closeCreatedKey"/)
  assert.match(keys, /@closed="createdKey = ''"/, '关闭后仍须清明明文')
  // 确认文案/按钮/「确认后才关闭」收敛进一次性凭据守卫单源；
  // 三处（密钥明文、注册令牌、恢复码）行为由该单源统一保证。
  assert.match(keys, /const closeCreatedKey = createOneTimeSecretCloseGuard\(\{/)
  assert.match(keys, /密钥仅此一次显示，关闭后将无法再次查看/)
  assert.match(keys, /title: '保存密钥'/)
})

// ── ③ 锁摘要 → 流程弹框的键盘入口 ──────────────────────────────
test('规则列表锁图标：Enter/Space 打开流程弹框，不依赖 teleport 内的按钮', () => {
  const rules = code('src/views/Rules.vue')
  const reference = section(rules, '<template #reference>', '</template>')
  assert.match(reference, /role="button"/)
  assert.match(reference, /:aria-label="`查看「\$\{row\.name\}」的安全处理流程`"/)
  // 插槽 row 是 Element Plus 的 DefaultRow（Record<PropertyKey, any>），传给
  // 强类型处理器时带 `as Rule` 断言——断言不影响「收到整行」这一语义。
  assert.match(reference, /@keydown\.enter\.prevent="activateOnce\(\$event, \(\) => openFlowFromLock\(row(?: as [A-Za-z]+)?\)\)"/)
  assert.match(reference, /@keydown\.space\.prevent="activateOnce\(\$event, \(\) => openFlowFromLock\(row(?: as [A-Za-z]+)?\)\)"/, '长按 Enter/Space 不得按系统重复率反复开窗')
  // EP 默认把 Enter/Space 绑成 popover 开关——必须置空，否则同键既开弹框又弹只读面板
  const popover = section(rules, '<el-popover\n                v-if="row.protocol === \'http\'"', 'popper-class="rule-lock-popper"')
  assert.match(popover, /:trigger-keys="\[\]"/)
  assert.match(code('src/views/Rules.vue'), /\.acl-lock-icon:focus-visible \{ outline:/)
})

// ── ④ 动效无障碍 ──────────────────────────────────────────────
test('处理流程弹框：prefers-reduced-motion 关闭循环流动与错峰进场', () => {
  const raw = code('src/components/RuleFlowDialog.vue')
  const media = section(raw, '@media (prefers-reduced-motion: reduce) {', '}\n}')
  assert.match(media, /\.tl-row \{ animation: none; \}/)
  assert.match(media, /\.tl-line \{ animation: none;/, '循环流动线必须停止')
  // 反向：被降级的动画确实存在（否则媒体查询是空转）
  assert.match(raw, /animation: tl-flow-down 0\.7s linear infinite/)
})

// ── ⑤ WAF 模式词单源 ──────────────────────────────────────────
test('WAF 模式词单源：单词表 + 消费方不各自内联、不裸下标查表', () => {
  assert.deepEqual({ ...WAF_MODE_TEXT }, { blocking: '拦截', detection: '检测', custom_only: '仅自定义', off: '关闭' })
  assert.equal(wafModeLabel('blocking'), '拦截')
  assert.equal(wafModeLabel('custom_only'), '仅自定义')
  assert.equal(wafModeLabel('off'), '关闭')
  assert.equal(wafModeLabel('future_mode'), 'future_mode', '未登记 mode 回落原文（fail-visible）')
  assert.equal(wafModeLabel(''), '')
  // 原型键形态（带外改库/备份还原可达）：必须回落原文，不得命中 Object.prototype
  // 上的函数——否则模板插值把函数源码当展示词。
  for (const mode of ['constructor', 'toString', '__proto__', 'valueOf']) {
    assert.equal(wafModeLabel(mode), mode, `${mode} 命中原型链，展示词会变成函数源码`)
  }

  // 任何视图/组件不得再自建 mode→中文 映射表，也不得裸下标查表（原型键直读）；
  // 单源文件本身除外（其查表已过 hasOwn 守卫）。
  const singleSource = 'src/utils/securityStages.ts'
  const offenders: string[] = []
  for (const file of webFiles('src', ['.vue', '.ts'])) {
    if (file === singleSource) continue
    const body = code(file)
    if (/custom_only:\s*'仅自定义/.test(body)) offenders.push(`${file}: 本地 mode 词表`)
    if (/custom_only' ?\? ?'仅自定义规则'/.test(body)) offenders.push(`${file}: 内联「仅自定义规则」`)
    if (/blocking' ?\? ?'阻断'/.test(body)) offenders.push(`${file}: 内联「阻断」`)
    if (/WAF_MODE_TEXT\[/.test(body)) offenders.push(`${file}: 裸下标查表（须走 wafModeLabel）`)
  }
  assert.deepEqual(offenders, [], 'WAF 模式词必须取 securityStages.WAF_MODE_TEXT/wafModeLabel')
  assert.match(code('src/views/security/SecurityPolicies.vue'), /wafModeLabel,/)
  assert.match(code('src/components/events/TriggerDetailDialog.vue'), /wafModeLabel\s*\}\s*from '@\/utils\/securityStages'/)
})

// ── ⑥ 前置门归因：加载失败 ≠ 数据不存在 ────────────────────────
test('ACME 全局设置保存：CA 列表未就绪先报加载态，不误报「默认 CA 不存在」', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  const gate = section(page, 'if (loadingCAProviders.value) {', 'const defaultCA =')
  assert.match(gate, /ElMessage\.warning\('CA 提供商列表加载中，请稍后再保存'\)/)
  assert.match(gate, /if \(caProvidersError\.value\) \{/)
  assert.match(gate, /CA 提供商列表加载失败，请点顶部「立即重试」后再保存/)
  // 顺序：加载态 → 失败态 → 真不存在（误报会推向无从操作的「重新选择」）
  const loadingAt = page.indexOf("CA 提供商列表加载中")
  const errorAt = page.indexOf('CA 提供商列表加载失败')
  const missingAt = page.indexOf('默认 CA 提供商不存在')
  assert.ok(loadingAt > 0 && loadingAt < errorAt && errorAt < missingAt, '前置门顺序漂移')
  // 前置门必须在写请求之前（失败态照发 PUT 等于把误报变成写侧 400）
  assert.ok(errorAt < page.indexOf("request.put('/config', payload)"), '前置门必须早于 PUT /config')
})

test('免费证书：CA 提供商测试先确认再发起写操作', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  // 不得命名为 test：会遮蔽 `node:test` 的 test，用例体内再声明子用例时会得到
  // `TypeError: test is not a function` 而不是断言失败。
  const providerTestBody = section(page, 'const testCAProvider = async', 'const openConfigDialog')
  assert.match(providerTestBody, /await ElMessageBox\.confirm\(/)
  assert.ok(
    providerTestBody.indexOf('await ElMessageBox.confirm(') < providerTestBody.indexOf('testingCAId.value = p.id'),
    '确认必须先于测试 loading 与请求',
  )
})

test('免费证书：编辑 CA 与 DNS 提供商弹框保存前先确认', () => {
  const page = code('src/views/settings/FreeCertificates.vue')
  for (const [fn, saving] of [['saveCAProvider', 'savingCA'], ['saveConfig', 'savingConfig']] as const) {
    const body = section(page, `const ${fn} = async`, '\nconst ')
    const confirmAt = body.indexOf('await ElMessageBox.confirm(')
    assert.ok(confirmAt > 0, `${fn} 缺保存确认`)
    assert.ok(confirmAt < body.indexOf(`${saving}.value = true`), `${fn} 确认必须早于 saving/请求`)
  }
})

// ── ⑦ 错误横幅样式单源（mb-5 与共享类叠加是死重量） ──────────────
test('错误横幅：统一 polling-error-alert error-banner，el-alert 不再挂 mb-5', () => {
  for (const file of [
    'src/views/security/SecurityRules.vue',
    'src/views/security/SecurityEvents.vue',
    'src/views/security/SecurityOverview.vue',
  ]) {
    const body = code(file)
    assert.match(body, /class="polling-error-alert error-banner"/, `${file} 未用共享横幅类`)
    // 只约束错误横幅：同页 el-card/el-row 的 mb-5 是行间距用途，属正常
    assert.doesNotMatch(body, /class="(?:error-banner mb-5|mb-5 error-banner)"/, `${file} 横幅仍有 mb-5 叠加`)
  }
  // 全局：el-alert 不得再挂 mb-5（同族新增横幅不许重新发明间距）
  const offenders: string[] = []
  for (const file of webFiles('src', ['.vue'])) {
    for (const match of code(file).matchAll(/<el-alert\b[^>]*>/g)) {
      if (/\bmb-5\b/.test(match[0])) offenders.push(file)
    }
  }
  assert.deepEqual([...new Set(offenders)], [], 'el-alert 的间距由 polling-error-alert 单源承担')
  const css = code('src/styles/main.css')
  assert.equal(cssDeclarations(css, '.polling-error-alert').get('margin-bottom'), '16px')
  assert.equal(cssDeclarations(css, '.mb-5').get('margin-bottom'), '20px', 'mb-5 仍用于 el-row/el-card 行间距')
})
