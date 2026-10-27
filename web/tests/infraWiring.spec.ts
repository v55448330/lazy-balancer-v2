// 前端基础设施接线的回归钉（页面键/导航文案/轮询 API/弹窗序号/阶段副标题/
// CRS 全量分页/高亮策略）：这些是应用外壳与共享组件的行为契约。真实前提：
// node --test 无 .vue 装载器且模板依赖 element-plus 全局组件——不可挂载，
// 故以「限段 + 调用点」文本钉覆盖。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section, source } from './_helpers.ts'
import { escapeHtml, withCodeTrailingBreak } from '../src/utils/escape.ts'
import { PAGE_IDS } from '../src/utils/pageIds.ts'
import { SETTINGS_TAB_IDS } from '../src/utils/settingsPages.ts'

test('设置页键单源：PAGE_IDS 的 settings 段由 SETTINGS_TAB_IDS 派生', () => {
  const derived = SETTINGS_TAB_IDS.map((tab) => `settings-${tab}`)
  assert.deepEqual(
    (PAGE_IDS as readonly string[]).filter((id) => id.startsWith('settings-')),
    derived,
    'PAGE_IDS 的 settings 段必须与 SETTINGS_TAB_IDS 同序同集',
  )
  assert.deepEqual(
    SETTINGS_TAB_IDS.filter((tab) => !(PAGE_IDS as readonly string[]).includes(`settings-${tab}`)),
    [],
    '每个设置分页键都必须可用于深链/currentPage',
  )
  const pageIds = code('src/utils/pageIds.ts')
  assert.match(pageIds, /SETTINGS_TAB_IDS\.map\(\(tab\) => `settings-\$\{tab\}`/, '派生关系不得回退到手写清单')
  assert.doesNotMatch(pageIds, /'settings-basic'/, '不得再手写 settings 页键')
})

test('App.vue 设置分支由 settingsTabOfPage 派生（新增分页不会静默落空页）', () => {
  const app = code('src/App.vue')
  assert.match(app, /import \{ settingsTabOfPage \} from '@\/utils\/settingsPages'/)
  assert.match(app, /<Settings v-else-if="settingsTabOfPage\(currentPage\) !== null" \/>/)
  assert.doesNotMatch(app, /currentPage === 'settings-basic' \|\|/, '不得回退为逐键字面量分支')
})

test('侧栏菜单文案与面包屑同源：模板取 NAV_LABELS，pageTitle 由 NAV_ITEMS 派生', () => {
  const layout = code('src/components/layout/AppLayout.vue')
  const nav = section(layout, 'const NAV_ITEMS', 'const settingsPageTitles')
  for (const id of [
    'dashboard',
    'rules',
    'security-overview',
    'security-policies',
    'security-rules',
    'security-block-pages',
    'security-events',
    'caddy',
    'users',
    'audit-log',
  ]) {
    assert.match(nav, new RegExp(`id: '${id}'`), `NAV_ITEMS 缺 ${id}`)
  }
  const menu = section(layout, '<el-menu', '</el-menu>')
  // 菜单标题必须插值取值（字面量会在改名时与面包屑分叉）
  assert.match(menu, /\{\{ NAV_LABELS\.rules \}\}/)
  assert.match(menu, /\{\{ NAV_LABELS\['security-events'\] \}\}/)
  assert.match(menu, /\{\{ NAV_LABELS\['settings-basic'\] \}\}/)
  assert.doesNotMatch(menu, /<template #title>负载均衡<\/template>/, '菜单文案不得再写字面量')
  assert.doesNotMatch(menu, /<template #title>安全总览<\/template>/, '菜单文案不得再写字面量')
  // 面包屑由同一张表派生（含分组前缀）
  assert.match(layout, /item\.parent \? `\$\{item\.parent\} \/ \$\{item\.label\}` : item\.label/)
})

test('文档钉：轮询诊断 API 与生产守卫分离（无消费面必须标注用途）', () => {
  // usePollingTask.isDisposed 生产零消费、由 pollingSignal 用例验证中止终态；
  // 保留时必须有明确标注，避免读者误以为有生产调用方。
  // 文档钉（断言对象是注释文字）：改用 raw 视图读标注，符号存在性另由 code 视图钉。
  const taskDoc = source('src/composables/usePollingTask.ts')
  assert.match(taskDoc, /诊断\/测试用[\s\S]{0,80}isDisposed/, 'isDisposed 必须标注为诊断/测试用')
  assert.match(code('src/composables/usePollingTask.ts'), /isDisposed/, 'isDisposed 必须存在')
  const flightDoc = source('src/utils/sessionSingleFlight.ts')
  const requestBlock = section(flightDoc, 'interface SessionSingleFlight', '\n}')
  assert.match(requestBlock, /诊断\/测试用[\s\S]*requestedSession/)
  assert.match(requestBlock, /诊断\/测试用[\s\S]*isInflight/)
})

test('useVisibilityIntervals：无 window 时不启动间隔', () => {
  // 剥注释视图：守卫信号是 `win === undefined) return`，注释化守卫不得继续满足断言。
  const vis = code('src/composables/useVisibilityIntervals.ts')
  // 不再断言注释措辞（注释改写即红且不守护行为）；退化行为由下方实现断言独立
  // 成立：缺 window 直接返回、不登记定时器。
  const startTimers = member(vis, 'const startTimers')
  assert.match(startTimers, /win === undefined\) return/, '缺 window 必须直接返回（不得空转登记定时器）')
})

test('弹窗会话序号用普通变量（无响应式消费）', () => {
  const dialog = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(dialog, /let customRuleSeq = 0/)
  assert.match(dialog, /const seq = \+\+customRuleSeq/)
  assert.match(dialog, /if \(seq !== customRuleSeq\) return/)
  assert.doesNotMatch(dialog, /customRuleSeq\.value/, '不得残留 ref .value 访问')
})

test('阶段 0 副标题：空 groups 不得误报「保留检测记录」', () => {
  const dialog = code('src/components/RuleFlowDialog.vue')
  const subtitle = section(dialog, 'const stageZeroSubtitle', 'const policyTypeOf')
  assert.match(subtitle, /if \(states\.length === 0\) return '未启用'/)
  // 该分支必须先于 every(Boolean)（空数组 every 恒真）
  assert.ok(
    subtitle.indexOf('states.length === 0') < subtitle.indexOf('states.every(Boolean)'),
    '空数组判定必须先于 every(Boolean)',
  )
})

test('CRS 规则清单分页取全量（超 50 文件不再静默回退裸组码）', () => {
  // 取全量实现单源在 utils/crsRuleFiles：流程弹框与策略页两处消费
  // （策略页原只取第 1 页，>50 文件时组会被误判「已无此规则组」）。
  const fetcher = code('src/utils/crsRuleFiles.ts')
  assert.match(fetcher, /page_size=\$\{CRS_RULE_PAGE_SIZE\}&page=\$\{page\}/, '必须带 page 参数循环')
  assert.match(fetcher, /rules\.length < CRS_RULE_PAGE_SIZE\) break/, '不足一页即收敛')
  assert.match(fetcher, /all\.length >= total\) break/, '按 total 收敛')
  const dialog = code('src/components/RuleFlowDialog.vue')
  assert.match(dialog, /import \{ fetchAllCrsRuleFiles \} from '@\/utils\/crsRuleFiles'/)
  const details = section(dialog, 'const ensureDetails', 'const togglePolicyDetail')
  assert.match(details, /fetchAllCrsRuleFiles\(\)/)
  assert.doesNotMatch(details, /\/security\/crs\/rules\?page_size=50`/, '不得再单页硬编码')
  const policies = code('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /import \{ fetchAllCrsRuleFiles \} from '@\/utils\/crsRuleFiles'/)
  assert.doesNotMatch(policies, /\/security\/crs\/rules\?page_size=50/, '策略页不得再只取第一页')
})

test('语法高亮：首帧转义文本 + 停顿后高亮（与 CodeEditor 同策略）', () => {
  const highlight = code('src/components/SyntaxHighlight.vue')
  assert.doesNotMatch(highlight, /computed\(\(\) => highlightCode/, '不得在渲染期同步全文高亮')
  assert.match(highlight, /shallowRef\(escapeHtml\(props\.content\)\)/, '首帧必须是转义文本（v-html 注入面）')
  const watcher = section(highlight, 'watchDebounced(', 'maxWait: 500')
  assert.match(watcher, /debounce: 160/)
  assert.match(highlight, /maxWait: 500/)
  assert.match(highlight, /highlighted\.value = highlightCode\(content, language\)/)
})

test('代码编辑器首帧与键入即时回显：转义纯文本兜底，Prism 高亮随后覆盖', () => {
  const editor = code('src/components/CodeEditor.vue')
  // textarea 的文字是透明的，屏幕上可见文本全部来自高亮层：首帧若留空、键入若
  // 只 emit 不回显，字符要等到下一轮防抖（最长 500ms）才出现。
  assert.match(
    editor,
    /shallowRef\(withCodeTrailingBreak\(escapeHtml\(props\.modelValue\), props\.modelValue\)\)/,
    '首帧高亮层必须是转义纯文本（既回显又守住 v-html 注入面）',
  )
  const onInput = member(editor, 'const onInput = (e: Event) =>')
  const echoed = onInput.indexOf('highlighted.value = withCodeTrailingBreak(escapeHtml(value), value)')
  const emitted = onInput.indexOf("emit('update:modelValue', value)")
  assert.ok(echoed > 0, '键入必须同步写入转义纯文本')
  assert.ok(emitted > echoed, '兜底写入先于 emit（父级重渲染前高亮层已有字符）')
  // 尾换行补 `<br>` 收敛到单源：组件内不再各自拼字符串
  assert.match(
    editor,
    /highlighted\.value = withCodeTrailingBreak\(highlightCode\(props\.modelValue, props\.language\), props\.modelValue\)/,
    '防抖高亮同样走 withCodeTrailingBreak',
  )
  assert.doesNotMatch(editor, /html \+ '<br>'/, '不得在组件内拼尾换行 `<br>`')
  assert.match(editor, /import \{ escapeHtml, withCodeTrailingBreak \} from '@\/utils\/escape'/)
})

test('尾换行补齐与转义的实际行为（代码块 v-html 的注入面单源）', () => {
  assert.equal(escapeHtml('<b>&"x"\'</b>'), '&lt;b&gt;&amp;&quot;x&quot;&#39;&lt;/b&gt;')
  assert.equal(withCodeTrailingBreak('A', 'x\n'), 'A<br>', '源码以换行结尾时高亮层补一个 <br>（否则末行错位）')
  assert.equal(withCodeTrailingBreak('A', 'x'), 'A')
  // 补齐作用在已转义/已高亮的 HTML 上：不得触发二次转义或把 `<br>` 也转义掉
  assert.equal(withCodeTrailingBreak(escapeHtml('<i>\n'), '<i>\n'), '&lt;i&gt;\n<br>')
})
