import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, cssDeclarations, enclosingOpenTag, section } from './_helpers.ts'

test('任务监控：KPI 不再显示证书工作项括注，筛选组右对齐，操作列保持单行', () => {
  const page = code('src/views/settings/TaskMonitor.vue')
  assert.doesNotMatch(page, /（不含证书工作项）|（含证书工作项）/)
  assert.match(page, /<div class="tm-filter-group">/)
  assert.match(page, /class-name="tm-op-cell"/)
  // 样式按「声明集」判定：单行整串或「首个 } 收尾」的切片在换行重排、增删声明、
  // 属性顺序调整时都会假红/截断，而界面没变（声明集与排版形态无关）。
  assert.deepEqual(
    Object.fromEntries(cssDeclarations(page, '.tm-filter-group')),
    { display: 'flex', 'align-items': 'center', gap: '10px', 'margin-left': 'auto' },
    '筛选组必须靠右对齐并单行排布',
  )
  const opCell = cssDeclarations(page, ':deep(.tm-nowrap-table .tm-op-cell .cell)')
  assert.equal(opCell.get('display'), 'flex')
  assert.equal(opCell.get('flex-wrap'), 'nowrap', '操作列必须保持单行（换行会把每行撑高）')
  assert.equal(
    cssDeclarations(page, ':deep(.tm-nowrap-table .tm-op-cell .el-button)').get('margin-left'),
    '0',
    '操作按钮不得再左缩进（否则单行也会溢出）',
  )
  // 「运行」按钮的 tooltip 必须只在有冷却原因时才出现（`:disabled` 门）：
  // 恒定出现的空 tooltip 会吞掉悬停/焦点提示。按标签配对判定包裹关系，
  // 不用 `[\s\S]{0,300}` 这类距离型正则——标记一变长它就可能恒真（永远放行）。
  const runs = [...page.matchAll(/<el-button\b(?:[^>"']|"[^"]*"|'[^']*')*>运行<\/el-button>/g)]
  assert.ok(runs.length > 0, '前置：「运行」按钮必须存在（否则本断言空转）')
  for (const run of runs) {
    const tooltip = enclosingOpenTag(page, 'el-tooltip', run.index)
    assert.ok(tooltip !== null, `「运行」按钮必须在冷却提示 tooltip 内：${run[0]}`)
    assert.match(tooltip, /v-if="row\.triggerable"/, `「运行」tooltip 必须按可用性渲染：${tooltip}`)
    assert.match(tooltip, /:disabled="[^"]*runCooldownReason\(/, `tooltip 必须按冷却原因条件化（否则永远显示空提示）：${tooltip}`)
  }
})

test('安全总览 Top10 源 IP 展示近 10 分钟/近 1 小时/近 24 小时频率', () => {
  const page = code('src/views/security/SecurityOverview.vue')
  // 按字段逐个判定（后端响应字段名即契约）：单行整串钉在格式化/加字段/加可选
  // 标记时即假红，而列的绑定关系没变。
  const topIp = section(page, 'interface TopIP', '}')
  for (const field of ['recent_10m', 'recent_1h', 'recent_24h']) {
    assert.match(topIp, new RegExp(`\\b${field}\\??:\\s*number\\b`), `TopIP 必须声明后端字段 ${field}`)
  }
  assert.doesNotMatch(page, /prop="frequency"/)
  // i18n 后双钉:列头调用点钉键,zh 母本钉原文(列绑定关系漂移仍必红)
  assert.match(page, /prop="blocked" :label="t\('app\.security\.overview\.status\.blocked'\)" width="100"/)
  assert.match(page, /prop="detected" :label="t\('app\.security\.overview\.status\.detected'\)" width="100"/)
  assert.match(page, /prop="recent_10m" :label="t\('app\.security\.overview\.topIps\.colRecent10m'\)" width="120"/)
  assert.match(page, /prop="recent_1h" :label="t\('app\.security\.overview\.topIps\.colRecent1h'\)" width="128"/)
  assert.match(page, /prop="recent_24h" :label="t\('app\.security\.overview\.topIps\.colRecent24h'\)" width="110"/, '近 24 小时列（用户要求 110 宽）')
  assert.ok(code('src/locales/zh/security.ts').includes('"zh": "近10分钟"'), '近10分钟列头原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('"zh": "近1小时"'), '近1小时列头原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('"zh": "近24小时"'), '近24小时列头原文必须在 zh 母本词条中')
  // 新增列后不得整体撑破表格：IP 地址与攻击类型让宽（列头已抽词,调用点钉键）
  assert.match(page, /:label="t\('app\.security\.overview\.topIps\.colIp'\)" min-width="160"/, 'IP 地址列让宽到 160（原 200）')
  assert.match(page, /:label="t\('app\.security\.overview\.topIps\.colAttackType'\)" min-width="140"/, '攻击类型列让宽到 140（原 180）')
  assert.ok(code('src/locales/zh/security.ts').includes('"zh": "IP 地址"'), 'IP 地址列头原文必须在 zh 母本词条中')
})

test('策略向导 WAF 步骤：排除行撑满内容列，记录请求体警示条对齐控件列（2026-11-03 用户验收反馈）', () => {
  const page = code('src/views/security/SecurityPolicies.vue')

  // 1) 排除规则行编辑器外层容器必须撑满表单内容列：el-form-item__content 是 flex
  //    容器，裸 div 子项收缩到内容自然宽（旧行 ~1030px，比同步骤全宽控件窄）。
  //    宽度机制与同步骤全宽控件同源（width:100% 填内容列，不写死 px）。
  assert.match(page, /<div class="exclusion-body">/, '排除编辑器必须有撑满容器类')
  assert.equal(cssDeclarations(page, '.exclusion-body').get('width'), '100%', '排除容器必须撑满内容列')
  assert.equal(cssDeclarations(page, '.exclusion-body').get('min-width'), '0', 'flex 子项收缩防溢出')

  // 2) 记录请求体警示条必须挂在「记录请求体」带标签表单项内（EP 表单 flex 行中
  //    无标签项内容从行首起渲染，比控件列宽 ~100px、左缘贴弹框内容边）——
  //    移入带标签项后宽度自然对齐控件列；样式主体走全局 info-note-bar（padding
  //    8px 12px 由全局类提供，禁止本地重定义）。
  //    i18n 后表单项标签/警示文案抽词:调用点钉键,zh 母本钉原文(任一漂移必红)
  const item = section(page, ':label="t(\'app.security.policies.waf.logRequestBody\')"', '</el-form-item>')
  assert.match(item, /<el-switch v-model="form\.log_request_body"/, '开关必须仍在原表单项')
  assert.match(item, /class="form-tip-line"/, '控件说明行必须保留')
  assert.match(item, /v-if="form\.log_request_body"[^>]*class="info-note-bar form-item-note-bar"/, '警示条必须移入带标签表单项内')
  assert.match(item, /t\('app\.security\.policies\.waf\.logRequestBodyWarn'\)/, '警示文案必须保留')
  assert.ok(code('src/locales/zh/security.ts').includes('"zh": "记录请求体"'), '表单项标签原文必须在 zh 母本词条中')
  assert.ok(code('src/locales/zh/security.ts').includes('请仅在排障期间开启'), '警示文案原文必须在 zh 母本词条中')
  // 全局规范不被局部覆写：本文件不得重定义 info-note-bar 的盒模型
  assert.doesNotMatch(page, /\.info-note-bar[^{]*\{[^}]*padding/, 'info-note-bar 内边距必须走全局规范，禁局部覆写')
  assert.equal(cssDeclarations(page, '.form-item-note-bar').get('width'), '100%', '警示条必须撑满控件列')
})
