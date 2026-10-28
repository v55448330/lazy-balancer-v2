// 规则库展示单源验收
//   IP 地理库「未安装」不得再显示「已最新/正常」——状态/健康标签显式表达
//   SecurityRules 与 SecurityOverview 的聚合/状态映射单源，空源列表两端同结论
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

import {
  crsRuleCountLabel,
  libraryHealthTag,
  libraryScheduleError,
  librarySourceHealthTag,
  libraryStatusLabel,
  libraryStatusTagType,
  summarizeLibrarySources,
} from '../src/utils/securityLibraries.ts'

test('状态词表：缺失/未安装统一「未安装」、未更新不再伪装为已最新', () => {
  assert.equal(libraryStatusLabel('not-installed'), '未安装')
  // 文件缺失与未安装的用户可见词同一（版本列 2026-09-24 裁定用词），
  // 两者区别只由色调承载：缺失=danger、未安装=info。
  assert.equal(libraryStatusLabel('missing'), '未安装')
  assert.equal(libraryStatusLabel('never'), '未更新')
  assert.notEqual(libraryStatusLabel('not-installed'), libraryStatusLabel('idle'))
  assert.equal(libraryStatusTagType('not-installed'), 'info')
  assert.equal(libraryStatusTagType('missing'), 'danger')
  assert.equal(libraryStatusTagType('failed'), 'danger')
  assert.equal(libraryStatusTagType('success'), 'success')
  // 同族：后端持久 cancelled 状态不得在状态列漏成英文原词
  assert.equal(libraryStatusLabel('cancelled'), '已取消')
  assert.equal(libraryStatusTagType('cancelled'), 'info')
})

test('多源聚合：空源列表统一为 never（两页面不再一处已最新一处无标签）', () => {
  const summary = summarizeLibrarySources([])
  assert.equal(summary.status, 'never')
  assert.equal(summary.latestVersion, '')
  assert.equal(summary.totalEntries, 0)
  assert.equal(summary.lastChecked, '—')
  assert.equal(summary.nextUpdate, '—')
  assert.equal(libraryStatusLabel(summary.status), '未更新')
})

test('多源聚合：状态优先级 更新中>失败>成功>未更新', () => {
  const base = { version: '2026.10.01', update_status: 'success', entry_count: 2 }
  assert.equal(summarizeLibrarySources([base, { ...base, update_status: 'failed' }]).status, 'failed')
  assert.equal(summarizeLibrarySources([base, { ...base, update_status: 'running' }]).status, 'running')
  assert.equal(summarizeLibrarySources([base]).status, 'success')
})

test('多源聚合：关闭源（update_enabled=false）→ disabled，不沿用历史失败/排程', () => {
  // disabled 分支与 libraryStatusTagType('disabled') 此前无覆盖。
  const base = { version: '2026.10.01', update_status: 'failed', entry_count: 3, last_checked: '2026-10-01', next_update: '2026-11-01' }
  const summary = summarizeLibrarySources([{ ...base, update_enabled: false }])
  assert.equal(summary.status, 'disabled', '全部源已关闭时不得沿用关闭前的 failed')
  assert.equal(libraryStatusLabel(summary.status), '已关闭')
  assert.equal(libraryStatusTagType(summary.status), 'info')
  assert.equal(summary.nextUpdate, '—', '关闭源不参与下次排程')
  assert.equal(summary.latestVersion, '2026.10.01', '已装版本仍展示')
  assert.equal(summary.totalEntries, 3)
  // 部分关闭：历史失败不再计入聚合失败面
  const mixed = summarizeLibrarySources([
    { ...base, update_enabled: false },
    { ...base, update_status: 'success', next_update: '2026-12-01' },
  ])
  assert.equal(mixed.status, 'success', '关闭源的历史失败不得污染聚合状态')
  assert.equal(mixed.nextUpdate, '2026-12-01')
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [{ update_status: 'failed', update_enabled: false }, { update_status: 'success' }], false),
    { label: '威胁情报库 · 正常', type: 'success' },
  )
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [{ update_status: 'success', update_enabled: false }], false),
    { label: '威胁情报库 · 已关闭', type: 'info' },
  )
})

test('多源聚合：版本取最近、条目求和、日期取两端', () => {
  const summary = summarizeLibrarySources([
    { version: '2026.09.01', update_status: 'success', entry_count: 10, last_checked: '2026-09-01', next_update: '2026-10-01' },
    { version: '2026.10.15', update_status: 'success', entry_count: 5, last_checked: '2026-10-15', next_update: '2026-10-20' },
  ])
  assert.equal(summary.latestVersion, '2026.10.15')
  assert.equal(summary.totalEntries, 15)
  assert.equal(summary.lastChecked, '2026-10-15')
  assert.equal(summary.nextUpdate, '2026-10-01')
})

test('单库健康标签：IP 地理库未安装 → 未安装警示（不再「正常」）', () => {
  const tag = libraryHealthTag('IP 地理库', { loadError: false, available: true, status: 'not-installed' })
  assert.deepEqual(tag, { label: 'IP 地理库 · 未安装', type: 'warning' })
  assert.deepEqual(
    libraryHealthTag('IP 地理库', { loadError: true, available: true, status: 'failed' }),
    { label: 'IP 地理库 · 加载失败', type: 'danger' },
  )
  assert.deepEqual(
    libraryHealthTag('IP 地理库', { loadError: false, available: false, status: 'missing' }),
    { label: 'IP 地理库 · 未安装', type: 'danger' },
  )
  assert.deepEqual(
    libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: 'success' }),
    { label: 'CRS 规则库 · 正常', type: 'success' },
  )
})

test('多源库健康标签：未配置源不再显示正常', () => {
  assert.deepEqual(librarySourceHealthTag('威胁情报库', [], false), { label: '威胁情报库 · 未配置', type: 'warning' })
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [{ update_status: 'failed' }, { update_status: 'success' }], false),
    { label: '威胁情报库 · 1 源更新失败', type: 'warning' },
  )
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [{ update_status: 'success' }], false),
    { label: '威胁情报库 · 正常', type: 'success' },
  )
})

test('健康标签加载三态：首次响应落地前显示「加载中」，不得冒充「正常」', () => {
  // 首屏窗口：初值 available:true/status:'' 不代表已确认正常
  assert.deepEqual(
    libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: '', loaded: false }),
    { label: 'CRS 规则库 · 加载中', type: 'info' },
  )
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [], false, false),
    { label: '威胁情报库 · 加载中', type: 'info' },
  )
  // loaded 缺省=true：既有调用方（含 SecurityOverview）口径不变
  assert.deepEqual(
    libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: 'success' }),
    { label: 'CRS 规则库 · 正常', type: 'success' },
  )
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [], false),
    { label: '威胁情报库 · 未配置', type: 'warning' },
  )
})

test('单库健康标签：持久 update_status 的失败/进行中/关闭态不得伪装为正常', () => {
  // 后端 update_status 可为 failed（更新失败落库）；同卡状态列已据此显示「更新失败」，
  // 卡头此前一律绿「正常」——自相矛盾。
  assert.deepEqual(
    libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: 'failed' }),
    { label: 'CRS 规则库 · 更新失败', type: 'danger' },
  )
  // 活动期 overlay：checking/downloading/installing/reloading/running → warning
  for (const status of ['checking', 'downloading', 'installing', 'reloading', 'running']) {
    const tag = libraryHealthTag('IP 地理库', { loadError: false, available: true, status })
    assert.equal(tag.type, 'warning', `${status} 必须为进行中警示`)
    assert.match(tag.label, /^IP 地理库 · /)
  }
  assert.deepEqual(
    libraryHealthTag('IP 地理库', { loadError: false, available: true, status: 'running' }),
    { label: 'IP 地理库 · 更新中', type: 'warning' },
  )
  // 已关闭/已取消是独立态，不是正常
  assert.deepEqual(
    libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: 'disabled' }),
    { label: 'CRS 规则库 · 已关闭', type: 'info' },
  )
  assert.deepEqual(
    libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: 'cancelled' }),
    { label: 'CRS 规则库 · 已取消', type: 'info' },
  )
  // 成功/idle/空状态仍为正常（idle 与后端「无活动任务」语义一致）
  for (const status of ['success', 'idle', '']) {
    assert.deepEqual(
      libraryHealthTag('CRS 规则库', { loadError: false, available: true, status }),
      { label: 'CRS 规则库 · 正常', type: 'success' },
    )
  }
  // 未知状态词 fail-visible（保留原词 + 状态列同源色调），不静默归正常
  const unknown = libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: '下载失败' })
  assert.equal(unknown.type, 'danger')
})

test('CRS 数量列是规则条数，不是文件数', () => {
  assert.equal(crsRuleCountLabel(832), '832 条规则')
  assert.equal(crsRuleCountLabel(1234), '1,234 条规则')
  assert.equal(crsRuleCountLabel(1234567), '1,234,567 条规则', '千分位必须逐级分组')
  // 缺失/0 不冒充「0 条规则已就绪」
  assert.equal(crsRuleCountLabel(0), '—')
  assert.equal(crsRuleCountLabel(undefined), '—')
})

test('数量文案不随宿主 locale 漂移（千分位固定，不消费 toLocaleString 的默认 locale）', () => {
  // 默认 locale 由 LC_ALL/LANG 决定：de_DE 下 `(1234).toLocaleString()` 给
  // '1.234'、fr_FR 给窄空格——同一份代码在不同开发机/CI 上显示不同，断言也假红。
  // 这里换一个子进程用 de_DE 重跑真实实现，进程内改不了 Intl 默认 locale。
  const probe = execFileSync(
    process.execPath,
    ['--input-type=module', '-e', [
      "import { crsRuleCountLabel } from './src/utils/securityLibraries.ts'",
      'process.stdout.write(crsRuleCountLabel(1234))',
    ].join('\n')],
    {
      cwd: new URL('..', import.meta.url),
      env: { ...process.env, LC_ALL: 'de_DE.UTF-8', LANG: 'de_DE.UTF-8', LANGUAGE: 'de_DE' },
      encoding: 'utf8',
    },
  )
  assert.equal(probe, '1,234 条规则', 'de_DE 宿主下必须仍是固定形态（toLocaleString 会给 1.234）')
})

// 规则库「定时更新」保存前校验：时间被清空时必须显式拒绝——原实现
// 静默回落 04:00，输入框显示空、落库却是 04:00（可观察行为与输入不一致）。
test('定时更新校验：空时间拒绝保存，不静默代填 04:00', () => {
  assert.equal(libraryScheduleError([1], null), '请选择时间')
  assert.equal(libraryScheduleError([1], ''), '请选择时间')
  assert.equal(libraryScheduleError([], '04:00'), '至少选择一天')
  assert.equal(libraryScheduleError([], ''), '至少选择一天', '两项都缺失时先提示未选星期（原行为）')
  assert.equal(libraryScheduleError([1, 3], '04:00'), null)
  assert.equal(libraryScheduleError([7], '23:59'), null)
})

test('零源多源库占位行状态：未配置（与卡头健康标签同词）', () => {
  assert.equal(libraryStatusLabel('not-configured'), '未配置')
  assert.equal(libraryStatusTagType('not-configured'), 'info')
  // 空串仍是空文案（调用方以 v-if 守卫，不渲染空标签）
  assert.equal(libraryStatusLabel(''), '')
})

// 状态词表是普通对象：直接下标会让 'constructor'/'toString' 取到原型链上的
// 函数（真值）并当标签返回，状态列渲染出函数而非原文。
test('原型链键不得冒充词表命中：返回状态原文而非函数', () => {
  for (const status of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__']) {
    const label: unknown = libraryStatusLabel(status)
    assert.equal(typeof label, 'string', `${status} 不得返回函数`)
    assert.equal(label, status, `${status} 未登记 → 原样回显`)
  }
})

// 跨栈共享夹具：与 Go internal/services 的 latestSourceVersion 同读一份
// （web/tests/fixtures/library-aggregate.tsv）。两端各写一套空值过滤曾让
// 纯空白版本分叉——后端 trim 后跳过（报未更新）、前端 !!v 视为有值（报已最新）。
test('多源聚合：跨栈共享夹具（Go latestSourceVersion 同源）', () => {
  const fixture = readFileSync(new URL('./fixtures/library-aggregate.tsv', import.meta.url), 'utf8')
  let checked = 0
  for (const [index, line] of fixture.split('\n').entries()) {
    if (line.startsWith('#') || line.trim() === '') continue
    const fields = line.split('\t')
    assert.equal(fields.length, 4, `夹具第 ${index + 1} 行字段数`)
    const rawVersions = fields[1] as string
    const versions = rawVersions === ''
      ? []
      : rawVersions.split(';').map((token) => (token === '<empty>' ? '' : token === '<blank>' ? ' ' : token))
    const summary = summarizeLibrarySources(versions.map((version) => ({ version, update_status: 'idle' })))
    assert.equal(
      summary.latestVersion,
      fields[2],
      `夹具第 ${index + 1} 行 latestVersion：纯空白版本必须与后端一样在 trim 后跳过`,
    )
    assert.equal(summary.status, fields[3], `夹具第 ${index + 1} 行 status`)
    checked++
  }
  assert.ok(checked > 0, '跨栈聚合夹具为空')
})

// version 是可选列（API 行可缺该键）：缺省与空串同口径——不参与聚合，
// 不得因 undefined 落进比较器（Number(undefined)=NaN 的字符串兜底语义）。
test('多源聚合：缺省 version 键与空串同口径', () => {
  const summary = summarizeLibrarySources([{ update_status: 'idle' }])
  assert.equal(summary.latestVersion, '')
  assert.equal(summary.status, 'never')
})
