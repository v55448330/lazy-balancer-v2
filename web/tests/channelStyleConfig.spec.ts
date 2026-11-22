// 通道 style_config 读写契约（通道卡编辑 + 日报模板保存共用单源）：
// PUT /notification/channels 的 style_config 是全量覆盖语义——表单重建必须把
// 不认识的既有键（daily_mode 等）原样带回；日报模板多 tab 全量保存只提交
// 与存量有差异的通道，与任一语言预置相同的草稿不落库（预置升级继续生效）。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildChannelStyleConfig,
  channelStyleExtras,
  channelStyleFormFrom,
  channelBodyTplKey,
  effectiveDailyMode,
  emptyChannelStyleForm,
  planDailyChannelStyle,
  stylesEqual,
} from '../src/utils/channelStyle.ts'

test('未知键原样带回：daily_mode 与未来新增键不得被表单重建抹掉', () => {
  const raw = JSON.stringify({ daily_mode: 'template', content_template: 'tpl', future_key: { a: 1 } })
  const extras = channelStyleExtras(raw)
  assert.deepEqual(extras, { daily_mode: 'template', future_key: { a: 1 } }, '表单不认识的键必须保留')
  const built = buildChannelStyleConfig('qq', { ...emptyChannelStyleForm(), content_template: 'tpl' }, {}, extras)
  assert.equal(built.daily_mode, 'template', 'daily_mode 必须在全量 PUT 中原样带回')
  assert.deepEqual(built.future_key, { a: 1 })
  assert.equal(built.content_template, 'tpl')
  assert.equal(built.msg_type, 'markdown', 'QQ 协议固定 msg_type')
})

test('表单已知键清空=移除该键（不回写旧值）', () => {
  const extras = channelStyleExtras(JSON.stringify({ daily_mode: 'modules', subject_template: 'old' }))
  const built = buildChannelStyleConfig('email', { ...emptyChannelStyleForm(), body_template: 'body' }, {}, extras)
  assert.ok(!('subject_template' in built), '留空的 subject_template 必须移除（不得残留旧值）')
  assert.equal(built.body_template, 'body')
  assert.equal(built.daily_mode, 'modules')
})

test('webhook 请求头与非默认 method 由表单写入', () => {
  const built = buildChannelStyleConfig(
    'webhook',
    { ...emptyChannelStyleForm(), payload_template: '{"a":{{requests}}}', method: 'GET' },
    { Authorization: 'Bearer x' },
    { daily_mode: 'modules' },
  )
  assert.equal(built.method, 'GET')
  assert.deepEqual(built.headers, { Authorization: 'Bearer x' })
  assert.equal(built.payload_template, '{"a":{{requests}}}')
  assert.equal(built.daily_mode, 'modules')
})

test('回填：既有 style_config 的已知字符串键进表单，非字符串与未知键不进', () => {
  const form = channelStyleFormFrom(JSON.stringify({
    payload_template: 'x', subject_template: 42, body_template: 'b', body_format: 'html', method: 'POST', daily_mode: 'modules',
  }))
  assert.equal(form.payload_template, 'x')
  assert.equal(form.body_template, 'b')
  assert.equal(form.body_format, 'html')
  assert.equal(form.method, 'POST')
  assert.equal(form.subject_template, '', '非字符串已知键按默认形态')
  assert.equal(form.daily_format, '')
  assert.ok(!('daily_mode' in form), '未知键不进表单（由 extras 携带）')
})

test('坏 JSON/空值按默认形态（不抛）', () => {
  assert.deepEqual(channelStyleExtras(''), {})
  assert.deepEqual(channelStyleExtras('not-json'), {})
  assert.deepEqual(channelStyleExtras('[]'), {})
  assert.deepEqual(channelStyleFormFrom('null'), emptyChannelStyleForm())
})

test('渲染模式生效值：显式优先，缺省按存量模板键推断', () => {
  assert.equal(channelBodyTplKey('webhook'), 'payload_template')
  assert.equal(channelBodyTplKey('email'), 'body_template')
  assert.equal(channelBodyTplKey('qq'), 'content_template')
  assert.equal(effectiveDailyMode(undefined, 'qq'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({}), 'qq'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({ content_template: 'tpl' }), 'qq'), 'template')
  // 后端 DailyModuleModeEffective 判据是 `Key == ""`（不 trim）：空白模板也算已配置。
  assert.equal(effectiveDailyMode(JSON.stringify({ content_template: '   ' }), 'qq'), 'template', '后端不 trim：空白模板=已配置')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_mode: 'modules', content_template: 'tpl' }), 'qq'), 'modules', '显式值优先')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_mode: 'weird', content_template: 'tpl' }), 'qq'), 'template', '未知值按存量推断')
})

test('渲染模式跨键对齐后端：payload/body/content 任一非空即模板模式', () => {
  // 后端不按通道类型挑键——三类正文模板键任一存在即 suppress 模块拼装。
  assert.equal(effectiveDailyMode(JSON.stringify({ payload_template: '{}' }), 'qq'), 'template', 'webhook 模板键在机器人通道同样生效')
  assert.equal(effectiveDailyMode(JSON.stringify({ content_template: 'x' }), 'email'), 'template', '机器人模板键在邮件通道同样生效')
  assert.equal(effectiveDailyMode(JSON.stringify({ body_template: ' ' }), 'webhook'), 'template', '空白（不 trim）同样算已配置')
  assert.equal(effectiveDailyMode(JSON.stringify({ payload_template: '' }), 'webhook'), 'modules', '空串=未配置')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_mode: 'modules', body_template: 'x' }), 'qq'), 'modules', '显式值仍优先')
})

test('未编辑直接保存=零差异（多 tab 全量保存只提交真正变化的通道）', () => {
  const raw = JSON.stringify({ daily_mode: 'modules', content_template: 'saved-tpl' })
  const plan = planDailyChannelStyle({
    raw, type: 'qq', draft: 'saved-tpl', presets: ['preset-zh', 'preset-en'], mode: 'modules',
  })
  assert.equal(plan.changed, false, '草稿与存量一致时不得写库')
  const presetPlan = planDailyChannelStyle({
    raw: JSON.stringify({ content_template: 'saved-tpl' }), type: 'qq', draft: 'saved-tpl', presets: ['saved-tpl', 'other'], mode: 'modules',
  })
  assert.equal(presetPlan.changed, true, '存量=预置文本时保存预置应清除该键（预置升级继续生效）')
  assert.ok(!('content_template' in presetPlan.style))
  assert.equal(presetPlan.style.daily_mode, 'modules')
})

test('与任一语言预置相同的草稿不落库（模板键移除）', () => {
  for (const presets of [['预置中文', 'preset-en'], ['preset-zh', 'preset-en']]) {
    const plan = planDailyChannelStyle({
      raw: JSON.stringify({ daily_mode: 'template' }), type: 'email', draft: ` ${presets[1]} `, presets, mode: 'modules',
    })
    assert.ok(!('body_template' in plan.style), '任一语言预置均视为默认链（不冗余落库）')
    assert.equal(plan.style.daily_mode, 'modules', '模式切换仍要落库')
    assert.equal(plan.changed, true)
  }
})

test('自定义草稿落库 + 未知键保留', () => {
  const plan = planDailyChannelStyle({
    raw: JSON.stringify({ daily_mode: 'modules', future_key: 'keep' }), type: 'qq',
    draft: '  我的模板  ', presets: ['p1', 'p2'], mode: 'template',
  })
  assert.equal(plan.style.content_template, '我的模板', '草稿按 trim 后落库')
  assert.equal(plan.style.daily_mode, 'template')
  assert.equal(plan.style.future_key, 'keep', '未知键必须保留')
  assert.equal(plan.changed, true)
})

test('模式未变且草稿未变=零差异（不重复写 daily_mode）', () => {
  const raw = JSON.stringify({ daily_mode: 'template', content_template: 'mine' })
  const plan = planDailyChannelStyle({ raw, type: 'qq', draft: 'mine', presets: ['p1', 'p2'], mode: 'template' })
  assert.equal(plan.changed, false)
  // 缺省推断=template（有模板键）时，选中 template 无需显式落键
  const inferred = planDailyChannelStyle({ raw: JSON.stringify({ content_template: 'mine' }), type: 'qq', draft: 'mine', presets: ['p1'], mode: 'template' })
  assert.equal(inferred.changed, false, '显式值与推断值相同=无行为变化')
})

test('stylesEqual：键序无关、嵌套对象同样生效', () => {
  assert.equal(stylesEqual({ a: 1, b: { c: 2, d: 3 } }, { b: { d: 3, c: 2 }, a: 1 }), true)
  assert.equal(stylesEqual({ a: 1 }, { a: 2 }), false)
  assert.equal(stylesEqual({ headers: { X: '1' } }, { headers: { X: '1' } }), true)
})
