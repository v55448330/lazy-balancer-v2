// 通道 style_config 读写契约（通道卡编辑 + 日报模板保存共用单源）：
// PUT /notification/channels 的 style_config 是全量覆盖语义——表单重建必须把
// 不认识的既有键（daily_mode 等）原样带回，否则保存一次就把别的功能写进去的
// 键抹掉。日报模板写入 daily_* 键（与事件正文模板键分离）；多 tab 全量保存只
// 提交与存量有差异的通道。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildChannelStyleConfig,
  channelStyleExtras,
  channelStyleFormFrom,
  dailyBodyTplKey,
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

test('日报模板键与事件正文模板键分离（类型派生）', () => {
  assert.equal(dailyBodyTplKey('webhook'), 'daily_payload_template')
  assert.equal(dailyBodyTplKey('email'), 'daily_body_template')
  assert.equal(dailyBodyTplKey('qq'), 'daily_content_template')
  assert.equal(dailyBodyTplKey('wx_clawbot'), 'daily_content_template')
})

test('渲染模式生效值：显式优先，缺省只看日报模板键', () => {
  assert.equal(effectiveDailyMode(undefined, 'qq'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({}), 'qq'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_content_template: 'tpl' }), 'qq'), 'template')
  // 后端 DailyModuleModeEffective 判据是 `Key == ""`（不 trim）：空白模板也算已配置。
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_content_template: '   ' }), 'qq'), 'template', '后端不 trim：空白模板=已配置')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_mode: 'modules', daily_content_template: 'tpl' }), 'qq'), 'modules', '显式值优先')
  assert.equal(effectiveDailyMode(JSON.stringify({ daily_mode: 'weird', daily_content_template: 'tpl' }), 'qq'), 'template', '未知值按存量推断')
})

test('事件模板不推断日报模式（事件模板≠日报模板；存量归一在后端读面完成）', () => {
  assert.equal(effectiveDailyMode(JSON.stringify({ payload_template: '{"title": {{title}}}' }), 'webhook'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({ content_template: '静态版式' }), 'qq'), 'modules')
  // 事件键即使引用日报变量也不在前端归一：列表接口输出的已是新布局，
  // 这种形态的行只可能是事件模板。
  assert.equal(effectiveDailyMode(JSON.stringify({ content_template: '{{requests}}' }), 'qq'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({ payload_template: '{"requests": {{requests}}}' }), 'webhook'), 'modules')
  assert.equal(effectiveDailyMode(JSON.stringify({ body_template: ' ' }), 'email'), 'modules', '无日报变量的空白事件模板')
})

test('未编辑直接保存=零差异（多 tab 全量保存只提交真正变化的通道）', () => {
  const raw = JSON.stringify({ daily_mode: 'template', daily_content_template: 'mine' })
  const plan = planDailyChannelStyle({ raw, type: 'qq', draft: 'mine', presets: ['p1', 'p2'], mode: 'template' })
  assert.equal(plan.changed, false, '草稿与存量一致时不得写库')
  // 推断值=所选模式（存量无 daily_mode，靠日报模板推断为 template）同样零差异。
  const inferred = planDailyChannelStyle({ raw: JSON.stringify({ daily_content_template: 'mine' }), type: 'qq', draft: 'mine', presets: ['p1', 'p2'], mode: 'template' })
  assert.equal(inferred.changed, false, '推断模式与所选模式一致时不得补写 daily_mode')
})

test('与预置相同的草稿在内置模板模式不落库（预置升级继续生效）', () => {
  for (const presets of [['预置中文', 'preset-en'], ['preset-zh', 'preset-en']]) {
    const plan = planDailyChannelStyle({
      raw: JSON.stringify({ daily_mode: 'template' }), type: 'email', draft: ` ${presets[1]} `, presets, mode: 'modules',
    })
    assert.ok(!('daily_body_template' in plan.style), '任一语言预置均视为默认链（不冗余落库）')
    assert.equal(plan.style.daily_mode, 'modules', '模式切换仍要落库')
    assert.equal(plan.changed, true)
  }
})

test('自定义草稿落库 + 未知键保留', () => {
  const plan = planDailyChannelStyle({
    raw: JSON.stringify({ daily_mode: 'modules', future_key: 'keep' }), type: 'qq',
    draft: '  我的模板  ', presets: ['p1', 'p2'], mode: 'template',
  })
  assert.equal(plan.style.daily_content_template, '我的模板', '草稿按 trim 后落库到日报键')
  assert.equal(plan.style.daily_mode, 'template')
  assert.equal(plan.style.future_key, 'keep', '未知键必须保留')
  assert.equal(plan.changed, true)
})

test('模式未变且草稿未变=零差异（不重复写 daily_mode）', () => {
  const raw = JSON.stringify({ daily_mode: 'template', daily_content_template: 'mine' })
  const plan = planDailyChannelStyle({ raw, type: 'qq', draft: 'mine', presets: ['p1', 'p2'], mode: 'template' })
  assert.equal(plan.changed, false)
})

test('stylesEqual：键序无关、嵌套对象同样生效', () => {
  assert.equal(stylesEqual({ a: 1, b: { c: 2, d: 3 } }, { b: { d: 3, c: 2 }, a: 1 }), true)
  assert.equal(stylesEqual({ a: 1 }, { a: 2 }), false)
  assert.equal(stylesEqual({ headers: { X: '1' } }, { headers: { X: '1' } }), true)
})
