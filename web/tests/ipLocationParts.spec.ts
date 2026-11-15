// 归属地文本拆分单源：光流地域键与弧线起点共用同一 split('·') 规则——两处各自
// 拆分会在分隔符/段数变化时让「键里的省」与「端点用的省」漂移。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { parseIpLocation, compactIpLocation } from '../src/utils/ipLocationParts.ts'
import { code, member } from './_helpers.ts'

test('国内联值取前两段（国家/省），第三段及以后忽略', () => {
  assert.deepEqual(parseIpLocation('中国·广东省·深圳市'), { country: '中国', province: '广东省' })
  assert.deepEqual(parseIpLocation('中国·北京市'), { country: '中国', province: '北京市' })
})

test('海外两段与单段：缺省补空串', () => {
  assert.deepEqual(parseIpLocation('美国·California'), { country: '美国', province: 'California' })
  assert.deepEqual(parseIpLocation('日本'), { country: '日本', province: '' })
})

test('空/缺失输入回退两空串（不炸渲染路径）', () => {
  assert.deepEqual(parseIpLocation(''), { country: '', province: '' })
  assert.deepEqual(parseIpLocation(undefined), { country: '', province: '' })
  // 空段保留空串：`中国··深圳市` 的省位不得被后续段顶替
  assert.deepEqual(parseIpLocation('中国··深圳市'), { country: '中国', province: '' })
})

test('缺失/null 输入回退两空串', () => {
  assert.deepEqual(parseIpLocation(null as unknown as string), { country: '', province: '' })
})

test('四段以上只取前两段；混合分隔符不参与拆分（后端只发 `·`）', () => {
  assert.deepEqual(parseIpLocation('中国·广东省·深圳市·南山区'), { country: '中国', province: '广东省' })
  // 全角项目符号 `•` 不是分隔符：混用时整段落进 province——钉住现状，后端
  // 若改分隔符本用例先红（避免两处 split 各自漂移）。
  assert.deepEqual(parseIpLocation('中国·广东省•深圳市'), { country: '中国', province: '广东省•深圳市' })
})

// 头注释的「两处共用」是可核对接线，不是修辞：威胁模块必须经本函数取值，
// 场景/地球两引擎不得各自再 split 一遍（否则分隔符或段数变化时，键里的省与
// 端点用的省会静默不一致）。纯函数全绿不覆盖这一点。
test('消费接线：弧线端点走单源拆分，两引擎不各自再拆一次', () => {
  const shared = code('src/utils/threatShared.ts')
  assert.match(shared, /import \{ parseIpLocation \} from '\.\/ipLocationParts\.ts'/, '必须复用单源导入')
  assert.match(shared, /parseIpLocation\(ipLocation\)/, '弧线/地域键取数必须经本函数')
  const offenders = ['src/utils/threatScene.ts', 'src/utils/threatGlobe.ts']
    .filter((file) => /split\(['"]·['"]\)/.test(code(file)))
  assert.deepEqual(offenders, [], '场景/地球引擎只消费 threatShared 的结果，不得自带第二份分隔符拆分')
})

// ── 紧凑展示单源 compactIpLocation（IP 处置单元/累犯弹框共用）──

const LABELS = { reserved: '保留地址', china: '中国' }
const EN_LABELS = { reserved: 'Reserved', china: 'China' }

test('紧凑归属地：国内三段取市、两段取省、单段取国名', () => {
  assert.equal(compactIpLocation('中国·广东省·深圳市', LABELS), '深圳市')
  assert.equal(compactIpLocation('中国·广东省', LABELS), '广东省')
  assert.equal(compactIpLocation('中国', LABELS), '中国')
})

test('紧凑归属地：保留地址/海外按词条本地化，判定锚定数据值', () => {
  assert.equal(compactIpLocation('保留地址', EN_LABELS), 'Reserved')
  assert.equal(compactIpLocation('中国', EN_LABELS), 'China')
  assert.equal(compactIpLocation('中国·广东省·深圳市', EN_LABELS), '深圳市')
  // 海外国家名原样（数据值即展示值，不做二次翻译）
  assert.equal(compactIpLocation('美国·California', EN_LABELS), '美国')
})

test('紧凑归属地：空/缺失回退空串；空段被过滤不顶替段序', () => {
  assert.equal(compactIpLocation('', LABELS), '')
  assert.equal(compactIpLocation(undefined, LABELS), '')
  // 空段过滤后「中国··深圳市」= [中国, 深圳市] 两段 → 取第二段
  assert.equal(compactIpLocation('中国··深圳市', LABELS), '深圳市')
})

test('消费接线：IP 处置单元走紧凑单源，累犯弹框经处置单元间接消费', () => {
  const action = code('src/views/security/IPLocationAction.vue')
  assert.match(action, /import \{ compactIpLocation \} from '@\/utils\/ipLocationParts'/, 'IP 处置单元必须复用单源导入')
  assert.match(action, /compactIpLocation\(props\.location/, '紧凑文案必须经本函数')
  const dialog = code('src/components/security/RecidivismDialog.vue')
  // 累犯弹框 IP 列改用 IPLocationAction 快捷弹框（用户裁定）：归属地紧凑文案
  // 由处置单元内部经 compactIpLocation 呈现，弹框不得自带第二份紧凑实现。
  assert.match(dialog, /import IPLocationAction from '@\/views\/security\/IPLocationAction\.vue'/, '累犯弹框必须复用 IP 快捷弹框组件')
  assert.doesNotMatch(dialog, /compactIpLocation/, '弹框不得自带紧凑归属地实现（经处置单元单源消费）')
  // 两处不得自带第二份「保留地址/中国」判定或 split('·') 紧凑实现
  for (const [file, text] of [['IPLocationAction', action], ['RecidivismDialog', dialog]] as const) {
    assert.doesNotMatch(text, /=== '保留地址'/, `${file} 不得自带保留地址判定`)
    assert.doesNotMatch(text, /split\(['"]·['"]\)/, `${file} 不得自带第二份分隔符拆分`)
  }
})

test('自动封禁取消：CIDR 条目同路径可解禁 + 写成功通知宿主', () => {
  const action = code('src/views/security/IPLocationAction.vue')
  // CIDR（IPv6 /64 整段）与裸地址同按钮同路径——累犯弹框「封禁中禁用
  // 移除，请先取消封禁」的指引对 v6 必须成立（旧实现 CIDR 只给编辑跳转，
  // unbanAutoban 对 CIDR 直接 return，指引落空）。
  assert.doesNotMatch(action, /if \(!hit \|\| !listId \|\| autobanHitIsCidr\.value/, 'unbanAutoban 不得再按 CIDR 拒绝解禁')
  assert.match(action, /<button type="button" class="ipm-remove" :disabled="autobanUnbanning" @click="unbanAutoban">/, '取消封禁按钮必须对全部条目形态在场（无 v-else 门）')
  assert.match(action, /confirmTextCidr/, 'CIDR 整段解封必须用网段口径确认文案')
  // 取消封禁成功 → emit('changed')（与加名单同族），宿主累犯弹框
  // ban_status/移除禁用态即时刷新。
  const unban = member(action, 'const unbanAutoban')
  assert.match(unban, /emit\('changed'\)/, '取消封禁成功必须通知宿主刷新')
})
