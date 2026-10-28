// 归属地文本拆分单源：光流地域键与弧线起点共用同一 split('·') 规则——两处各自
// 拆分会在分隔符/段数变化时让「键里的省」与「端点用的省」漂移。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { parseIpLocation } from '../src/utils/ipLocationParts.ts'
import { code } from './_helpers.ts'

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
