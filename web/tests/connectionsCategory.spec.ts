// 连接监控回退视图（req_mon=false）行分类与筛选键同源：
// 后端 connectionEntry.category 是 socket 状态族（established/time_wait/closed），
// 筛选器键是窗口语义（active/closing/closed）。此前筛选器按 active 过滤原始
// category，默认视图恒空（统计卡有计数、表格显示无连接）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { connectionFilterCategory } from '../src/utils/connectionCategories.ts'
import { code } from './_helpers.ts'

test('socket 状态族 → 筛选键映射（established=活跃、time_wait=关闭中）', () => {
  assert.equal(connectionFilterCategory('established'), 'active')
  assert.equal(connectionFilterCategory('time_wait'), 'closing')
  assert.equal(connectionFilterCategory('closed'), 'closed')
})

test('请求视图行已是筛选键：映射幂等，不误改 active/closing/closed', () => {
  assert.equal(connectionFilterCategory('active'), 'active')
  assert.equal(connectionFilterCategory('closing'), 'closing')
  assert.equal(connectionFilterCategory('closed'), 'closed')
  // 未知形态原样返回（不静默归入 active，避免把未知连接藏进活跃视图）
  assert.equal(connectionFilterCategory('listen'), 'listen')
})

test('ConnectionsDialog 筛选与徽标统一走映射单源', () => {
  const page = code('src/components/ConnectionsDialog.vue')
  assert.match(page, /from '@\/utils\/connectionsView\.ts'/, '必须消费视图口径单源')
  assert.match(page, /computed\(\(\) => filterRows\(rows\.value, category\.value\)\)/, '筛选必须按映射后的键比较（5xx 分支同源）')
  assert.match(page, /const rowCat = \(row: unknown\): string =>/, '徽标/文案必须走同一映射')
  assert.match(page, /return filterKeyOf\(/, '徽标映射复用视图单源')
  assert.match(page, /:class="'is-' \+ rowCat\(row\)">\{\{ catLabel\(rowCat\(row\)\) \}\}/, '行状态徽标按筛选键文案展示')
  // 委派链路：connectionsView → connectionCategories（socket 状态族映射仍单源）
  const view = code('src/utils/connectionsView.ts')
  assert.match(view, /import \{ connectionFilterCategory \} from '\.\/connectionCategories\.ts'/, '视图单源必须复用既有 socket 状态映射')
  assert.match(view, /filterKeyOf = \(category: string\): string => connectionFilterCategory\(category\)/, 'filterKeyOf 只做映射委派')
})
