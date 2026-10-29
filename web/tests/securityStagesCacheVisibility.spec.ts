// 共享名单条目缓存的外部变更收敛：写动作之外的唯一入口是「恢复可见」——
// 期间另一标签页/另一管理员可能已增删条目，模块只能在回前台时感知。
// 语义：标记陈旧（保留已显示数据，避免打开中的弹框突然变空名单）→ 下次
// ensureSharedEntries 按缺失重拉；真正的 TTL 判定见 ipList.spec。
//
// 监听在模块 import 时单次绑定，故先把假 document 装上再动态 import。
//
// 运行：cd web && node --test tests/securityStagesCacheVisibility.spec.ts

import { test, after } from 'node:test'
import assert from 'node:assert/strict'

import { installBrowserHost } from './_helpers.ts'

// 监听在模块 import 时单次绑定，故先把假 document 装上再动态 import。
const browser = installBrowserHost({ visibility: true })
const fakeDocument = browser.document

after(() => {
  // 被测模块以匿名 handler 单次绑定（设计上不摘除）——文件结束先清场再还原。
  assert.equal(fakeDocument.listenerCount, 1, 'visibilitychange 只允许模块级单次绑定')
  fakeDocument.clear()
  assert.equal(fakeDocument.listenerCount, 0, '假 document 上不得残留监听器')
  browser.restore()
})

const {
  ensureSharedEntries,
  invalidateSharedEntriesCache,
  missingSharedEntryIds,
  sharedEntriesCache,
} = await import('../src/utils/securityStages.ts')

test('恢复可见：标记已缓存条目陈旧（保留数据），下次 ensure 重拉', async () => {
  invalidateSharedEntriesCache()
  assert.equal(fakeDocument.listenerCount, 1, 'visibilitychange 单次绑定')

  let calls = 0
  const loader = async (): Promise<string[]> => {
    calls += 1
    return [`10.0.0.${calls}`]
  }

  await ensureSharedEntries([3], loader)
  assert.equal(calls, 1)
  assert.deepEqual(sharedEntriesCache[3], ['10.0.0.1'])

  // TTL 内正常命中：不回源
  await ensureSharedEntries([3], loader)
  assert.equal(calls, 1, 'TTL 内已缓存 id 不得重复请求')

  // 隐藏期间不失效（只有回前台才需要重拉）
  fakeDocument.hidden = true
  fakeDocument.dispatch()
  assert.deepEqual(missingSharedEntryIds([3]), [], '隐藏态不得标记陈旧')

  // 恢复可见：标记陈旧但保留数据（打开中的弹框不得变空名单）
  fakeDocument.hidden = false
  fakeDocument.dispatch()
  assert.deepEqual(sharedEntriesCache[3], ['10.0.0.1'], '恢复可见不得清空已显示条目')
  assert.deepEqual(missingSharedEntryIds([3]), [3], '恢复可见后按缺失重拉（外部变更收敛）')

  await ensureSharedEntries([3], loader)
  assert.equal(calls, 2, '恢复可见后必须重拉一次')
  assert.deepEqual(sharedEntriesCache[3], ['10.0.0.2'])
  invalidateSharedEntriesCache()
})
