// 连接监控弹框轮询必须经 usePollingTask 单源（单飞 + 会话序号守卫 + 轮次
// signal 取消在途），不得残留裸 setInterval——无守卫的裸定时器会让迟到响应
// 覆写新帧。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code } from './_helpers.ts'
test('ConnectionsDialog 轮询经 usePollingTask 单源（无裸 setInterval）', () => {
  const page = code('src/components/ConnectionsDialog.vue')
  assert.match(page, /usePollingTask/)
  assert.doesNotMatch(page, /window\.setInterval|setInterval\(/)
  assert.match(page, /signal/)
})
