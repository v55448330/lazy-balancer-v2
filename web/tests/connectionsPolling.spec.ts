// 连接监控弹框轮询必须经 usePollingTask 单源（单飞 + 会话序号守卫 + 轮次
// signal 取消在途），不得残留裸 setInterval——无守卫的裸定时器会让迟到响应
// 覆写新帧。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section } from './_helpers.ts'
test('ConnectionsDialog 轮询经 usePollingTask 单源（无裸 setInterval，接线+会话守卫强判据）', () => {
  const page = code('src/components/ConnectionsDialog.vue')
  assert.match(page, /usePollingTask/)
  assert.doesNotMatch(page, /window\.setInterval|setInterval\(/)
  // 接线钉（pollingSignal.spec 同形态强判据）：轮次 signal/isCurrent 必须真的
  // 透传给取数函数——/signal/ 子串断言会被形参名满足（接线回归假绿）。
  assert.match(page, /usePollingTask\(async \(\{ signal, isCurrent \}\) => \{ await fetchOnce\(signal, isCurrent\) \}/, '轮询回调必须消费本轮 signal 与 isCurrent')
  assert.match(page, /const fetchOnce = async \(roundSignal\?: AbortSignal, isCurrent\?: \(\) => boolean\)/, '取数函数必须接收本轮 signal 与会话守卫')
  assert.match(page, /signal: roundSignal/, '请求必须携带本轮 signal（pause/关闭可取消在途）')
  // isCurrent 早退钉：迟到响应在写回前必须过会话守卫（无守卫=旧帧覆写新帧）
  const fetch = section(page, 'const fetchOnce = async', '\n}')
  const guardAt = fetch.indexOf('if (isCurrent && !isCurrent()) return')
  const writeAt = fetch.indexOf('counts.value =')
  assert.ok(guardAt > 0, '缺会话守卫早退（迟到响应不得写回）')
  assert.ok(writeAt > guardAt, '早退必须先于任何帧写回')
})
