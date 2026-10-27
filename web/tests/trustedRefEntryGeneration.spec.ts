// 受信代理「引用名单条目」缓存的世代守卫。
//
// 条目按 id 惰性拉取并缓存；名单目录重新拉取成功时会清空缓存并重排当前引用
// （名单可能在别处被改过）。问题出在**在途请求**与**失效**交错：
//   - 失效前发出的详情请求落地后会把旧条目写回空缓存 →「合计 N 条」与超限提示
//     长期基于旧快照，而界面已经说「已刷新」；
//   - 旧响应的 catch 还会给已复位的 id 重新打上失败标记 → 明明重排成功仍显示
//     「按条数估算」；
//   - 在途标记若按「是否存在」而非「是否属于当前世代」判断，重排的拉取会被
//     「已在途」跳过，反而只有那次旧响应能落库。
//
// 因此缓存世代（refEntryGeneration）必须同时守住三处：写回、失败标记、在途标记
// 的收尾。真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），
// 该状态机依赖组件内 ref ——用「限段 + 顺序」文本钉住三处守卫的相对位置。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'

const SETTINGS = 'src/views/settings/CaddyGlobalSettings.vue'

test('在途标记按世代记录（id → 发起时的世代），不是布尔集合', () => {
  const text = code(SETTINGS)
  assert.match(text, /const refListEntriesLoading = new Map<number, number>\(\)/, '在途标记必须携带世代（Set 无法区分新旧请求）')
  assert.match(text, /let refEntryGeneration = 0/)
  const body = member(code(SETTINGS), 'const fetchRefListEntries = async (id: number): Promise<void> =>')
  assert.match(body, /const generation = refEntryGeneration/, '发起时快照当前世代')
  assert.match(body, /refListEntriesLoading\.set\(id, generation\)/, '在途标记带世代')
  assert.match(body, /refListEntriesLoading\.has\(id\)/, '在途判据仍按 id（同代内不重复请求）')
  // finally 只清自己那一代：旧响应不得抹掉新一代的在途标记（否则同 id 并发请求）
  const tail = section(body, '} finally {', '\n  }')
  assert.match(tail, /refListEntriesLoading\.get\(id\) === generation/, '收尾必须核对世代')
  assert.match(tail, /refListEntriesLoading\.delete\(id\)/)
})

test('失效推进世代并作废旧代在途标记', () => {
  const text = code(SETTINGS)
  const invalidate = member(text, 'const invalidateRefListEntries = (): void =>')
  const bumped = invalidate.indexOf('refEntryGeneration++')
  assert.ok(bumped > 0, '失效必须推进世代')
  assert.ok(invalidate.indexOf('refListEntries.value = {}') > bumped, '先推进世代再清缓存（顺序反了会让旧响应赶在失效前写回）')
  assert.match(invalidate, /refListEntriesFailed\.value = \{\}/, '清失败标记')
  assert.match(invalidate, /refListEntriesLoading\.clear\(\)/, '旧代在途标记一并作废（否则重排拉取被「已在途」跳过）')
  assert.match(invalidate, /for \(const id of trustedRangeRefs\.value\) scheduleRefListEntries\(id\)/, '重排当前引用')
})

test('成功响应：世代不符则不写回、不动失败标记', () => {
  const body = member(code(SETTINGS), 'const fetchRefListEntries = async (id: number): Promise<void> =>')
  const awaited = body.indexOf('await request.get')
  assert.ok(awaited > 0, '前置：确实在拉取详情')
  const guard = body.indexOf('if (generation !== refEntryGeneration) return')
  const write = body.indexOf('refListEntries.value = {')
  const clearFailed = body.indexOf('if (refListEntriesFailed.value[id])')
  assert.ok(guard > awaited, '守卫必须紧跟在响应之后')
  assert.ok(write > guard, '世代守卫必须早于缓存写回（否则旧条目覆盖新缓存）')
  assert.ok(clearFailed > guard, '守卫必须早于失败标记清理')
})

test('失败响应：世代不符则不打失败标记（重排后的成功不得被旧失败覆盖）', () => {
  const body = member(code(SETTINGS), 'const fetchRefListEntries = async (id: number): Promise<void> =>')
  const catchBlock = section(body, '} catch {', '\n  }')
  const guard = catchBlock.indexOf('if (generation !== refEntryGeneration) return')
  const flag = catchBlock.indexOf('refListEntriesFailed.value = {')
  assert.ok(guard > 0, 'catch 也必须有世代守卫')
  assert.ok(flag > guard, '守卫必须早于失败标记写入')
})
