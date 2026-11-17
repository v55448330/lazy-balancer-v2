// 写操作互斥、乐观状态补偿与最新读取会话的行为验收。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createLatestReadSession, runExclusive } from '../src/utils/viewAsyncState.ts'
import { rollbackUserStatus } from '../src/utils/userStatus.ts'
import { code, matchBrace, member, section } from './_helpers.ts'

test('删除写通道从确认前占位，连点只执行一次并在成功后释放', async () => {
  let locked = false
  let confirms = 0
  let deletes = 0
  const remove = () => runExclusive(
    () => locked,
    (value) => { locked = value },
    async () => {
      confirms++
      await Promise.resolve()
      deletes++
    },
  )
  await Promise.all([remove(), remove()])
  assert.equal(confirms, 1)
  assert.equal(deletes, 1)
  assert.equal(locked, false)
})

test('写通道在取消与请求失败后都释放', async () => {
  for (const error of [new Error('cancel'), new Error('request')]) {
    let locked = false
    await assert.rejects(
      runExclusive(() => locked, (value) => { locked = value }, async () => { throw error }),
      error,
    )
    assert.equal(locked, false)
  }
})

test('用户状态写失败按目标行回滚两个方向，不误改其它行', () => {
  for (const attempted of [true, false]) {
    const rows = [
      { id: 1, is_enabled: attempted },
      { id: 2, is_enabled: true },
    ]
    rollbackUserStatus(rows, 1, attempted)
    assert.equal(rows[0]?.is_enabled, !attempted)
    assert.equal(rows[1]?.is_enabled, true)
  }
  const rows = [{ id: 1, is_enabled: true }]
  rollbackUserStatus(rows, 99, false)
  assert.equal(rows[0]?.is_enabled, true)
})

test('最新读取会话按 B→A 乱序完成时，旧成功与旧收尾均不落地', async () => {
  const session = createLatestReadSession()
  const first = Promise.withResolvers<string>()
  const second = Promise.withResolvers<string>()
  const applied: string[] = []
  const loading: boolean[] = []
  const errors: unknown[] = []
  const run = (gate: PromiseWithResolvers<string>) => session.run(() => gate.promise, {
    onStart: () => { loading.push(true) },
    onSuccess: (value) => { applied.push(value) },
    onError: (error) => { errors.push(error) },
    onFinally: () => { loading.push(false) },
  })
  const a = run(first)
  const b = run(second)
  second.resolve('fresh')
  await b
  applied.push('user-edit')
  first.resolve('stale')
  await a
  assert.deepEqual(applied, ['fresh', 'user-edit'])
  assert.deepEqual(loading, [true, true, false])
  assert.deepEqual(errors, [])
})

test('旧读取失败不提示；关闭会话作废响应并取消在途请求', async () => {
  const session = createLatestReadSession()
  const gate = Promise.withResolvers<string>()
  let signal: AbortSignal | undefined
  const events: string[] = []
  const pending = session.run((requestSignal) => { signal = requestSignal; return gate.promise }, {
    onStart: () => {},
    onSuccess: () => { events.push('success') },
    onError: () => { events.push('error') },
    onFinally: () => { events.push('finally') },
  })
  session.invalidate()
  assert.equal(signal?.aborted, true)
  gate.reject(new Error('stale failure'))
  await pending
  assert.deepEqual(events, [])
})

test('最新读取会话正常顺序仍逐轮落地', async () => {
  const session = createLatestReadSession()
  const applied: string[] = []
  for (const value of ['a', 'b']) {
    await session.run(async () => value, {
      onStart: () => {},
      onSuccess: (result) => { applied.push(result) },
      onError: () => assert.fail('不应失败'),
      onFinally: () => {},
    })
  }
  assert.deepEqual(applied, ['a', 'b'])
})

test('当前读取失败仍披露并收尾，不被序号守卫吞掉', async () => {
  const session = createLatestReadSession()
  const events: string[] = []
  await session.run(async () => { throw new Error('current failure') }, {
    onStart: () => { events.push('start') },
    onSuccess: () => { events.push('success') },
    onError: (error) => { events.push(error instanceof Error ? error.message : 'unknown') },
    onFinally: () => { events.push('finally') },
  })
  assert.deepEqual(events, ['start', 'current failure', 'finally'])
})

test('OIDC 删除复用同一 saving 写通道并覆盖确认、删除与最终回填', () => {
  const page = code('src/views/settings/OIDCSettings.vue')
  const remove = section(page, 'const remove = async', 'const copy = async')
  assert.match(remove, /runExclusive\(/)
  assert.match(remove, /saving\.value/)
  for (const operation of [/ElMessageBox\.confirm/, /request\.delete[<(]/, /await load\(\)/]) {
    assert.ok(operation.test(remove), `删除写通道缺少 ${operation}`)
  }
})

test('用户状态 catch 先本地回滚再刷新，成功路径不回滚', () => {
  const page = code('src/views/Users.vue')
  // 函数体与 catch 块体都按命名锚 + 花括号配对整取。此前的窗口切片判据
  // （以「} catch」末次字符串命中定位 + indexOf 推「回滚→刷新」次序）是盲区：
  // 外层 catch 被删时定位指到内层「确认取消」catch，其后的成功路径 fetchUsers
  // 仍满足次序；成功段窗口还会因边界倒置变空切片（doesNotMatch 空转假绿）。
  const toggle = member(page, 'const handleToggleStatus')
  const catches = [...toggle.matchAll(/\bcatch\s*[({]/g)]
  assert.ok(catches.length >= 1, 'handleToggleStatus 缺 catch 分支')
  const lastCatch = catches[catches.length - 1]
  const lastCatchAt = lastCatch.index ?? -1
  const catchOpen = toggle.indexOf('{', lastCatchAt)
  const catchClose = matchBrace(toggle, catchOpen)
  assert.ok(catchOpen >= 0 && catchClose > catchOpen, '最后一个 catch 块未闭合')
  const catchBody = toggle.slice(catchOpen + 1, catchClose)
  // 最后一个 catch（外层失败路径）块体内必须同时本地回滚并刷新。
  assert.match(catchBody, /rollbackUserStatus\(users\.value, id, isEnabled\)/, '失败路径必须先本地回滚乐观状态')
  assert.match(catchBody, /fetchUsers\(\)/, '失败路径必须刷新列表')
  const successAt = toggle.indexOf('mfaAwareSuccess')
  assert.ok(successAt > 0)
  assert.doesNotMatch(toggle.slice(successAt, lastCatchAt), /rollbackUserStatus/, '成功路径不得回滚乐观状态')
})

test('自动备份非 quiet 读取使用可取消最新会话，关闭与卸载均作废', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /createLatestReadSession\(\)/)
  const fetcher = section(page, 'const fetchAutoBackup = async', 'const onAutoBackupOpened')
  assert.match(fetcher, /autoBackupReadSession\.run/)
  assert.match(fetcher, /signal/)
  const quiet = section(fetcher, 'if (quiet) {', 'await autoBackupReadSession.run')
  assert.doesNotMatch(quiet, /autoBackupForm|autoBackupLoading\.value|autoBackupLoaded\.value\s*=\s*true/, 'quiet 轮只能更新列表与执行时间')
  assert.match(fetcher, /onSuccess:[\s\S]*?autoBackupLoaded\.value = true/, '只有当前非 quiet 成功读取能开放保存')
  assert.match(page, /@close="onAutoBackupClosed"/)
  assert.match(page, /const onAutoBackupClosed =[\s\S]*?autoBackupReadSession\.invalidate\(\)/)
  const unmounted = section(page, 'onUnmounted(() => {', 'const onTlsFile')
  assert.match(unmounted, /autoBackupReadSession\.invalidate\(\)/)
})
