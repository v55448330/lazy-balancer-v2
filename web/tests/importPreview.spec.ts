// 导入预览校验的复用层：分类勾选只改后端过滤口径，备份字节不变——修复前每次
// 勾选都重传整份备份（上限 128MB）。现在按「内容指纹 + 所选分类」缓存结果，
// 并在分类连续切换时取消在途请求。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createImportPreviewSession, importPreviewFingerprint, invalidateImportPreviews } from '../src/utils/importPreview.ts'
import type * as ImportPreviewModule from '../src/utils/importPreview.ts'
import { importSummaryLabel } from '../src/utils/importSummaryLabels.ts'
import { code, deferred, repoCode, section } from './_helpers.ts'

const instrumentBlobReads = (content: Blob) => {
  const slices: Array<[number, number]> = []
  const reads: number[] = []
  const wholeReads: number[] = []
  const slice = content.slice.bind(content)
  const arrayBuffer = content.arrayBuffer.bind(content)
  content.slice = (start?: number, end?: number, contentType?: string): Blob => {
    slices.push([start ?? 0, end ?? content.size])
    const part = slice(start, end, contentType)
    const readPart = part.arrayBuffer.bind(part)
    part.arrayBuffer = async (): Promise<ArrayBuffer> => {
      reads.push(part.size)
      return readPart()
    }
    return part
  }
  content.arrayBuffer = async (): Promise<ArrayBuffer> => {
    wholeReads.push(content.size)
    return arrayBuffer()
  }
  return { slices, reads, wholeReads }
}

test('同一份备份 + 同一分类集合只发一次请求（回到已看过的分类不重传）', async () => {
  const sent: string[] = []
  const session = createImportPreviewSession<{ sections: string }>({
    fingerprint: 'fp-a',
    send: async (sections) => {
      sent.push([...sections].join(','))
      return { sections: sections.join(',') }
    },
  })
  const first = await session.validate(['users', 'rules'])
  const again = await session.validate(['rules', 'users'])
  assert.equal(first.cached, false)
  assert.equal(again.cached, true, '同一分类集合（顺序无关）必须命中缓存')
  assert.equal(again.value.sections, 'users,rules')
  assert.deepEqual(sent, ['users,rules'], '缓存命中不得再发请求')
})

test('不同分类集合才发新请求，且上一轮在途请求被取消', async () => {
  const signals: AbortSignal[] = []
  const firstGate = deferred<{ mark: string }>()
  const session = createImportPreviewSession<{ mark: string }>({
    fingerprint: 'fp-abort',
    send: (_sections, signal) => {
      signals.push(signal)
      return signals.length === 1 ? firstGate.promise : Promise.resolve({ mark: 'second' })
    },
  })
  const stale = session.validate(['users'])
  const fresh = session.validate(['rules'])
  assert.equal(signals[0]?.aborted, true, '新选择必须取消上一轮在途的整份备份上传')
  assert.equal(signals[1]?.aborted, false)
  assert.equal((await fresh).value.mark, 'second')
  firstGate.reject(new Error('aborted by supersede'))
  await assert.rejects(stale)
})

test('缓存按内容指纹隔离：换了一份备份后同分类集合必须重新校验', async () => {
  const sent: string[] = []
  const make = (fingerprint: string) => createImportPreviewSession<string>({
    fingerprint,
    send: async () => { sent.push(fingerprint); return fingerprint },
  })
  assert.equal((await make('fp-1').validate(['users'])).value, 'fp-1')
  assert.equal((await make('fp-2').validate(['users'])).value, 'fp-2')
  assert.deepEqual(sent, ['fp-1', 'fp-2'])
})

test('失败不入缓存：同分类集合可重试', async () => {
  let calls = 0
  const session = createImportPreviewSession<string>({
    fingerprint: 'fp-retry',
    send: async () => {
      calls++
      if (calls === 1) throw new Error('network')
      return 'ok'
    },
  })
  await assert.rejects(session.validate(['users']))
  assert.equal((await session.validate(['users'])).value, 'ok')
  assert.equal(calls, 2, '失败必须可重试')
})

test('dispose 取消在途请求（关闭弹框不再白传整份备份）', async () => {
  const gate = deferred<string>()
  const signals: AbortSignal[] = []
  const session = createImportPreviewSession<string>({
    fingerprint: 'fp-dispose',
    send: (_sections, requestSignal) => {
      signals.push(requestSignal)
      return gate.promise
    },
  })
  const pending = session.validate(['users'])
  session.dispose()
  assert.equal(signals[0]?.aborted, true)
  gate.reject(new Error('aborted by dispose'))
  await assert.rejects(pending)
})

test('内容指纹：采样内容 + 长度决定，同一内容稳定、不同内容分离', async () => {
  const content = new Blob(['{"version":3,"sections":[]}'])
  assert.equal(await importPreviewFingerprint(content), await importPreviewFingerprint(new Blob(['{"version":3,"sections":[]}'])))
  assert.notEqual(await importPreviewFingerprint(content), await importPreviewFingerprint(new Blob(['{"version":3,"sections":[1]}'])))
  assert.notEqual(await importPreviewFingerprint(content), await importPreviewFingerprint('{"version":3,"sections":[]}'.repeat(2)))
  // 字符串（JSON 备份）与 lbbak Blob 各自稳定：同一文本两次选择要到同一缓存键
  const text = '{"version":3}'
  assert.equal(await importPreviewFingerprint(text), await importPreviewFingerprint(text))
})

test('内容指纹只读取首尾两个采样窗口（不整读 Blob）', async () => {
  const sample = 512 * 1024
  const big = new Blob(['x'.repeat(4 * 1024 * 1024)])
  const io = instrumentBlobReads(big)
  await importPreviewFingerprint(big)
  assert.deepEqual(io.slices, [[0, sample], [big.size - sample, big.size]], '必须恰好切首、尾两个窗口')
  assert.deepEqual(io.reads, [sample, sample], '实际 arrayBuffer 读取量必须等于两个采样窗口')
  assert.deepEqual(io.wholeReads, [], '不得直接整读原 Blob')

  const small = new Blob(['x'.repeat(1024)])
  const smallIO = instrumentBlobReads(small)
  await importPreviewFingerprint(small)
  assert.deepEqual(smallIO.slices, [[0, sample], [0, small.size]], '小文件尾部起点必须钳到 0')
  assert.deepEqual(smallIO.reads, [small.size, small.size])
  assert.deepEqual(smallIO.wholeReads, [])

  // 采样语义：仅中段不同（首尾窗口与长度相同）仍得到同一缓存键。这是纯函数的
  // 有意取舍（整份摘要要把 128MB 备份再复制一遍）；跨文件误命中由调用方在换文件
  // 时作废缓存兜住（见「组件接线」用例）。
  const head = 'a'.repeat(600 * 1024)
  const tail = 'z'.repeat(600 * 1024)
  const left = `${head}${'m'.repeat(2048)}${tail}`
  const right = `${head}${'n'.repeat(2048)}${tail}`
  assert.equal(await importPreviewFingerprint(left), await importPreviewFingerprint(right))
})

test('非安全上下文（无 crypto.subtle）同样可得指纹：HTTP 访问不影响选文件', async () => {
  // 面板常经 http://<host>:8000 访问——此时 crypto.subtle 不存在。
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  try {
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true, writable: true })
    assert.match(await importPreviewFingerprint(new Blob(['{"version":3}'])), /^fnv1a:/)
  } finally {
    // 用例前无 crypto 时也必须把注入的属性删掉（只在 descriptor 存在时还原会让
    // 假 crypto 残留在进程里，污染同进程后续用例的 WebCrypto 判定）。
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor)
    else Reflect.deleteProperty(globalThis, 'crypto')
    assert.equal(Object.getOwnPropertyDescriptor(globalThis, 'crypto')?.value, descriptor?.value, 'crypto 替身必须还原')
  }
})

test('缓存超过上限后淘汰最旧键，最新结果仍命中（长会话不无界增长）', async () => {
  // 缓存是模块级状态：查询串加载独立实例，避免受本文件其它用例已写入的键影响。
  const fresh = (await import(`../src/utils/importPreview.ts?evict=${Date.now()}`)) as typeof ImportPreviewModule
  let sends = 0
  const session = fresh.createImportPreviewSession<string>({
    fingerprint: 'fp-evict',
    send: async (sections) => { sends++; return sections.join(',') },
  })
  // 33 个不同分类组合 > 上限 32：最早的 k0 被淘汰
  for (let i = 0; i < 33; i++) {
    assert.equal((await session.validate([`k${i}`])).cached, false)
  }
  assert.equal((await session.validate(['k0'])).cached, false, '最旧键必须已淘汰（否则会话无界增长）')
  assert.equal((await session.validate(['k32'])).cached, true, '最新键必须仍在缓存（不得删最新）')
  // 重新插入的 k0 排到最新，淘汰顺延到 k1
  assert.equal((await session.validate(['k1'])).cached, false)
  assert.equal(sends, 35)
})

test('缓存命中刷新热度（LRU）：反复勾选的备份不被一次性条目挤出', async () => {
  // 缓存是模块级状态：查询串加载独立实例（上限 32 条）。
  const fresh = (await import(`../src/utils/importPreview.ts?lru=${Date.now()}`)) as typeof ImportPreviewModule
  const sends: string[] = []
  const session = fresh.createImportPreviewSession<string>({
    fingerprint: 'fp-lru',
    send: async (sections) => {
      sends.push(sections.join(','))
      return sections.join(',')
    },
  })
  // 填满 32 条：k0 最旧
  for (let i = 0; i < 32; i++) {
    assert.equal((await session.validate([`k${i}`])).cached, false)
  }
  // 再命中 k0（刷新其热度）→ 插入 k32 时被淘汰的应是最久未用的 k1
  assert.equal((await session.validate(['k0'])).cached, true)
  assert.equal((await session.validate(['k32'])).cached, false)
  assert.equal((await session.validate(['k0'])).cached, true, '刚命中的热条目必须仍在缓存（FIFO 会先淘汰它）')
  assert.equal((await session.validate(['k1'])).cached, false, '最久未用的 k1 必须已被淘汰')
})

test('组件接线：预览经会话复用，请求带 abort signal，关闭/换文件即取消', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const preview = section(page, 'const postImportValidation', 'const revalidateImport')
  assert.match(preview, /signal/, '预览请求必须可被取消')
  assert.match(preview, /\?sections=/, '预览必须携带 sections query')
  assert.doesNotMatch(preview, /JSON\.parse/, '预览不得为注入 sections 重新序列化请求体')

  const revalidate = section(page, 'const revalidateImport', 'const confirmImport')
  assert.match(revalidate, /const session = importPreviewSession/, '分类切换必须走会话缓存/取消层')
  assert.match(revalidate, /session\.validate\(sections\)/)
  assert.doesNotMatch(revalidate, /postImportValidation\(sections\)/, '分类切换不得直接重传备份')

  const upload = section(page, 'const handleImportFile', 'const postImportValidation')
  assert.match(upload, /const fingerprint = await importPreviewFingerprint\(importFileContent\.value\)/, '会话键来自内容指纹')
  assert.match(upload, /createImportPreviewSession<ImportValidation>\(\{\s*fingerprint,/)
  // 换文件必须作废预览缓存：指纹只采样首尾各 512KiB + 长度，同长度且改动落在
  // 中段的两份备份指纹相同 → 会显示上一份备份的预览结论，与导入实际结果不一致。
  assert.match(upload, /invalidateImportPreviews\(\)/, '同一弹框内换文件必须清空预览缓存')

  const closed = section(page, 'const onImportDialogClosed', 'const chooseImportFile')
  assert.match(closed, /importPreviewSession\?\.dispose\(\)/, '关闭弹框必须取消在途上传')
  assert.match(closed, /importPreviewSession = null/)
})

// 缓存时效：预览事实依赖服务端「当时」的库状态，跨会话常驻会让同一份备份在
// 配置改变后仍返回旧预览（例如刚删掉一个 CA 提供商，预览却说无悬挂告警）。
test('缓存有 TTL：超过有效期必须重新校验', async () => {
  const realNow = Date.now
  let now = 1_000_000
  Date.now = () => now
  try {
    const sent: string[] = []
    const session = createImportPreviewSession<string>({
      fingerprint: 'fp-ttl',
      send: async () => { sent.push('x'); return 'v' },
    })
    assert.equal((await session.validate(['users'])).cached, false)
    now += 4 * 60 * 1000
    assert.equal((await session.validate(['users'])).cached, true, '有效期内仍可复用')
    now += 2 * 60 * 1000
    assert.equal((await session.validate(['users'])).cached, false, '过期条目必须重新校验')
    assert.equal(sent.length, 2)
  } finally {
    Date.now = realNow
  }
})

test('invalidateImportPreviews 清空跨会话缓存，且弹框打开时调用它', async () => {
  const sent: string[] = []
  const session = createImportPreviewSession<string>({
    fingerprint: 'fp-invalidate',
    send: async () => { sent.push('x'); return 'v' },
  })
  await session.validate(['users'])
  assert.equal((await session.validate(['users'])).cached, true)
  invalidateImportPreviews()
  assert.equal((await session.validate(['users'])).cached, false)
  assert.equal(sent.length, 2)

  const page = code('src/views/settings/BasicSettings.vue')
  const trigger = section(page, 'const triggerImport = (): void =>', 'const onImportDialogClosed')
  assert.match(trigger, /invalidateImportPreviews\(\)/, '打开导入弹框必须清空预览缓存')
})

// ── 摘要标签：后端表集全覆盖（预览不得泄漏内部表名） ──────────────
test('导入摘要标签覆盖后端 configBackupTables 全集（跨栈单源）', () => {
  const backend = repoCode('internal/handlers/config_backup.go')
  const tableSet = section(backend, 'var configBackupTables = []string{', '}')
  const tables = [...tableSet.matchAll(/"([a-z0-9_]+)"/g)].map((m) => m[1])
  assert.ok(tables.length >= 18, `后端表集解析异常（仅 ${tables.length} 张）`)

  for (const table of tables) {
    const label = importSummaryLabel(table)
    assert.notEqual(label, table, `表 ${table} 缺中文标签——预览会直接显示内部表名`)
    assert.ok(label.trim().length > 0)
  }
  // 页面不再自带第二份键集（标签表单源 utils/importSummaryLabels）
  const page = code('src/views/settings/BasicSettings.vue')
  assert.match(page, /\{\{ importSummaryLabel\(key\) \}\}·\{\{ count \}\}/)
  assert.doesNotMatch(page, /const summaryLabels: Record<string, string>/, '页内标签表必须删除')
})

test('未知摘要键回退原键（fail-visible，不静默吞成空串）', () => {
  assert.equal(importSummaryLabel('security_new_table'), 'security_new_table')
  assert.equal(importSummaryLabel('security_policies'), '安全策略')
})

test('摘要键查表防原型键：constructor/toString 不得把原型函数当标签', () => {
  // 键来自后端 summary 的任意字符串；裸下标会把 Object.prototype 上的函数
  // 当成命中（truthy，绕过 `||` 回退），预览 chip 会渲染出函数源码。
  for (const key of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__']) {
    const label = importSummaryLabel(key)
    assert.equal(typeof label, 'string', `${key} 标签必须是字符串（原型链函数不得外泄）`)
    assert.equal(label, key, `${key} 必须按原文回退`)
  }
})
