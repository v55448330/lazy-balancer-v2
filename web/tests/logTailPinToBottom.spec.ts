// 日志尾部轮询:写回后仅在用户贴底时才滚底——用户上翻阅读历史日志时不得被
// 每轮轮询拉回底部(五处消费方:Rules/CertJobs/TaskMonitor/BasicSettings/
// CaddyGlobalSettings)。贴底判定抽成导出纯函数 isPinnedToBottom(三形状:
// 贴底 / 上翻 / clientHeight 不可得)并钉行为级:判定取「写回前」的容器状态
// (内容变长后浏览器不会自动跟随,写回后再量会把贴底用户误判成上翻)。

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ref } from 'vue'

import { isPinnedToBottom, useLogTailPolling } from '../src/composables/useLogTailPolling.ts'

test('isPinnedToBottom:贴底与容差内(≤8px)视为贴底', () => {
  assert.equal(isPinnedToBottom({ scrollTop: 900, scrollHeight: 1000, clientHeight: 100 }), true)
  assert.equal(isPinnedToBottom({ scrollTop: 892, scrollHeight: 1000, clientHeight: 100 }), true, '距底 8px 仍在容差内')
  assert.equal(isPinnedToBottom({ scrollTop: 891, scrollHeight: 1000, clientHeight: 100 }), false, '距底 9px 视为已上翻')
  assert.equal(isPinnedToBottom({ scrollTop: 0, scrollHeight: 1000, clientHeight: 100 }), false, '长日志上翻到顶不是贴底')
})

test('isPinnedToBottom:clientHeight 不可得时视为贴底(保持旧行为)', () => {
  assert.equal(isPinnedToBottom({ scrollTop: 0, scrollHeight: 1000 }), true)
  assert.equal(isPinnedToBottom({ scrollTop: 0, scrollHeight: 1000, clientHeight: Number.NaN }), true)
})

test('用户贴底时写回滚到新底部(贴底判定取写回前状态)', async () => {
  const content = ref('old')
  // 假 DOM:内容变化后 scrollHeight 随之变长(与真实浏览器一致——浏览器不会
  // 自动跟随,贴底与否必须按写回前的度量判定)。
  const el = {
    scrollTop: 0,
    get scrollHeight(): number { return content.value === 'old' ? 200 : 480 },
    clientHeight: 200,
  }
  const container = ref<typeof el | null>(el)
  const tail = useLogTailPolling({
    interval: 60_000,
    content,
    container,
    isActive: () => true,
    fetch: async () => 'a\nb\nc',
  })
  await tail.refresh()
  assert.equal(el.scrollTop, 480, '贴底用户必须跟随到新底部')
  tail.stop()
})

test('用户上翻阅读时写回不滚底(不被强制拉回底部)', async () => {
  const content = ref('old')
  const el = { scrollTop: 0, scrollHeight: 2000, clientHeight: 200 }
  const container = ref<typeof el | null>(el)
  const tail = useLogTailPolling({
    interval: 60_000,
    content,
    container,
    isActive: () => true,
    fetch: async () => 'new-line\n'.repeat(50),
  })
  await tail.refresh()
  assert.equal(content.value, 'new-line\n'.repeat(50))
  assert.equal(el.scrollTop, 0, '上翻到顶的用户不得被拉回底部')
  tail.stop()
})

test('客户端高度缺失时保持旧行为:写回即滚底', async () => {
  const content = ref('')
  const el = { scrollTop: 0, scrollHeight: 999 }
  const container = ref<typeof el | null>(el)
  const tail = useLogTailPolling({
    interval: 60_000,
    content,
    container,
    isActive: () => true,
    fetch: async () => 'line1\nline2',
  })
  await tail.refresh()
  assert.equal(el.scrollTop, 999)
  tail.stop()
})
