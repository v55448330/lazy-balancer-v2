import { test } from 'node:test'
import assert from 'node:assert/strict'

import { existsSync } from 'node:fs'
import { code, repoCode, section } from './_helpers.ts'

// 审计列表 total 走后端 5 秒进程缓存并以 total_stale 披露来源；面板必须消费
// 该字段并在陈旧时给出可见提示——否则「列表条数与总数短暂不一致」对用户
// 完全不可见（与同视图 partial 下拉披露同一取向）。
const page = code('src/views/AuditLog.vue')

test('审计列表消费 total_stale 并驱动提示位', () => {
  assert.match(page, /const totalStale = ref\(false\)/)
  const fetchBody = section(page, 'const fetchLogs = async', 'onMounted(')
  assert.match(fetchBody, /total_stale\?: boolean/)
  assert.match(fetchBody, /totalStale\.value = res\.data\?\.total_stale === true/)
  // 提示只在陈旧时出现，且不与分页条重叠布局；批次 D(audit 域)双钉:
  // 调用点钉键,zh 母本(locales/zh/views.ts)钉提示原文(任一漂移必红)。
  assert.match(page, /<el-text v-if="totalStale"[^>]*>[\s\S]*?\{\{ t\('common\.app\.views\.audit\.totalStaleHint'\) \}\}[\s\S]*?<\/el-text>/)
  assert.ok(existsSync(new URL('../src/locales/zh/views.ts', import.meta.url)), '词条母本 src/locales/zh/views.ts 未落库(integrator 接线)')
  assert.ok(code('src/locales/zh/views.ts').includes('统计总数来自缓存，可能滞后数秒'), 'totalStaleHint zh 原文必须在 zh 母本词条中')
})

test('后端响应与文档示例都登记 total_stale', () => {
  const backend = repoCode('internal/handlers/auditlog.go')
  assert.match(backend, /"total_stale": totalStale/)
  // 文档钉（断言对象是 API 文档示例与注释文字，故用 raw 视图）
  const docs = repoCode('internal/handlers/apidocs.go')
  assert.match(docs, /"total_stale":false/)
  assert.match(docs, /total_stale=true 表示本次计数来自缓存/)
})
