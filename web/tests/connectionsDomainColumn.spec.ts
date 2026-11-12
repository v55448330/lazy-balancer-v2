import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code } from './_helpers.ts'

test('连接监控域名列不换行：省略号+悬浮完整，路径列让宽', () => {
  const page = code('src/components/ConnectionsDialog.vue')
  assert.match(page, /class="conn-mono conn-host" :title="row\.host"/, '域名列必须带完整 title')
  assert.match(page, /connColHost'\)" min-width="170" show-overflow-tooltip/, '域名列需更宽并启用溢出 tooltip')
  assert.match(page, /\.conn-host \{[^}]*white-space: nowrap;/, '域名不得换行')
  assert.match(page, /\.conn-host \{[^}]*text-overflow: ellipsis;/, '超长用省略号')
  assert.match(page, /connColUri'\)" min-width="110"/, '路径列适当让宽给域名')
})
