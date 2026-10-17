import { test } from 'node:test'
import assert from 'node:assert/strict'

import { normalizeRateLimitBlocks } from '../src/utils/rateLimitBlocks.ts'

test('null data -> empty hosts, total 0', () => {
  assert.deepEqual(normalizeRateLimitBlocks(null), { total: 0, hosts: [] })
})

test('hosts:null from legacy backend -> empty array (no .length crash)', () => {
  assert.deepEqual(normalizeRateLimitBlocks({ total: 0, hosts: null }), { total: 0, hosts: [] })
})

test('valid hosts are preserved and sorted data untouched', () => {
  assert.deepEqual(
    normalizeRateLimitBlocks({ total: 21, hosts: [{ host: 'a.example', count: 14 }, { host: 'b.example', count: 7 }] }),
    { total: 21, hosts: [{ host: 'a.example', count: 14 }, { host: 'b.example', count: 7 }] },
  )
})

test('malformed host entries are dropped without throwing', () => {
  assert.deepEqual(
    normalizeRateLimitBlocks({ total: 3, hosts: [null, { host: 'ok.example', count: 3 }, { count: 9 }] } as unknown),
    { total: 3, hosts: [{ host: 'ok.example', count: 3 }] },
  )
})
