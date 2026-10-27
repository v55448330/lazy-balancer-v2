import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ADMIN1_PROVINCES } from '../src/utils/admin1Provinces.ts'
import { source } from './_helpers.ts'

test('省界资源头注释与实际要素和国家地区键数一致', () => {
  const countries = Object.keys(ADMIN1_PROVINCES).length
  const provinces = Object.values(ADMIN1_PROVINCES).reduce((total, rows) => total + rows.length, 0)
  assert.equal(countries, 251)
  assert.equal(provinces, 4600)
  const header = source('src/utils/admin1Provinces.ts').split('\n').slice(0, 7).join('\n')
  assert.match(header, /4600 要素\/251 个国家和地区键/)
  assert.match(header, /含特殊地区/)
})
