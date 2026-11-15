// 全量 zh/en 键集 parity 守卫：i18n/index.ts 深合并后的完整词条树
// （commonApp 归一形态，即运行期 messages.app 实际挂载的树）两侧键集必须
// 完全一致——域级守卫（ccProtectionContracts 等）只覆盖各自改动域，
// 其他域的单侧漏译/裸键在此全量兜底。
//
// leafPaths 模式提升自 ccProtectionContracts（编译期常量树按记录收窄递归）。
// geo.provinces 为有意不对称映射（zh 市名即源文，消费方仅 en 侧映射且带
// 裸键回退守卫），显式豁免。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { i18n } from '../src/i18n/index.ts'

type LocaleTree = { [key: string]: unknown }

const leafPaths = (node: unknown, prefix = ''): string[] => {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return prefix ? [prefix] : []
  const record = node as LocaleTree
  return Object.entries(record).flatMap(([key, value]) => leafPaths(value, prefix ? `${prefix}.${key}` : key))
}

test('全量双语 parity：深合并后 zh/en 完整树键集一致（无单侧裸键）', () => {
  // 直接取运行期实例的挂载树（index.ts 已做 deepMerge + commonApp 归一），
  // 不在测试里复刻第二份合并实现——合并口径漂移时本守卫跟随真实树。
  const messages = i18n.global.messages.value as Record<string, LocaleTree>
  const zh = messages['zh-CN'].app
  const en = messages.en.app
  assert.ok(zh && en, 'i18n 实例必须挂载 zh-CN/en 双侧 app 树')

  const PARITY_EXEMPT_PREFIXES = ['security.policies.geo.provinces.']
  const exempt = (key: string): boolean => PARITY_EXEMPT_PREFIXES.some((p) => key.startsWith(p))
  const zhKeys = new Set(leafPaths(zh).filter((key) => !exempt(key)))
  const enKeys = new Set(leafPaths(en).filter((key) => !exempt(key)))

  // 扫描面下限：防树装配失效后空集假绿（当前全量四千余键）。
  assert.ok(zhKeys.size > 1000, `zh 键集过小（${zhKeys.size}）——树装配失效`)
  assert.ok(enKeys.size > 1000, `en 键集过小（${enKeys.size}）——树装配失效`)

  const zhOnly = [...zhKeys].filter((key) => !enKeys.has(key))
  const enOnly = [...enKeys].filter((key) => !zhKeys.has(key))
  assert.deepEqual(zhOnly, [], 'zh 独有键（en 缺译 → 英文界面裸键）必须为空')
  assert.deepEqual(enOnly, [], 'en 独有键（zh 缺失）必须为空')
})