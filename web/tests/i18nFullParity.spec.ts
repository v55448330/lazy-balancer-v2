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
import { readdirSync } from 'node:fs'
import { relative } from 'node:path'
import { fileURLToPath } from 'node:url'

import { i18n } from '../src/i18n/index.ts'
import { code } from './_helpers.ts'

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
// 键集 parity 只证明「两侧一致」，不证明「源码引用的键存在」——同一个裸键在
// zh/en 双侧同时缺失时 parity 恒绿（历史：autoBackup.sat/sun 双侧缺失，周日/
// 周六下拉项直接渲染裸键）。此守卫扫描 src 下所有字面量 t()/tSafe() 调用，
// 断言每个静态键都能在运行期挂载树中解析。
test('源码字面量 t()/tSafe() 引用键必须在挂载树中存在（双侧同时缺失兜底）', () => {
  const webRoot = fileURLToPath(new URL('../', import.meta.url))
  const srcRoot = fileURLToPath(new URL('../src/', import.meta.url))
  const files: string[] = []
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`
      if (entry.isDirectory()) walk(path)
      else if (entry.name.endsWith('.vue') || entry.name.endsWith('.ts')) files.push(path)
    }
  }
  walk(srcRoot)

  const messages = i18n.global.messages.value as Record<string, { app?: LocaleTree; common?: { app?: LocaleTree } }>
  const zhApp = messages['zh-CN'].app
  const zhCommonApp = messages['zh-CN'].common?.app
  assert.ok(zhApp && zhCommonApp, 'i18n 实例必须挂载 zh-CN 的 app/common.app 树')

  const resolve = (tree: unknown, path: string): unknown =>
    path.split('.').reduce<unknown>((node, key) => (typeof node === 'object' && node !== null ? (node as LocaleTree)[key] : undefined), tree)

  const KEY_CALL = /(?<![\w$])(?:\$t|tSafe|t)\(\s*['"]([^'"\\]*(?:\\.[^'"\\]*)*)['"]/g
  const missing: string[] = []
  const seen = new Set<string>()
  for (const file of files) {
    const text = code(relative(webRoot, file).split('\\').join('/'))
    for (const match of text.matchAll(KEY_CALL)) {
      const key = match[1]
      // 非静态键：模板插值（本正则不匹配反引号）、拼接前缀（尾部 . 或 _）、
      // 文档示例（含 *）不参与。
      if (!key || key.includes('*') || key.endsWith('.') || key.endsWith('_')) continue
      let tree: unknown
      let path: string
      if (key.startsWith('common.app.')) {
        tree = zhCommonApp
        path = key.slice('common.app.'.length)
      } else if (key.startsWith('app.')) {
        tree = zhApp
        path = key.slice('app.'.length)
      } else {
        continue // 非本树前缀（不存在于本仓库调用点）
      }
      if (seen.has(key)) continue
      seen.add(key)
      if (resolve(tree, path) === undefined) missing.push(key)
    }
  }

  // 扫描面下限：防止 walk/正则失效后空集假绿。
  assert.ok(seen.size > 1000, `静态 t() 键扫描面过小（${seen.size}）——扫描失效`)
  assert.deepEqual(missing.sort(), [], '源码引用但词表缺失的键（zh 缺失即 zh 裸键；en 由 parity 保证）')
})
