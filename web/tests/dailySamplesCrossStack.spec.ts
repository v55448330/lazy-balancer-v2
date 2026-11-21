// 日报跨栈对表（前端预览样例/模块词条 ↔ 后端 DailyItemIDs/dailySections）：
// 后端新增日报项目而前端样例缺键 → 预览残留 {{key}}；模块词条缺键 → en 界面
// 直出后端中文。单侧改动必须红。
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { repoCode, section } from './_helpers.ts'
import { dailySampleValues } from '../src/utils/dailySamples.ts'

const go = repoCode('internal/notify/daily_report.go')

const goItemIDs = (): string[] => {
  const block = section(go, 'var DailyItemIDs = []string{', '}')
  return [...block.matchAll(/"([a-z0-9_]+)"/g)].map(m => m[1])
}

interface GoSection { title: string; items: string[] }
const goSections = (): GoSection[] => {
  const block = go.slice(go.indexOf('var dailySections = []struct'), go.indexOf('// DailyModuleExport'))
  const rows: GoSection[] = []
  for (const m of block.matchAll(/\{"[^"]*",\s*"([^"]+)",\s*\[\]string\{([^}]*)\}\}/g)) {
    rows.push({ title: m[1], items: [...m[2].matchAll(/"([a-z0-9_]+)"/g)].map(x => x[1]) })
  }
  return rows
}

test('日报预览样例值键集覆盖后端 DailyItemIDs（+date），无缺键无幽灵键', () => {
  const samples = Object.fromEntries(dailySampleValues)
  const ids = goItemIDs()
  assert.ok(ids.length >= 20, `DailyItemIDs 解析异常（${ids.length}）——扫描器失效`)
  const missing = ids.filter(id => !(id in samples))
  assert.deepEqual(missing, [], `样例缺键（预览将残留 {{key}}）: ${missing.join(', ')}`)
  const known = new Set([...ids, 'date'])
  const ghost = Object.keys(samples).filter(k => !known.has(k))
  assert.deepEqual(ghost, [], `样例幽灵键（后端无此项目）: ${ghost.join(', ')}`)
})

test('每日摘要模块词条：zh/en daily.modules.modN 与后端 dailySections 同序同数', async () => {
  const sections = goSections()
  assert.ok(sections.length >= 5, `dailySections 解析异常（${sections.length}）`)
  const [{ default: zh }, { default: en }] = await Promise.all([
    import('../src/locales/zh/notifications.ts'),
    import('../src/locales/en/notifications.ts'),
  ]) as Array<{ default: { app: { notification: { daily: { modules?: Record<string, string> } } } } }>
  const zhMods = zh.app.notification.daily.modules ?? {}
  const enMods = en.app.notification.daily.modules ?? {}
  assert.deepEqual(Object.keys(enMods).sort(), Object.keys(zhMods).sort(), 'zh/en 模块词条必须同位')
  sections.forEach((sec, i) => {
    const key = `mod${i + 1}`
    assert.equal(zhMods[key], sec.title, `${key} 中文词条必须与后端分节标题同文`)
    assert.ok(enMods[key], `${key} 缺 en 词条（en 界面将直出中文）`)
    assert.ok(!/[\u4e00-\u9fa5]/.test(enMods[key]), `${key} en 词条不得残留中文`)
    assert.notEqual(enMods[key], sec.title, `${key} en 词条必须是翻译而非直传中文`)
  })
})

test('模块勾选分组：各模块 items 并集=DailyItemIDs（分组不漏项不造项）', () => {
  const ids = new Set(goItemIDs())
  const union = new Set(goSections().flatMap(s => s.items))
  const missing = [...ids].filter(id => !union.has(id))
  const ghost = [...union].filter(id => !ids.has(id))
  assert.deepEqual(missing, [], `模块分组漏掉项目: ${missing.join(', ')}`)
  assert.deepEqual(ghost, [], `模块分组含未知项目: ${ghost.join(', ')}`)
})
