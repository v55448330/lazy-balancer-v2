// audit153 FE153-01 跨栈对表：internal/notify/catalog.go 是事件目录唯一事实源，
// 前端 eventTitles（zh/en）只是它的展示投影。缺词条=通知中心显示裸事件 ID；
// 多词条=无发布点的臆造键。双向钉死（缺/多均红），zh 标题必须与 Go TitleFormat
// 同文（zh 母本不是「随便起的中文名」）。
//
// 仅两个显式豁免（都不在 catalog 里，理由见常量注释）：
//   sys.daily_report —— 日报拆独立区块，事件键保留供投递记录展示；
//   channel.test     —— 前端「通道测试」伪事件，无后端发布点。
//
// 运行：cd web && npm test
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { repoCode } from './_helpers.ts'
import zhLocale from '../src/locales/zh/notifications.ts'
import enLocale from '../src/locales/en/notifications.ts'

const NON_CATALOG_TITLES: Record<string, string> = {
  'sys.daily_report': '日报不进订阅目录（per-user 配置+独立区块），事件键保留供投递记录展示',
  'channel.test': '前端「通道测试」伪事件（后端无发布点）',
}

// catalog 常量存在但刻意不进条目（日报拆独立区块，见 catalog.go 注释）：
const DECLARED_NOT_CATALOGED = new Set(['sys.daily_report'])

const zh: Record<string, string> = zhLocale.app.notification.eventTitles
const en: Record<string, string> = enLocale.app.notification.eventTitles

/** catalog.go → 事件 ID → Title（EvtXxx 常量折叠到 id）。 */
const parseCatalogTitles = (): Map<string, string> => {
  const src = repoCode('internal/notify/catalog.go')
  const constToID = new Map<string, string>()
  for (const m of src.matchAll(/^\s*(Evt[A-Za-z0-9_]+)\s*=\s*"([a-z0-9_.]+)"/gm)) {
    constToID.set(m[1], m[2])
  }
  assert.ok(constToID.size > 40, `catalog 常量解析异常（${constToID.size}）——扫描器失效`)
  const titles = new Map<string, string>()
  for (const m of src.matchAll(/^\s*\{(Evt[A-Za-z0-9_]+),\s*Level[A-Za-z]+,\s*(?:true|false),\s*"([^"]*)"/gm)) {
    const id = constToID.get(m[1])
    assert.ok(id, `catalog 条目引用了未声明的常量 ${m[1]}`)
    titles.set(id, m[2])
  }
  const uncataloged = [...constToID].filter(([, id]) => !titles.has(id) && !DECLARED_NOT_CATALOGED.has(id))
  assert.deepEqual(uncataloged.map(([name]) => name), [], '事件常量必须在 catalog 条目里有标题（除日报豁免）')
  return titles
}

test('事件标题对表：catalog ID ↔ zh/en eventTitles 双向零缺零多', () => {
  const titles = parseCatalogTitles()
  const catalogIDs = new Set(titles.keys())

  const missingZh = [...catalogIDs].filter((id) => !(id in zh))
  const missingEn = [...catalogIDs].filter((id) => !(id in en))
  assert.deepEqual(missingZh, [], `zh eventTitles 缺 ${missingZh.length} 个目录事件`)
  assert.deepEqual(missingEn, [], `en eventTitles 缺 ${missingEn.length} 个目录事件`)

  const extrasZh = Object.keys(zh).filter((id) => !catalogIDs.has(id) && !(id in NON_CATALOG_TITLES))
  const extrasEn = Object.keys(en).filter((id) => !catalogIDs.has(id) && !(id in NON_CATALOG_TITLES))
  assert.deepEqual(extrasZh, [], 'zh eventTitles 出现目录外键（臆造/已下线事件）')
  assert.deepEqual(extrasEn, [], 'en eventTitles 出现目录外键（臆造/已下线事件）')

  // 豁免键两侧都必须存在（删日报/通道测试词条同样会回落裸键）
  for (const id of Object.keys(NON_CATALOG_TITLES)) {
    assert.ok(id in zh, `zh 缺豁免键 ${id}`)
    assert.ok(id in en, `en 缺豁免键 ${id}`)
  }
})

test('事件标题对表：zh 文案与 catalog TitleFormat 同文，en 全部已翻译（非空且不残留中文）', () => {
  const titles = parseCatalogTitles()
  const drift: string[] = []
  for (const [id, title] of titles) {
    if (zh[id] !== title) drift.push(`${id}: zh「${zh[id]}」≠ catalog「${title}」`)
  }
  assert.deepEqual(drift, [], `zh 标题与 catalog 原文漂移:\n${drift.join('\n')}`)

  const untranslated = Object.entries(en)
    .filter(([id, value]) => !(id in NON_CATALOG_TITLES) && /[\u4e00-\u9fa5]/.test(value))
    .map(([id, value]) => `${id}: ${value}`)
  assert.deepEqual(untranslated, [], 'en eventTitles 残留中文（未翻译）')
  const blank = Object.entries(en).filter(([, value]) => !value.trim()).map(([id]) => id)
  assert.deepEqual(blank, [], 'en eventTitles 存在空值')
})
