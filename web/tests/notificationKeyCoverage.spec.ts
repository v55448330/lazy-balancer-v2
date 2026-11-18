// 裸键守卫：通知中心+API 接入相关页面的全部 t('app.notification.*') 键引用
// 必须存在于 zh/en 词条树——模板臆造键名（裸键直出）永久绝迹。
// 运行：cd web && node --test tests/notificationKeyCoverage.spec.ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const files = [
  'src/views/Keys.vue',
  ...readdirSync(join(root, 'src/views/notifications')).map(f => `src/views/notifications/${f}`),
  ...readdirSync(join(root, 'src/views/settings')).map(f => `src/views/settings/${f}`),
]

type Dict = Record<string, unknown>

const flatten = (node: Dict, prefix: string, out: Record<string, unknown>): Record<string, unknown> => {
  for (const [k, v] of Object.entries(node)) {
    const p = prefix ? `${prefix}.${k}` : k
    if (typeof v === 'object' && v !== null) flatten(v as Dict, p, out)
    else out[p] = v
  }
  return out
}

test('裸键守卫：页面引用的 app.notification.* 键全部在词条树内（zh/en 双侧）', async () => {
  const { default: zh } = await import(join(root, 'src/locales/zh/notifications.ts'))
  const { default: en } = await import(join(root, 'src/locales/en/notifications.ts'))
  const zhTree = flatten((zh as { app?: Dict }).app as Dict, 'app', {})
  const enTree = flatten((en as { app?: Dict }).app as Dict, 'app', {})

  const missing: string[] = []
  const used = new Set<string>()
  for (const rel of files) {
    if (!rel.endsWith('.vue')) continue
    const src = readFileSync(join(root, rel), 'utf8')
    for (const m of src.matchAll(/[^\w$](?:t|S)\(\s*['"`](app\.notification\.[A-Za-z0-9_.]+)['"`]/g)) {
      const key = m[1]
      used.add(`${rel} → ${key}`)
      if (!(key in zhTree)) missing.push(`${rel} → ${key}（zh 缺失）`)
      if (!(key in enTree)) missing.push(`${rel} → ${key}（en 缺失）`)
    }
  }
  assert.ok(used.size > 50, `扫描键引用数异常（${used.size}）——扫描器失效`)
  assert.deepEqual(missing, [], `裸键（模板引用但词条树缺失）:\n${missing.join('\n')}`)
})
