// 规则流程弹框的证书到期时间必须与规则列表同一展示口径（配置时区换算）。
// 后端 not_after 是 UTC 墙钟串，直出会让弹框显示 UTC 而列表显示配置时区——
// 同一条证书两处相差时区偏移（管理员按错的时间判断续期）。列表侧用
// formatDate(not_after)（web/src/views/Rules.vue），弹框必须一致；后端不改。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, codeSection } from './_helpers.ts'

test('规则流程弹框的证书到期时间走 formatDate（配置时区口径）', () => {
  const dialog = code('src/components/RuleFlowDialog.vue')
  assert.match(dialog, /import \{ formatDate \} from '@\/utils\/date'/, '弹框必须复用全局 formatDate（单源时区口径）')

  const cell = codeSection('src/components/RuleFlowDialog.vue', 'flow-kv-label">到期时间</span>', '</div>')
  assert.match(cell, /formatDate\(certInfo\.not_after\)/, '到期时间必须经 formatDate 换算')
  assert.doesNotMatch(
    cell,
    /\{\{ certInfo\.not_after \|\| '-' \}\}/,
    '禁止直出 UTC 墙钟（与规则列表口径分裂）',
  )
})

test('规则列表侧的到期时间为同一口径（对照钉）', () => {
  const rules = code('src/views/Rules.vue')
  assert.match(rules, /formatDate\(certInfoMap\[row\.caddy_id\]\?\.not_after \|\| ''\)/, '列表侧口径是基准，两侧必须一致')
})
