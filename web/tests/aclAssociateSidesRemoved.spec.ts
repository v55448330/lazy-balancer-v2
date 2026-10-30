// 残留守卫：securityStages 的 aclAssociateSides 已删除且零
// 消费。全仓 web/src 扫描，符号回归（重新实现/重新引用）即红。
//
// 扫描走 raw 视图（source 而非 code）：删除类守卫的语义是「符号不得再出现」，
// 连注释/字符串里的残留提及都算审计残留——剥注释视图反而会放过这类残留。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { source, webFiles } from './_helpers.ts'

const REMOVED_SYMBOL = 'aclAssociateSides'
const ANCHOR_FILE = 'src/utils/securityStages.ts'

test('aclAssociateSides 已从 web/src 全量移除且零消费', () => {
  const files = webFiles('src', ['.ts', '.vue'])
  assert.ok(files.length > 0, 'web/src 源文件清单为空——守卫空转')
  // 锚点必须在扫描面内：securityStages.ts 缺席说明目录/清单漂移，守卫假绿。
  assert.ok(files.includes(ANCHOR_FILE), `守卫锚点 ${ANCHOR_FILE} 不在扫描清单内`)
  const offenders = files.filter((file) => source(file).includes(REMOVED_SYMBOL))
  assert.deepEqual(offenders, [], `aclAssociateSides 残留于: ${offenders.join(', ')}`)
})
