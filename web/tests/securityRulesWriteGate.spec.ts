// SecurityRules 写函数必须自带函数级只读早退：按钮 disabled 只是交互层
// 兜底，键盘/程序化调用/未来新入口都能绕过。只读 = 全局只读契约或从节点。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member } from './_helpers.ts'

const RULES = 'src/views/security/SecurityRules.vue'

const WRITE_FUNCTIONS = [
  'const toggleSourceFlag = async (',
  'const toggleLibAutoUpdate = async (row: LibRow, val: boolean)',
  'const toggleIP2RegionV6 = async (',
  'const saveIpList = async ()',
  'const deleteIpList = (row: IPListRow)',
  'const saveCRSSchedule = async (',
  'const saveIP2RegionSchedule = async (',
  'const saveThreatSchedule = async (',
  'const saveCrawlerSchedule = async (',
  'const saveCustomRule = async ()',
  'const deleteCustomRule = (row: CustomRule)',
]

test('只读门单源：isReadOnly ∨ isSlaveNode', () => {
  const text = code(RULES)
  assert.match(
    text,
    /const writeBlocked = \(\): boolean => isReadOnly\.value \|\| isSlaveNode\.value/,
    '写门必须是 isReadOnly/isSlaveNode 单源（不得各处手写不同条件）',
  )
})

test('每个写函数首部有函数级只读早退', () => {
  const text = code(RULES)
  for (const marker of WRITE_FUNCTIONS) {
    assert.ok(text.includes(marker), `缺少写函数：${marker}`)
    // 花括号配对取函数体（不再用「起点+320 字符」定长窗口）：定长窗口在函数
    // 头注释/参数展开变长时假红，窗口内混入另一处早退时假绿；early return 只
    // 允许出现在函数体的**首条语句**位置。
    const body = member(text, marker)
    const firstStatement = body.slice(body.indexOf('{\n') + 2).trimStart()
    assert.match(
      firstStatement,
      /^if \(writeBlocked\(\)(?:\s*\|\|\s*[^)]+)?\) return/,
      `${marker} 缺少函数级只读早退（仅靠按钮 disabled 不够）`,
    )
  }
})
