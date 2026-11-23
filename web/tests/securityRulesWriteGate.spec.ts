// SecurityRules 写函数必须自带函数级只读早退：按钮 disabled 只是交互层
// 兜底，键盘/程序化调用/未来新入口都能绕过。只读 = 全局只读契约或从节点。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'

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
    const at = text.indexOf(marker)
    assert.ok(at >= 0, `缺少写函数：${marker}`)
    const head = text.slice(at, at + 320)
    assert.match(
      head,
      /if \(writeBlocked\(\)(?:\s*\|\|\s*[^)]+)?\) return/,
      `${marker} 缺少函数级只读早退（仅靠按钮 disabled 不够）`,
    )
  }
})
