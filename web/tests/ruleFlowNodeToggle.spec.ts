// 规则流程弹框的节点卡折叠语义：卡片对读屏声明 aria-expanded，因此点击必须是
// 真 toggle——再次点击同一环节收起面板。原实现恒赋值（activeNode = key），
// 承诺「可展开/收起」却永远收不起来：指针用户再点无效，键盘用户看不到任何
// 状态变化，而 aria-expanded 的语义与行为不一致（对 assistive tech 撒谎）。
//
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），
// toggleNode 依赖组件内 ref——用「限段 + 结构」文本钉住决策路径与模板绑定。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'

const DIALOG = 'src/components/RuleFlowDialog.vue'

test('再次点击同一环节收起（activeNode 与二级明细键一并清空）', () => {
  const text = code(DIALOG)
  const toggle = member(text, 'const toggleNode = (key: string): void =>')
  const collapsed = section(toggle, 'if (activeNode.value === key)', '\n  }')
  assert.match(collapsed, /activeNode\.value = ''/, '同一节点必须收起（原实现恒赋值=收不起来）')
  assert.match(collapsed, /expandedPolicyKey\.value = ''/, '收起时二级明细键同步清空（否则下次展开直接弹出上一轮明细）')
  assert.match(collapsed, /return/, '收起后必须直接返回，不得继续走「展开」路径')
  // 收起分支必须排在赋值之前：放在后面就永远执行不到
  const guardAt = toggle.indexOf('activeNode.value === key')
  const assignAt = toggle.indexOf('activeNode.value = key')
  assert.ok(guardAt > 0 && assignAt > guardAt, '同键判断必须先于展开赋值')
})

test('展开路径保持原语义：设置节点键、清空二级明细、阶段面板触发拉取', () => {
  const text = code(DIALOG)
  const toggle = member(text, 'const toggleNode = (key: string): void =>')
  assert.match(toggle, /activeNode\.value = key/)
  assert.match(toggle, /if \(key\.startsWith\('stage'\)\) void ensureDetails\(\)/, '阶段面板首次选中仍触发明细拉取')
  // 接入/上游面板无明细：不得对它们发起拉取
  assert.doesNotMatch(toggle, /ensureDetails\(\)\s*\n\s*\{/, '拉取门仍是阶段前缀')
})

test('aria-expanded 绑定同一状态（承诺与行为同源）', () => {
  const text = code(DIALOG)
  assert.match(
    text,
    /:aria-expanded="activeNode === node\.key"/,
    'aria-expanded 必须绑定 activeNode 判定（承诺的状态就是收起/展开的真实状态）',
  )
  // 点击入口接的就是 toggleNode（不是另一套展开逻辑）
  assert.match(text, /@click="toggleNode\(node\.key\)"/)
})
