// 规则绑定编辑器「清空全部安全策略」的保存确认（可用性变更披露）。
//
// 规则模式的保存是「按提交集全量替换」：该规则原本有绑定、用户把四个阶段的分区
// 全部取消勾选后直接保存，WAF / CC 防护 / 信任名单 / IP 访问控制整族对该规则
// 静默失效，原实现零提示。判据抽成 utils 纯函数直测行为（三形状：原有绑定且清空
// → 需要确认；原有绑定且仍有选择 → 不需要；原本无绑定 → 零到零不是变更）。
// 接线（submit 规则模式分支先确认、取消即不提交）与披露形态（§20 后果清单）按
// 源码钉：.vue 无法在 node --test 里装载，模板/接线行为由静态钉覆盖。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { needsUnbindAllConfirm } from '../src/utils/securityStages.ts'
import { code, codeSection, section } from './_helpers.ts'

const bound = (policyId: number) => ({ policy_id: policyId, name: `policy-${policyId}`, mode: 'block', enabled: true })

test('原有绑定且清空全部选择 → 需要确认', () => {
  assert.equal(needsUnbindAllConfirm([bound(1)], 0), true)
  assert.equal(needsUnbindAllConfirm([bound(1), bound(2), bound(3)], 0), true, '多条原有绑定同样披露')
})

test('原有绑定但仍有选择 → 不是清空，不确认', () => {
  assert.equal(needsUnbindAllConfirm([bound(1)], 1), false, '部分保留不是全解绑')
  assert.equal(needsUnbindAllConfirm([bound(1), bound(2)], 2), false)
})

test('原本无绑定 → 零到零不是变更，不确认', () => {
  assert.equal(needsUnbindAllConfirm([], 0), false)
  assert.equal(needsUnbindAllConfirm(undefined, 0), false, '缺省绑定（GET 未返回该规则）按无绑定处理')
  assert.equal(needsUnbindAllConfirm(null, 0), false)
  assert.equal(needsUnbindAllConfirm(undefined, 2), false, '纯新增不触发清空披露')
})

test('submit 规则分支接线：清空判定先于保存请求，取消即不提交', () => {
  const submit = codeSection('src/components/SecurityBindingEditor.vue', 'const submit = async', '// 策略模式：全量重置该策略的绑定集')
  // 判定入参 = 该规则原有绑定 + 本次选择合计（不要另算一份计数）
  assert.match(
    submit,
    /needsUnbindAllConfirm\(props\.bindings\[rule\.caddy_id\], ruleModeTotal\.value\)/,
    '清空判定必须消费该规则原有绑定与 ruleModeTotal',
  )
  assert.match(submit, /await confirmUnbindAll\(rule\)/, '判定为真必须走确认弹框')
  const gate = submit.indexOf('needsUnbindAllConfirm(')
  const put = submit.indexOf('request.put<APIResponse>(`/security/rules/')
  const saving = submit.indexOf('saving.value = true')
  assert.ok(gate >= 0, 'submit 规则分支必须接线清空判定')
  assert.ok(put > gate, '确认必须先于保存请求（取消后不得发出 PUT）')
  assert.ok(saving > gate, '确认必须先于保存中冻结/提交')
  // 取消路径：确认返回 false 直接 return（不提交、弹框保持由 ElMessageBox 自身负责）
  assert.match(submit, /&& !\(await confirmUnbindAll\(rule\)\)\) return/)
})

test('确认弹框形态：§20 后果清单逐条成行，标题/按钮走词条', () => {
  const editor = code('src/components/SecurityBindingEditor.vue')
  const confirmFn = section(editor, 'const confirmUnbindAll = async', 'const submit = async')
  assert.match(confirmFn, /ElMessageBox\.confirm\(/, '复用 ElMessageBox.confirm')
  assert.match(confirmFn, /class: 'confirm-scope-lead'/, '披露引导行走全局单源类')
  assert.match(confirmFn, /class: 'confirm-scope-list'/, '后果清单走全局单源类')
  for (const key of ['unbindAllLossWaf', 'unbindAllLossCc', 'unbindAllLossTrust']) {
    assert.match(confirmFn, new RegExp(`secBinding\\.${key}`), `后果条目 ${key} 必须在清单里`)
  }
  assert.match(confirmFn, /secBinding\.unbindAllLead', \{ rule: rule\.name \}/, '引导行必须点名该规则')
  assert.match(confirmFn, /confirmButtonText: t\('common\.app\.views\.secBinding\.unbindAllOk'\)/, '确认按钮=仍然保存')
  assert.match(confirmFn, /cancelButtonText: t\('common\.app\.views\.secBinding\.cancel'\)/, '取消按钮复用既有词条')
  // 判定单源：组件不得再写一份内联判据
  assert.match(editor, /\bneedsUnbindAllConfirm,?/, '必须从 utils 导入单源判据')
})

test('新增词条 zh/en 成对且引导行带规则名占位', () => {
  const zh = code('src/locales/zh/views.ts')
  const en = code('src/locales/en/views.ts')
  for (const key of ['unbindAllTitle', 'unbindAllLead', 'unbindAllLossWaf', 'unbindAllLossCc', 'unbindAllLossTrust', 'unbindAllOk']) {
    assert.match(zh, new RegExp(`'${key}': '`), `zh 缺词条 ${key}`)
    assert.match(en, new RegExp(`'${key}': '`), `en 缺词条 ${key}`)
  }
  assert.match(zh, /'unbindAllLead': '[^']*\{rule\}[^']*'/, 'zh 引导行必须点名规则')
  assert.match(en, /'unbindAllLead': '[^']*\{rule\}[^']*'/, 'en 引导行必须点名规则')
})
