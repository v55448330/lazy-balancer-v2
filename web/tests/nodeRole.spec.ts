// 节点角色三态派生的行为验收（穷举 master / slave / null / undefined）。
//
// 判据此前写在 Dashboard.vue 的 computed 里，用例只能钉「=== 'master' 与
// === 'slave' 出现过」——两支互换、标签互换、tag 色互换都仍然全绿：
// 存在性断言没有方向。抽成 resolveNodeRole 后按四态逐项钉住输出。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'
import { tSafe } from '../src/i18n/tSafe.ts'
import { existsSync } from 'node:fs'

import { resolveNodeRole } from '../src/utils/nodeRole.ts'

// 批次 D(cluster 域)i18n 相位兜底:接线前 tSafe 未挂 views 子树,解析值=键名
// (行为钉退化为「label 恒等于该键解析值」,仍拦硬编码/换键漂移);integrator
// 落库 zh/en views.ts + tSafe 挂 views 后解析值=zh 原文,自动升级为逐字文案钉。
const view = (key: string, params?: Record<string, unknown>): string =>
  tSafe(`common.app.views.cluster.${key}`, params)

test('主节点：success 色 + 主节点文案', () => {
  assert.deepEqual(resolveNodeRole('master'), { role: 'master', label: view('master'), tagType: 'success' })
})

test('从节点：warning 色 + 从节点文案（不得与主节点同形）', () => {
  assert.deepEqual(resolveNodeRole('slave'), { role: 'slave', label: view('slave'), tagType: 'warning' })
})

test('null（/config 首拉失败或重试期）与 undefined（未取到）都归 unknown，且 fail-closed 用 info', () => {
  for (const mode of [null, undefined]) {
    assert.deepEqual(
      resolveNodeRole(mode),
      { role: 'unknown', label: view('roleUnknown'), tagType: 'info' },
      `${String(mode)} 必须归 unknown`,
    )
  }
})

test('未知态不得被误判为主/从节点（反向覆盖：标签与 tag 色逐一不同）', () => {
  const master = resolveNodeRole('master')
  const slave = resolveNodeRole('slave')
  const unknown = resolveNodeRole('unknown')
  for (const [name, view_] of [['主节点', master], ['从节点', slave]] as const) {
    assert.notEqual(unknown.label, view_.label, `未知态标签不得与${name}相同`)
    assert.notEqual(unknown.tagType, view_.tagType, `未知态 tag 不得与${name}同色`)
  }
  assert.notEqual(master.tagType, slave.tagType, '主/从 tag 色必须可区分')
})

// ── 批次 D 双钉:调用点钉键 + zh 母本钉原文(任一漂移必红) ──

test('label 文案走 i18n 单键:三态各自一个 cluster.* 键,不得回流字面量', () => {
  const util = code('src/utils/nodeRole.ts')
  for (const key of ['master', 'slave', 'roleUnknown']) {
    assert.match(util, new RegExp(`t\\('common\\.app\\.views\\.cluster\\.${key}'\\)`), `label 必须走 cluster.${key} 词条键`)
  }
  assert.doesNotMatch(util, /label: '[^']*节点[^']*'/, 'label 不得再写中文文案字面量(词条外第二份)')
})

test('cluster 词条 zh 母本钉(integrator 落库后逐字)', () => {
  assert.ok(existsSync(new URL('../src/locales/zh/views.ts', import.meta.url)), '词条母本 src/locales/zh/views.ts 未落库(integrator 接线);落库后本钉转绿')
  const zhLexicon = code('src/locales/zh/views.ts')
  for (const [key, text] of [['master', '主节点'], ['slave', '从节点'], ['roleUnknown', '节点角色未知']] as const) {
    assert.ok(zhLexicon.includes(text), `cluster.${key} 的 zh 原文「${text}」必须在母本中`)
    assert.equal(view(key), text, `cluster.${key} 必须解析为 zh 原文(接线前=键名自环)`)
  }
})

test('cluster 五面板调用点钉键(批次 D 抽查:每面板代表键,防整卡回退字面量)', () => {
  const pins: Array<[string, string[]]> = [
    ['src/views/settings/cluster/ClusterModeCard.vue', ['modeTitle', 'master"', 'syncIntervalLabel', 'registerDialogTitle']],
    ['src/views/settings/cluster/ClusterMasterPanel.vue', ['syncSettingsMasterTitle', 'nodeList', 'sectionSyncTitle', 'emptyNodes']],
    ['src/views/settings/cluster/ClusterNodeConfigDialog.vue', ['nodeConfigTitle', 'accessUrlLabel', 'siteCoordsLabel']],
    ['src/views/settings/cluster/ClusterStatusCard.vue', ['currentNodeStatus', 'roleLabel', 'clusterStatusLabel', 'plainHttpWarning']],
    ['src/views/settings/cluster/ClusterSlavePanel.vue', ['slaveActionsTitle', 'awaitingApprovalTitle', 'syncNow', 'promoteToMaster']],
  ]
  for (const [file, keys] of pins) {
    const page = code(file)
    for (const key of keys) {
      assert.ok(page.includes(`common.app.views.cluster.${key.replace('"', '')}`), `${file} 调用点必须含 cluster.${key} 词条键`)
    }
  }
})
