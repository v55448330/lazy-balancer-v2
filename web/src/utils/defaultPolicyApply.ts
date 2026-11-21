// 默认策略弹框的纯状态逻辑（audit153 FE153-04 自 SecurityPolicies.vue 抽出）：
// 失败项差集与重试状态流转是纯函数，组件只负责赋值与请求——行为测试可直接
// 覆盖，不必从 SFC 源码切片里拼断言。

interface DefaultApplyItemLike {
  kind: string
  name: string
  status: string
}

interface DefaultCatalogNameLike {
  lists: ReadonlyArray<{ name: string }>
  policies: ReadonlyArray<{ name: string }>
}

type DefaultsPhase = 'preview' | 'running' | 'done'

interface DefaultsFlowState {
  phase: DefaultsPhase
  failed: boolean
}

/**
 * 失败项差集：目录里有、结果集里没有的条目（kind+name 复合键——地址列表与
 * 策略可能同名）。**仅当有结果集时才成立**：apply 是单事务，失败整体回滚且
 * 失败信封不带已建项（后端 Data 恒空），此时「全目录差集」会把「一项都没建」
 * 误报成「全部失败/全部未创建」。无结果集返回空，由调用方呈现「状态未知」。
 */
export const failedDefaultNames = (
  catalog: DefaultCatalogNameLike | null,
  items: ReadonlyArray<DefaultApplyItemLike>,
): string[] => {
  if (!catalog || items.length === 0) return []
  const applied = new Set(items.map((it) => it.kind + it.name))
  const names: string[] = []
  for (const l of catalog.lists) if (!applied.has('list' + l.name)) names.push(l.name)
  for (const p of catalog.policies) if (!applied.has('policy' + p.name)) names.push(p.name)
  return names
}

/** 打开弹框：回到预览态并清空上一次的失败印记（目录状态可能已变）。 */
export const defaultsFlowOpening = (): DefaultsFlowState => ({ phase: 'preview', failed: false })

/** 开始执行（含失败后重试）：进入 running，先清失败印记（重试不得继承上次失败态）。 */
export const defaultsFlowStarting = (): DefaultsFlowState => ({ phase: 'running', failed: false })

/** 请求落定：成功/失败都停在完成态（可关框），失败留印记以区分「全部成功」。 */
export const defaultsFlowSettled = (ok: boolean): DefaultsFlowState => ({ phase: 'done', failed: !ok })
