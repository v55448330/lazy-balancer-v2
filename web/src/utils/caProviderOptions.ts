// 引用型下拉选项口径单源（规则向导 TLS 步的「CA 提供商」与「DNS 配置」两个
// 下拉 + 免费证书全局默认 CA）。
//
// 原各下拉各自 `filter(x => x.enabled)`：存量配置指向已禁用项时，选中值不在
// 选项集内——el-select 显示裸数字 id（像「未设置」），保存又原样保留旧引用。
// 口径：启用项 ∪ 当前值对应项（已禁用项仅供回显，视图为该 option 置
// :disabled 不允许新选）。后端写侧仍以 enabled=1 为准（rule_features.go
// validateRuleACMEReferences），回显的禁用项保存会被 400 明确拒绝——比下拉
// 里查无此项、到保存才拿到泛化错误更可诊断。
import { tSafe as t } from '../i18n/tSafe.ts'

interface ReferencedOptionSource {
  readonly id: number
  readonly enabled: boolean
}

/** 选择器可见集：全部启用项 + 当前选中值对应项（无论其是否禁用）。 */
export const selectableReferencedOptions = <T extends ReferencedOptionSource>(
  options: readonly T[],
  currentId: number,
): T[] => options.filter((o) => o.enabled || o.id === currentId)

/** 选项展示名：已禁用的回显项标注「（已禁用）」，避免被读成可用项。 */
export const referencedOptionLabel = (o: ReferencedOptionSource & { readonly name: string }): string =>
  o.enabled ? o.name : t('common.app.views.misc.disabledOptionSuffix', { name: o.name })
