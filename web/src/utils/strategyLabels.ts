// 负载策略→文案映射（Rules/Dashboard 共用）。
// 键集与后端 httpStrategies 全集对齐（weighted_round_robin/least_conn/
// ip_hash/random/first/cookie）；Dashboard 原死键 round_robin 与 Rules 原
// 死键 header 已删除（后端不接受该两形态）。
// 映射对象收窄为模块内私有（外泄面只剩 getStrategyLabel 一个函数，
// 消费方禁止绕过函数直读映射，防第二份映射/直改键值）
import { hasOwn } from './hasOwn.ts'
import { tSafe as t } from '../i18n/tSafe.ts'


// 词条文案模块首帧快照：键集为封闭枚举（与后端 httpStrategies/tcpStrategies
// 对表，strategyLabels.spec 钉死），运行期 locale 切换走整页重载，无跨帧漂移。
const strategyLabels: Record<string, string> = {
  weighted_round_robin: t('common.app.views.strategy.weightedRoundRobin'),
  least_conn: t('common.app.views.strategy.leastConn'),
  ip_hash: t('common.app.views.strategy.ipHash'),
  cookie: t('common.app.views.strategy.cookieSticky'),
  first: t('common.app.views.strategy.firstAvailable'),
  random: t('common.app.views.strategy.randomLabel'),
}

// 映射是普通对象且 strategy 可能来自导入/API（非向导白名单路径）：原型键直接
// 下标会返回函数并绕过原词回退，规则列表/仪表盘会把函数源码当策略列渲染。
export const getStrategyLabel = (strategy: string): string => {
  const label = hasOwn(strategyLabels, strategy) ? strategyLabels[strategy] : undefined
  return label || strategy
}

// ── 向导策略卡片与提交白名单单源 ──
// 卡片可见集与 submitWizard 的 allowedStrategies 原各自维护：白名单放行了
// random/first（后端 httpStrategies/tcpStrategies 同放行），卡片却没有这两张
// ——API/MCP/导入产生的 random/first 规则在向导内无高亮、点任意卡片即静默改写。
// 键集与后端 validateStrategyForProtocol（rule_features.go）逐协议对齐。
interface StrategyCardOption {
  readonly value: string
  readonly title: string
  readonly desc: string
  /** cookie 粘滞仅 HTTP 可用（后端 TCP 白名单不含 cookie）。 */
  readonly httpOnly?: boolean
}

export const STRATEGY_CARD_OPTIONS: readonly StrategyCardOption[] = [
  { value: 'weighted_round_robin', title: t('common.app.views.strategy.card.weightedRoundRobin.title'), desc: t('common.app.views.strategy.card.weightedRoundRobin.desc') },
  { value: 'least_conn', title: t('common.app.views.strategy.card.leastConn.title'), desc: t('common.app.views.strategy.card.leastConn.desc') },
  { value: 'ip_hash', title: t('common.app.views.strategy.card.ipHash.title'), desc: t('common.app.views.strategy.card.ipHash.desc') },
  { value: 'random', title: t('common.app.views.strategy.card.random.title'), desc: t('common.app.views.strategy.card.random.desc') },
  { value: 'first', title: t('common.app.views.strategy.card.first.title'), desc: t('common.app.views.strategy.card.first.desc') },
  { value: 'cookie', title: t('common.app.views.strategy.card.cookie.title'), desc: t('common.app.views.strategy.card.cookie.desc'), httpOnly: true },
]

/** 该协议可选的策略卡片（TCP 剔除 cookie）。 */
export const strategyCardsForProtocol = (protocol: 'http' | 'tcp'): readonly StrategyCardOption[] =>
  STRATEGY_CARD_OPTIONS.filter((card) => !(card.httpOnly && protocol === 'tcp'))

/** 该协议的合法策略值集——提交白名单与卡片集同源派生。 */
export const strategyValuesForProtocol = (protocol: 'http' | 'tcp'): readonly string[] =>
  strategyCardsForProtocol(protocol).map((card) => card.value)
