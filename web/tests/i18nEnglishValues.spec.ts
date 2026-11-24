// 英文词条不得残留汉字。
//
// 现有 i18nFullParity 只钉「键集一致」——en 侧某条译文若被直接填成中文（或留着
// 未译的汉字），键集仍然对等，英文界面上就是一句中文。2026-11-25 用户裁定：
// 全系统支持多语言，英文界面不得出现中文。本守卫遍历运行期实际挂载的 en 词条树
// （i18n/index.ts 深合并后的树，不在测试里复刻合并实现），任何字符串值含汉字
// 即红；确属例外的路径逐条登记在 HAN_ALLOWLIST 并写明理由。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { i18n } from '../src/i18n/index.ts'

type LocaleTree = { [key: string]: unknown }

// 有意保留汉字的英文词条：键路径 → 理由。
// 机器人绑定口令是固定的中文「绑定测试」（机器人只识别这一口令）；这几句英文
// 以引号原样引用口令并附英文解释，引用的是口令本身，不是未译文案。
const BIND_COMMAND = '机器人绑定口令「绑定测试」是固定中文口令，英文句子原样引用并附英文解释'
const HAN_ALLOWLIST: Readonly<Record<string, string>> = {
  'notification.channels.bindAwaitMsg': BIND_COMMAND,
  'notification.channels.rebindAwaitMsg': BIND_COMMAND,
  'notification.channels.wxSendMsgHint': BIND_COMMAND,
  'notification.channels.qqBindHint': BIND_COMMAND,
  'notification.channels.wxAlreadyLoggedInHint': BIND_COMMAND,
}

test('英文词条不得残留汉字', () => {
  const messages = i18n.global.messages.value as Record<string, LocaleTree>
  const en = messages.en?.app
  assert.ok(en, 'i18n 实例必须挂载 en 的 app 词条树')

  const offenders: string[] = []
  let leaves = 0
  const walk = (node: unknown, prefix: string): void => {
    for (const [key, value] of Object.entries(node as LocaleTree)) {
      const path = prefix ? `${prefix}.${key}` : key
      if (value !== null && typeof value === 'object') {
        walk(value, path)
        continue
      }
      leaves++
      if (typeof value !== 'string' || !/\p{Script=Han}/u.test(value)) continue
      if (HAN_ALLOWLIST[path]) continue
      offenders.push(`${path} = ${value}`)
    }
  }
  walk(en, '')
  // 例外表里的路径必须真实存在：键改名后登记项会静默失效，届时要么删登记、要么补登记。
  for (const path of Object.keys(HAN_ALLOWLIST)) {
    assert.ok(path.split('.').reduce<unknown>((node, key) => (node as LocaleTree | undefined)?.[key], en) !== undefined, `HAN_ALLOWLIST 登记了不存在的词条路径：${path}`)
  }
  assert.ok(leaves > 1000, `扫描面异常：en 词条树只有 ${leaves} 个叶子，守卫会假绿`)
  assert.deepEqual(offenders, [], `英文词条有 ${offenders.length} 条残留汉字——译文未完成；确属例外请在 HAN_ALLOWLIST 登记路径与理由`)
})
