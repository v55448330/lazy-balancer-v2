// 通知中心草稿合并纯函数：组件只负责取数/持久化，合并规则在此单源并可单测。

interface DailyModuleDef {
  id: string
  items: readonly string[]
}

// 大模块勾选：只切换本次发生变化的模块；部分选中的模块在未被操作时
// 必须保留原项目（历史配置是项目粒度，模块勾选只是整组快捷方式）。
export const toggleDailyModules = (
  items: readonly string[],
  modules: readonly DailyModuleDef[],
  checked: readonly string[],
): string[] => {
  const next = new Set(items)
  const on = new Set(checked)
  for (const mod of modules) {
    const wasFullyOn = mod.items.every(it => next.has(it))
    const isOn = on.has(mod.id)
    if (isOn === wasFullyOn) continue
    for (const it of mod.items) {
      if (isOn) next.add(it)
      else next.delete(it)
    }
  }
  return [...next]
}

// 与后端 validateChannelStyle 的 len(s) 同口径：模板长度按 UTF-8 字节，
// 不按 JS UTF-16 字符（中文 1 字符约 3 字节）。
export const utf8ByteLength = (value: string): number => new TextEncoder().encode(value).length

interface ChannelTemplateDraft {
  channelId: string
  text: string
  defaultZh: string
  defaultEn: string
  bodyTemplate: string
}

// 事件模板保存：保留未展示通道（如停用通道）的既有 per-channel 模板；
// 仅对本次展示的通道重建键。草稿等于默认或事件级 body 时删除该键，
// 让默认链/事件级模板继续生效，而不是把 body 钉成 per-channel 副本。
export const mergeChannelTemplateDrafts = (
  existing: Record<string, string> | undefined,
  drafts: readonly ChannelTemplateDraft[],
): Record<string, string> => {
  const out: Record<string, string> = { ...(existing ?? {}) }
  for (const d of drafts) {
    const id = String(d.channelId)
    const text = d.text
    if (!text || text === d.defaultZh || text === d.defaultEn || (d.bodyTemplate !== '' && text === d.bodyTemplate)) {
      delete out[id]
    } else {
      out[id] = text
    }
  }
  return out
}
