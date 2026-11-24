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

// 与后端 validateChannelStyle 的 len(s) 同口径：模板长度按 UTF8 字节，
// 不按 JS 字符数（中文 1 字符约 3 字节）。
export const utf8ByteLength = (value: string): number => new TextEncoder().encode(value).length

interface ChannelTemplateDraft {
  channelId: string
  text: string
  defaultZh: string
  defaultEn: string
  bodyTemplate: string
  /** 该通道的中文预置是否与后端默认链逐字等价（仅 QQ/微信成立，跨栈夹具
   * 钉住）。等价时「等于预置」才删键；webhook/邮件无后端默认模板、英文预置
   * 无后端英文缺省——保存后必须落库，否则实际投递与编辑器预览不一致。 */
  presetIsDefaultChain?: boolean
}

// 事件模板保存：保留未展示通道（如停用通道）的既有 per-channel 模板；
// 仅对本次展示的通道重建键。空草稿、等于事件级 body（事件级模板继续生效，
// 不钉 per-channel 副本）、等于**与默认链等价的**中文预置时删除该键；
// 其余（自定义、webhook/邮件预置、英文预置）原样落库。
export const mergeChannelTemplateDrafts = (
  existing: Record<string, string> | undefined,
  drafts: readonly ChannelTemplateDraft[],
): Record<string, string> => {
  const out: Record<string, string> = { ...(existing ?? {}) }
  for (const d of drafts) {
    const id = String(d.channelId)
    const text = d.text
    const isDefaultChainPreset = d.presetIsDefaultChain === true && text === d.defaultZh
    if (!text || isDefaultChainPreset || (d.bodyTemplate !== '' && text === d.bodyTemplate)) {
      delete out[id]
    } else {
      out[id] = text
    }
  }
  return out
}

// 规则级邮件模板的发送格式由内容决定（与后端派发同判据）：含 HTML 标签按
// text/html 发送（占位符值转义），否则按纯文本原文发送。后端没有规则级格式
// 字段，两侧判据一致预览才是实发形态。标签名须紧跟 "<"——比较运算里的
// "a < b" 不算标签。
const HTML_TAG = /<\/?[a-zA-Z!][^<>]*>/
export const ruleTemplateIsHtml = (tpl: string): boolean => HTML_TAG.test(tpl)

// 通道模板字节上限（与后端保存门同口径）：机器人 ≤2000、邮件 ≤4000、webhook
// 不限（保存时校验占位符替换后可解析）。日报卡与规则弹框共用。
export const channelTemplateByteLimit = (type: string): number =>
  type === 'qq' || type === 'wx_clawbot' ? 2000 : type === 'email' ? 4000 : 0
