// hash 查询串单源解析/剥离（App 首屏预处理消费 login_ticket / OIDC 回跳片段、
// auth store 深链取页面键共用）。必须无 Vue 依赖——stores/auth.ts 在模块初始化期调用。

interface HashQuery {
  /** hash 内路径段（形如「#/path?query」时为 "/path"；纯查询形态为空串） */
  path: string
  /** 路径段后的查询串参数；无路径形态时为整个 hash 体 */
  params: URLSearchParams
}

/**
 * 解析 location.hash。形态二种:「#login_ticket=x」（无路径）与
 * 「#/oidc/callback?token=x」（带路径）——先剥路径段再解析查询串，
 * 否则 key 会变成 "/oidc/callback?token"。路径段整段参与匹配（精确比对），
 * 调用方不得再对完整 hash 做子串探测（普通深链 `#/x/oidc/callback?…`
 * 或 `#/login?next=/oidc/callback` 都不是回调入口）。
 */
export function readHashQuery(hash: string = window.location.hash): HashQuery {
  const body = hash.startsWith('#') ? hash.slice(1) : ''
  if (body.startsWith('/')) {
    const qIdx = body.indexOf('?')
    return {
      path: qIdx >= 0 ? body.slice(0, qIdx) : body,
      params: new URLSearchParams(qIdx >= 0 ? body.slice(qIdx + 1) : ''),
    }
  }
  return { path: '', params: new URLSearchParams(body) }
}

/**
 * 从当前地址的 hash 查询串剥离指定键并 replaceState 回写；剩余为空串时不拼
 * 「?」、hash 整段消失，避免 URL 残留「#?」。无任一键命中时不产生历史扰动。
 */
export function stripHashParams(keys: readonly string[]): void {
  const { params } = readHashQuery()
  if (!keys.some((key) => params.has(key))) return
  for (const key of keys) params.delete(key)
  const rest = params.toString()
  window.history.replaceState({}, '', `${window.location.pathname}${window.location.search}${rest ? `#${rest}` : ''}`)
}
