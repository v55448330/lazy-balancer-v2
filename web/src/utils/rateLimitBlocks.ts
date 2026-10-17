// 限流拦截数据归一：后端历史版本在无 429 时返回 hosts:null（Go nil slice
// JSON 编码），直接读 hosts.length 会让整个安全总览渲染崩溃。这里把任何
// 非数组形态收敛为空数组，total 保持数值语义。

export interface RateLimitBlockHost {
  host: string
  count: number
}

export interface RateLimitBlocks {
  total: number
  hosts: RateLimitBlockHost[]
}

export function normalizeRateLimitBlocks(data: unknown): RateLimitBlocks {
  const raw = (data && typeof data === 'object' ? data : {}) as Record<string, unknown>
  const hosts = Array.isArray(raw.hosts)
    ? raw.hosts
        .filter((item): item is Record<string, unknown> => !!item && typeof item === 'object')
        .map((item) => ({
          host: typeof item.host === 'string' ? item.host : '',
          count: Number(item.count) || 0,
        }))
        .filter((item) => item.host !== '')
    : []
  const total = Number(raw.total)
  return {
    total: Number.isFinite(total) ? total : hosts.reduce((sum, item) => sum + item.count, 0),
    hosts,
  }
}
