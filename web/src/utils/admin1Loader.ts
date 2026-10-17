// 省界数据按需加载单源（第 78 轮 U15-F06）：admin1Provinces 为 ~1.9MB 静态表，
// 顶栏总览不需要它——两个威胁大屏引擎经此动态 import（Vite 切独立 chunk），
// 首屏零下载，首次下钻才拉取。加载失败返回 null（调用方按「无省层」降级，
// 不白屏），并允许下一次下钻重试。
//
// 注意：本模块只做「首次请求缓存 + 失败可重试」，不缓存失败态；消费方不得
// 静态 import ADMIN1_PROVINCES（否则数据回到主 chunk，本模块失去意义）。
import type { Admin1Province } from '@/utils/admin1Provinces'

type Admin1Tables = Record<string, Admin1Province[]>

let pending: Promise<Admin1Tables | null> | null = null
let tables: Admin1Tables | null = null

export function loadAdmin1Tables(): Promise<Admin1Tables | null> {
  if (tables) return Promise.resolve(tables)
  if (pending) return pending
  pending = import('@/utils/admin1Provinces')
    .then((mod) => {
      tables = mod.ADMIN1_PROVINCES
      return tables
    })
    .catch((error: unknown) => {
      console.warn('load admin1 provinces failed', error)
      pending = null // 允许下次下钻重试
      return null
    })
  return pending
}

/** 已加载的表（同步读取；未加载时 null——下钻前的 hover/合成路径使用）。 */
export function loadedAdmin1Tables(): Admin1Tables | null {
  return tables
}
