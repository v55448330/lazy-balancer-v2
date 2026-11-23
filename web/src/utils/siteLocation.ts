// 威胁大屏本站坐标：地点选择（中国省份 / 海外国家）→ 经纬度单源。
// 原自动检测依赖公网 IP 归属地，精度不可控；改为显式选择（城市列表过密，
// 按用户要求收敛到省级），坐标只在选择时写入，避免再次引入“猜位置”。
import { CHINA_PROVINCES } from './chinaProvinces.ts'
import { COUNTRY_CENTROIDS } from './countryCentroids.ts'

const CHINA_SITE_PREFIX = 'cn:'
const COUNTRY_SITE_PREFIX = 'country:'

interface SiteLocationChoice {
  key: string
  label: string
  lat: number
  lon: number
}

export const CHINA_SITE_CHOICES: SiteLocationChoice[] = CHINA_PROVINCES
  .slice()
  .sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'))
  .map((province) => ({
    key: CHINA_SITE_PREFIX + province.short,
    label: province.name,
    lat: province.centroid[1],
    lon: province.centroid[0],
  }))

// 中国已由省份分组覆盖，海外国家列表必须排除「中国」——否则下拉出现两个中国。
export const COUNTRY_SITE_CHOICES: SiteLocationChoice[] = Object.keys(COUNTRY_CENTROIDS)
  .filter((name) => name !== '中国')
  .sort((a, b) => a.localeCompare(b, 'zh-CN'))
  .map((name) => {
    const [lon, lat] = COUNTRY_CENTROIDS[name]
    return { key: COUNTRY_SITE_PREFIX + name, label: name, lat, lon }
  })

const ALL_CHOICES = [...CHINA_SITE_CHOICES, ...COUNTRY_SITE_CHOICES]

/** 选择 key → 坐标；未知 key 返回 null（保存前走显式校验）。 */
export function coordsForSiteLocation(key: string): { lat: number; lon: number } | null {
  const choice = ALL_CHOICES.find((item) => item.key === key)
  if (!choice) return null
  return { lat: Number(choice.lat.toFixed(4)), lon: Number(choice.lon.toFixed(4)) }
}

/**
 * 本站坐标是否已配置。后端 models.ServerMapLat/Lon 为 float64 且 0,0=未设置
 * （未配置时字段仍是 0 值，JSON 里恒为 number）——只判 typeof number 恒真，
 * 会把未配置站点当已配置，信标落在几内亚湾 (0,0)。赤道/本初子午线单点坐标
 * （lat=0 或 lon=0 但不同时为 0）仍是合法配置。
 */
export function isSiteConfigured(lat: unknown, lon: unknown): boolean {
  if (typeof lat !== 'number' || typeof lon !== 'number') return false
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false
  return !(lat === 0 && lon === 0)
}

/** 近似球面距离（km）；仅用于回显最近地点，不参与业务判定。 */
function siteDistanceKm(aLat: number, aLon: number, bLat: number, bLon: number): number {
  const rad = Math.PI / 180
  const dLat = (bLat - aLat) * rad
  const dLon = (bLon - aLon) * rad
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(aLat * rad) * Math.cos(bLat * rad) * Math.sin(dLon / 2) ** 2
  return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(h)))
}

/**
 * 已有坐标 → 最近地点 key（用于编辑现有配置时回显）。
 * 零坐标（未设置）返回空串；其余取全表最近项——表粒度为中国省级质心 +
 * 海外国家质心（无城市粒度），故回显精度只到省/国家。
 */
export function nearestSiteLocation(lat: number, lon: number): string {
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || (lat === 0 && lon === 0)) return ''
  let best = ''
  let bestDistance = Number.POSITIVE_INFINITY
  for (const choice of ALL_CHOICES) {
    const distance = siteDistanceKm(lat, lon, choice.lat, choice.lon)
    if (distance < bestDistance) {
      bestDistance = distance
      best = choice.key
    }
  }
  return best
}

interface NodeSiteFormValue {
  siteLocationKey: string
  lat: number
  lon: number
}

/**
 * 问题：节点站点弹框的表单初值单源。site_inherited 节点的
 * server_map_lat/lon 是服务端替换后的主节点坐标副本，必须还原为
 * 0,0 + 空选择（继承语义），不得把继承值预填为可保存值——否则
 * 「打开即保存」会把继承静默固化为显式坐标，此后主节点坐标变更不再传播。
 */
export function initialNodeSiteForm(node: {
  readonly server_map_lat?: number
  readonly server_map_lon?: number
  readonly site_inherited?: boolean
}): NodeSiteFormValue {
  if (node.site_inherited) {
    return { siteLocationKey: '', lat: 0, lon: 0 }
  }
  const lat = node.server_map_lat ?? 0
  const lon = node.server_map_lon ?? 0
  return { siteLocationKey: nearestSiteLocation(lat, lon), lat, lon }
}

/**
 * 问题：表单坐标相对打开时初值是否有变化。无变化保存=no-op——
 * 弹框直接关闭，不发 PUT、不触发集群版本 bump 与全集群同步。
 */
export function nodeSiteCoordsChanged(
  initial: { readonly lat: number; readonly lon: number },
  form: { readonly lat: number; readonly lon: number },
): boolean {
  return initial.lat !== form.lat || initial.lon !== form.lon
}
