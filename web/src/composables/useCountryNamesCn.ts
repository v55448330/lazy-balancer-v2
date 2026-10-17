import { ref } from 'vue'
import { request } from '@/utils/api'
import { createLazyLoader } from '@/utils/lazyOnce'
import type { APIResponse } from '@/types'

// country_names_cn 展示层单源消费（X1，第 74 轮）：海外国家英文名 → 中文简称
// 映射由后端 geoipnames.CountryNamesCN 单源下发（regions API 并行字段，模块级
// 缓存一次拉取）——前端零复制表，展示层翻译（geoip_countries 提交值/匹配键零
// 改动）；未命中（未来新增国名）、旧后端、请求失败一律回退英文原名。
const zhNames = ref<Record<string, string>>({})
// 单飞 + 失败可重试（第 78 轮 U15-F18）：原 `requested=true` 置在请求前，
// 一次失败即整会话闩死为英文标签；现失败不置加载态，下一次调用自然重试。
const namesLoader = createLazyLoader(async () => {
  const res = await request.get<APIResponse<{ country_names_cn?: Record<string, string> }>>('/security/ip2region/regions', { silent: true })
  return res.data?.country_names_cn || {}
})

async function fetchOnce(): Promise<void> {
  await namesLoader.ensure()
  const loaded = namesLoader.get()
  // 失败时保留已有映射（首次失败即空表→英文原名，属既定回退语义）
  if (loaded) zhNames.value = loaded
}

export function useCountryNamesCn() {
  void fetchOnce()
  return zhNames
}

// countryLabel 翻译单个地域条目：国家名命中映射→中文；省份/省市联值/「海外」
// 哨兵/未收录名原样返回（展示层零值改动）。三处消费方（IPLocationAction/
// TriggerDetailDialog/RuleFlowDialog）需锁步同语义回退——单源小函数在此是
// 锁步契约载体，非纯重命名。
export function countryLabel(zh: Record<string, string>, name: string): string {
  return zh[name] || name
}
