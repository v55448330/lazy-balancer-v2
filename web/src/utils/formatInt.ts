// 站内整数千分位单源（手工分组、',' 分隔、locale 无关）。
//
// 面板统计数字此前分散裸调 toLocaleString()：默认 locale 随宿主
// LC_ALL/LANG 变（de → `1.234`，fr → `1 234`），同一份代码在不同开发机/CI 上
// 给出不同文案（守卫假红），de/fr 用户还会把千分位读成小数点。收敛为本模块
// 的手工分组（crsRuleCountLabel 原内核），所有统计数字展示一律经此函数：
//   - tests/formatInt.spec.ts 守卫裸 `.toLocaleString(` 清零
//     （白名单：SecurityOverview 的 fmtStatNum 显式 'en-US' 调用）；
//   - 兜底语义（undefined → '—'/'-'）由调用方保留，本函数只管数字形态。
export function formatInt(n: number): string {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}
