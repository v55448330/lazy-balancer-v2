// 日报预览样例值（daily 模式预览用）：键集=后端 DailyItemIDs 全集 + date。
// 单源导出供跨栈对表测试消费（web/tests/dailySamplesCrossStack.spec.ts 逐键
// 对表 internal/notify/daily_report.go）——后端新增日报项目而样例缺键时，
// 预览会残留 {{key}} 占位符，测试必须红。
// top_ips/top_paths/cert_expiring/nodes_summary 为多行文本列表样例（预览侧
// 展开为语义表格，投递侧同口径）。
//
// 形态=有序键值对（非 Record 词表）：消费面只做整表遍历，没有按任意键下标的
// 展示查表——成对数组不落入「词表读取必须过 hasOwn」的守卫面（跨栈测试用
// Object.fromEntries 回查）。
export const dailySampleValues: ReadonlyArray<readonly [string, string]> = [
  ['date', '2026-11-18'],
  ['requests', '128340'],
  ['allowed', '120111'],
  ['logged', '7026'],
  ['distinct_ips', '3204'],
  ['bandwidth', '1.2 GB'],
  ['peak_qps', '340'],
  ['blocked', '1203'],
  ['attack_top', 'SQLi × 321'],
  ['top_ips', '45.33.32.9 × 321\n1.2.3.4 × 120'],
  ['top_paths', '/login × 200\n/api × 150'],
  ['cc_triggered', '3'],
  ['autoban', '17'],
  ['cert_status', 'OK'],
  ['cert_expiring', 'a.com · 2026-11-25\nb.com · 2026-11-28'],
  ['cluster_status', '3/3'],
  ['nodes_summary', 'slave-a：请求 22014 · 拦截 156 · 独立IP 402\nslave-b：请求 9821 · 拦截 12 · 独立IP 210'],
  ['uptime', '32 天'],
  ['threat_db', 'CRS 4.0 · IP库 2026-11'],
  ['app_version', 'v2.4.4'],
  ['api_calls', '1200'],
  ['mcp_calls', '300'],
  ['task_status', '成功 12 / 失败 1'],
  ['backup_status', '成功 7 / 失败 0'],
  ['login_status', '成功 40 / 失败 3 / MFA失败 1'],
]
