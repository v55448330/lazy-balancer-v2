// SecurityStagePolicy 测试夹具单源：securityStagesPure / securityStagesModel
// 两份 spec 的策略工厂近乎同构（字段清单完全一致，仅默认 name/mode/限流值不
// 同）——字段清单在此只维护一份，消费文件各自保留差异 override。
//
// 非 spec 文件（不以 .spec.ts 结尾），node --test 不会把它当用例。

import type { SecurityStagePolicy } from '../../src/utils/securityStages.ts'

export const stagePolicy = (overrides: Partial<SecurityStagePolicy> = {}): SecurityStagePolicy => ({
  id: 1,
  name: '策略',
  mode: 'blocking',
  enabled: true,
  has_ip_control: false,
  has_rate_limit: false,
  has_geoip: false,
  has_custom_rules: false,
  geoip_countries: '[]',
  custom_rules_count: 0,
  ip_acl_mode: 'deny',
  ip_acl_list: '[]',
  ip_whitelist: '[]',
  rate_limit_rps: 100,
  rate_limit_burst: 50,
  ...overrides,
})
