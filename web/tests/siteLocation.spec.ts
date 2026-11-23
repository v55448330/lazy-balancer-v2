import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  CHINA_SITE_CHOICES,
  COUNTRY_SITE_CHOICES,
  coordsForSiteLocation,
  isSiteConfigured,
  nearestSiteLocation,
} from '../src/utils/siteLocation.ts'

test('中国省份选择覆盖 34 个省级条目且坐标顺序为 [lon,lat]→lat/lon', () => {
  assert.equal(CHINA_SITE_CHOICES.length, 34)
  const gd = coordsForSiteLocation('cn:广东')
  assert.ok(gd)
  assert.ok(Math.abs(gd!.lat - 23.31) < 0.5)
  assert.ok(Math.abs(gd!.lon - 113.42) < 0.5)
})

test('海外国家选择回退到国家质心，且不重复出现中国', () => {
  const us = coordsForSiteLocation('country:美国')
  assert.ok(us)
  assert.ok(us!.lat > 20 && us!.lat < 50)
  assert.ok(us!.lon > -130 && us!.lon < -60)
  assert.ok(!COUNTRY_SITE_CHOICES.some((x) => x.label === '中国'))
  assert.equal(coordsForSiteLocation('country:中国'), null)
})

test('未知 key 返回 null，保存侧可显式拒绝', () => {
  assert.equal(coordsForSiteLocation('cn:不存在省'), null)
  assert.equal(coordsForSiteLocation(''), null)
})

test('已有坐标回显最近省份，零坐标回显未设置', () => {
  assert.equal(nearestSiteLocation(0, 0), '')
  assert.equal(nearestSiteLocation(23.13, 113.27), 'cn:广东')
  assert.equal(nearestSiteLocation(31.23, 121.47), 'cn:上海')
  // 质心坐标原样回显到同一选项（最近距离≈0 的可观测形态；距离函数是模块内部实现）
  const jp = coordsForSiteLocation('country:日本')
  assert.ok(jp)
  assert.equal(nearestSiteLocation(jp!.lat, jp!.lon), 'country:日本')
})

test('本站坐标配置判据：0,0=未设置（后端字段恒 float64，只看 typeof number 恒真）', () => {
  // 后端 models.ServerMapLat/Lon 注释与 stored 语义：0,0=未设置。
  assert.equal(isSiteConfigured(0, 0), false, '0,0 是未设置哨兵，不得当作已配置')
  assert.equal(isSiteConfigured(0, 0.5), true, '赤道点（lat=0）本身是合法坐标')
  assert.equal(isSiteConfigured(0.5, 0), true, '本初子午线点（lon=0）本身是合法坐标')
  assert.equal(isSiteConfigured(23.13, 113.27), true)
  assert.equal(isSiteConfigured(Number.NaN, 113.27), false, '非有限值不得当作已配置')
  assert.equal(isSiteConfigured(undefined, undefined), false)
})
