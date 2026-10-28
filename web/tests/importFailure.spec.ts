// 导入/还原失败响应的 data.warnings 必须到达用户界面：文件面「提交不确定的人工
// 核对指引」与「回退失败可能分裂」结论此前只有审计可见，前端只展示 message
// toast——运维按「已回滚、无需动作」处理，而执行面可能已与库分裂。本 spec 同时
// 钉住纯函数渲染与两处失败路径的接线。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { importFailureLines, importFailureReport } from '../src/utils/importFailure.ts'
import { code, section } from './_helpers.ts'

// 后端失败响应体（models.APIResponse）：真实形态由 config_backup.go 的
// respondAfterWafFailure 产出，挂在 ApiRequestError.data 上。
const backendFailure = (warnings: string[], conflicts: unknown[] = []) => ({
  code: 500,
  message: '配置导入失败: 提交配置：database is locked',
  data: { summary: {}, warnings, disabled_conflicts: conflicts },
})

// ApiRequestError 形态（拦截器把 error.response.data 透传为 data）。
const apiRequestError = (message: string, body: unknown) =>
  Object.assign(new Error(message), { name: 'ApiRequestError', status: 500, data: body })

const indeterminate = '规则库文件已按备份落盘，提交结果不确定：数据库未确认写入，规则库文件保持导入后状态——请核对规则库页版本后重新导入或触发规则库更新收敛'
const rollbackFailed = '规则库文件已按备份落盘，数据库已回滚，但规则库文件回退失败: permission denied——文件与版本记录可能分裂'

test('失败响应的 warnings 全部进入展示行（两种文件面判决形态）', () => {
  const report = importFailureReport(
    apiRequestError('配置导入失败: 提交配置：database is locked', backendFailure([indeterminate, rollbackFailed], [{ name: 'r1' }])),
    '配置导入失败',
  )
  assert.equal(report.message, '配置导入失败: 提交配置：database is locked')
  assert.deepEqual([...report.warnings], [indeterminate, rollbackFailed])
  assert.equal(report.conflictCount, 1)
  const lines = importFailureLines(report)
  assert.equal(lines[0], report.message)
  assert.ok(lines.includes(indeterminate), '提交不确定的人工核对指引不得被丢弃')
  assert.ok(lines.includes(rollbackFailed), '文件面分裂结论不得被丢弃')
  const conflictLine = lines.find((line) => line.includes('冲突规则'))
  assert.ok(conflictLine, '冲突条数必须出现（但只能是预告口径）')
  assert.match(conflictLine, /若导入成功将禁用/, '失败分支的冲突条数是预演清单，不得写成既成事实')
  assert.doesNotMatch(conflictLine, /^冲突置为禁用/, '不得沿用成功路径的既成事实句')
})

test('无响应体（网络失败/旧形态错误）回退兜底文案且不造警告行', () => {
  const report = importFailureReport(new Error('Network Error'), '配置还原失败')
  assert.equal(report.message, 'Network Error')
  assert.deepEqual([...report.warnings], [])
  assert.equal(report.conflictCount, 0)
  assert.deepEqual(importFailureLines(report), ['Network Error'])

  const blank = importFailureReport({ data: { data: { warnings: ['', '  '] } } }, '配置还原失败')
  assert.deepEqual([...blank.warnings], [], '空白 warning 不得渲染成空行')
})

test('接线：拦截器透传响应体，导入/还原失败路径复用同一展示函数且不再断言「配置未受影响」', () => {
  const api = code('src/utils/api.ts')
  assert.match(api, /readonly status\?: number[\s\S]*readonly data\?: unknown[\s\S]*constructor\(message: string, status\?: number, data\?: unknown\)/, 'ApiRequestError 必须携带响应体')
  assert.match(api, /this\.status = status[\s\S]*this\.data = data/, '构造参数必须落到只读字段')
  assert.match(api, /new ApiRequestError\(message, status, error\.response\?\.data\)/, '错误分支必须透传 error.response.data')

  const page = code('src/views/settings/BasicSettings.vue')
  const helper = section(page, 'const showImportFailure', 'const triggerImport')
  assert.match(helper, /importFailureReport\(error, fallbackMessage\)/)
  assert.match(helper, /importFailureLines\(report\)/)
  assert.match(helper, /ElMessageBox\.alert/)

  const restore = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  assert.match(restore, /showImportFailure\(error, '配置还原失败', '还原失败'\)/, '还原失败必须展示 warnings')
  assert.doesNotMatch(restore, /配置未受影响/, '不得把「配置未受影响」当成确定事实（文件面可能已分裂）')

  const importFn = section(page, 'const confirmImport', 'interface BasicSettingsConfig')
  assert.match(importFn, /showImportFailure\(error, '配置导入失败', '导入失败'\)/, '导入失败必须展示 warnings')
})
