// 设置页写操作/失败态契约：
//   A. 删除自动备份后走 quiet 刷新（不得整体覆盖未保存的表单编辑）
//   B. 备份行「还原/删除」有在途门（占位先于确认框，防叠框/并发提交）
//   C. 管理面板证书解析失败在弹框内常驻可见（含只选一半材料的原因）
//   D. 访问日志格式区分前端字符上限与后端 UTF-8 字节门（16KiB / 200 行）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, repoCode, section } from './_helpers.ts'

const page = code('src/views/settings/BasicSettings.vue')

test('A 删除备份后的刷新不得覆盖未保存的自动备份表单', () => {
  const del = section(page, 'const deleteAutoBackup = async', 'interface ImportValidation')
  assert.match(del, /await fetchAutoBackup\(true\)/, '缺省 quiet=false 会用服务端值整体覆盖表单')
  assert.doesNotMatch(del, /await fetchAutoBackup\(\)/)
})

test('B 备份行还原/删除有在途门（占位先于确认、按钮联动 loading/disabled）', () => {
  assert.match(page, /const restoringBackupId = ref<number \| null>\(null\)/)
  assert.match(page, /const deletingBackupId = ref<number \| null>\(null\)/)
  assert.match(page, /const autoBackupActionBusy = computed\(\(\) => restoringBackupId\.value !== null \|\| deletingBackupId\.value !== null\)/)

  const restore = section(page, 'const restoreAutoBackup = async', 'const deleteAutoBackup = async')
  const guard = restore.indexOf('if (backupDisabled.value || autoBackupActionBusy.value) return')
  const occupy = restore.indexOf('restoringBackupId.value = row.id')
  const confirm = restore.indexOf('ElMessageBox.confirm')
  assert.ok(guard > 0 && occupy > guard && confirm > occupy, '占位必须先于确认框（双击不得叠两个确认框）')
  assert.match(restore, /finally \{\s*restoringBackupId\.value = null/, '在途态必须在 finally 释放')

  const del = section(page, 'const deleteAutoBackup = async', 'interface ImportValidation')
  assert.match(del, /if \(backupDisabled\.value \|\| autoBackupActionBusy\.value\) return/)
  assert.match(del, /deletingBackupId\.value = row\.id[\s\S]*ElMessageBox\.confirm/, '删除同样占位先于确认')
  assert.match(del, /finally \{\s*deletingBackupId\.value = null/)

  assert.match(page, /:loading="restoringBackupId === row\.id"/, '还原按钮须呈在途态')
  assert.match(page, /:loading="deletingBackupId === row\.id"/, '删除按钮须呈在途态')
  assert.match(page, /:disabled="autoBackupActionBusy \|\| backupDisabled" @click="restoreAutoBackup\(row\)"/)
  assert.match(page, /:disabled="autoBackupActionBusy \|\| backupDisabled" @click="deleteAutoBackup\(row\)"/)
})

test('C 管理面板证书解析失败在弹框内常驻可见，重选文件即清除', () => {
  assert.match(page, /inspectError: string/, '弹框表单须带失败原因字段')
  assert.match(page, /class="info-note-desc">\{\{ adminTlsForm\.inspectError \}\}<\/el-text>/, '原因必须渲染在弹框内')
  const inspect = section(page, 'const onTlsFile = async', 'const notifyTlsRestarting')
  assert.match(inspect, /adminTlsForm\.value\.inspectError = ''/, '重选文件须清除旧原因')
  assert.match(inspect, /adminTlsForm\.value\.inspectError = '证书解析失败：/, 'catch 必须写原因（不再只把 certInfo 置空）')
  // 只选一半材料时也有可见原因（解析中/解析失败/配对缺失不可同形）
  assert.match(page, /const adminTlsMissingPairHint = computed\(/)
  assert.match(page, /还需选择私钥文件才能解析证书/)
  assert.match(page, /还需选择证书文件才能解析证书/)
})

test('D 访问日志格式：maxlength 是字符上限，后端按 UTF-8 字节拒绝', () => {
  const handlers = repoCode('internal/handlers/caddy.go')
  const bytes = /maxAccessLogFormatBytes = (\d+) \* (\d+)/.exec(handlers)
  const lines = /maxAccessLogFormatLines = (\d+)/.exec(handlers)
  assert.ok(bytes && lines, '后端缺访问日志格式写侧门')
  const byteLimit = Number(bytes[1]) * Number(bytes[2])

  const settings = code('src/views/settings/CaddyGlobalSettings.vue')
  const input = section(settings, 'v-model="settings.access_log_format"', '/>')
  assert.match(input, new RegExp(`maxlength="${byteLimit}"`), 'maxlength 仅作为同数值的宽松字符上限')
  assert.match(input, /show-word-limit/)
  assert.match(settings, new RegExp(`最多 ${lines[1]} 行、${byteLimit / 1024} KiB（后端按 UTF-8 字节计）`), '提示必须明确真正拒绝口径是 UTF-8 字节')

  const byteLength = (value: string): number => new TextEncoder().encode(value).length
  assert.equal(byteLength('a'.repeat(byteLimit)), byteLimit, 'ASCII 恰 16 KiB')
  assert.equal(byteLength('a'.repeat(byteLimit + 1)), byteLimit + 1, 'ASCII 超 1 字节')
  const chinese = '界'.repeat(byteLimit)
  assert.equal(chinese.length, byteLimit, '中文仍能占满前端字符上限')
  assert.equal(byteLength(chinese), byteLimit * 3, '相同字符数已是三倍 UTF-8 字节')
  assert.ok(byteLength(chinese) > byteLimit, '中文超字节形态必须落入后端拒绝面')
  const emoji = '😀'.repeat(byteLimit / 2)
  assert.equal(emoji.length, byteLimit)
  assert.equal(byteLength(emoji), byteLimit * 2)
  const validator = section(handlers, 'func validateAccessLogFormatSize', '\n}')
  assert.match(validator, /len\(format\); n > maxAccessLogFormatBytes/, 'Go len(string) 必须执行 UTF-8 字节门')
})
