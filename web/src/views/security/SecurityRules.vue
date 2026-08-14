<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Notebook /></el-icon>
          规则集
        </h2>
        <p class="page-desc">浏览 OWASP CRS 规则和管理自定义规则</p>
      </div>
    </div>

    <el-card class="crs-card mb-5">
      <template #header>
        <div class="crs-header">
          <div class="crs-header-title">
            <span style="font-weight: 500;">安全规则库</span>
          </div>
          <div class="crs-header-actions">
            <el-button v-if="!isReadOnly" size="small" type="primary" plain @click="manualUpdate">CRS 更新</el-button>
            <el-button v-if="!isReadOnly" size="small" type="primary" plain @click="manualIP2RegionUpdate">IP 库更新</el-button>
          </div>
        </div>
      </template>
      <el-descriptions :column="3" border>
        <el-descriptions-item label="CRS 版本">{{ crsInfo.version || '—' }}</el-descriptions-item>
        <el-descriptions-item label="规则文件数">{{ total }}</el-descriptions-item>
        <el-descriptions-item label="更新时间">{{ formatDate(crsInfo.updated_at) || '—' }}</el-descriptions-item>
        <el-descriptions-item label="自动更新">
          <div class="crs-cell-flex">
            <el-switch v-model="crsInfo.auto_update" :disabled="isReadOnly" @change="toggleAutoUpdate" />
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="更新状态">
          <div class="crs-cell-flex">
            <el-tooltip :disabled="!crsFailureMessage" :content="crsFailureMessage">
              <el-tag :type="crsStatusTagType(crsInfo.update_status)" size="small" effect="light">{{ crsStatusLabel(crsInfo.update_status) }}</el-tag>
            </el-tooltip>
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="下次更新">{{ formatDate(crsInfo.next_update) || '—' }}</el-descriptions-item>
      </el-descriptions>
      <el-descriptions :column="3" border class="ip2region-desc">
        <el-descriptions-item label="IP 库版本"><span class="version-cell">{{ ip2regionInfo.version || '—' }}</span></el-descriptions-item>
        <el-descriptions-item label="IP 规则数">{{ ip2regionInfo.db_size ? ip2regionInfo.db_size.toLocaleString() : '—' }}</el-descriptions-item>
        <el-descriptions-item label="更新时间">{{ formatDate(ip2regionInfo.updated_at) || '—' }}</el-descriptions-item>
        <el-descriptions-item label="自动更新">
          <div class="crs-cell-flex">
            <el-switch v-model="ip2regionInfo.auto_update" :disabled="isReadOnly" @change="toggleIP2RegionAutoUpdate" />
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="更新状态">
          <div class="crs-cell-flex">
            <el-tooltip :disabled="!ip2regionFailureMessage" :content="ip2regionFailureMessage">
              <el-tag :type="ip2regionStatusTagType(ip2regionInfo.update_status)" size="small" effect="light">{{ ip2regionStatusLabel(ip2regionInfo.update_status) }}</el-tag>
            </el-tooltip>
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="下次更新">{{ formatDate(ip2regionInfo.next_update) || '—' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card>
      <el-tabs v-model="activeTab">
        <el-tab-pane label="CRS 规则" name="rules">
          <div class="table-toolbar">
            <el-input v-model="searchQuery" placeholder="搜索规则文件名或分类" clearable :prefix-icon="Search" class="search-input" @clear="fetchRules" @keyup.enter="fetchRules" />
          </div>
          <el-table :data="rules" v-loading="loadingRules" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="" @row-click="openRuleContent" style="cursor: pointer">
            <template #empty><el-empty description="暂无规则文件" :image-size="60" /></template>
            <el-table-column prop="filename" label="文件名" min-width="320" show-overflow-tooltip />
            <el-table-column prop="category" label="分类" width="160">
              <template #default="{ row }"><el-tag size="small" effect="plain" type="info">{{ row.category }}</el-tag></template>
            </el-table-column>
            <el-table-column label="大小" width="100" align="right">
              <template #default="{ row }">{{ formatSize(row.size) }}</template>
            </el-table-column>
            <el-table-column label="更新时间" width="170" align="center">
              <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
            </el-table-column>
            <el-table-column label="" width="80" align="center">
              <template #default><el-button link type="primary" size="small">查看</el-button></template>
            </el-table-column>
          </el-table>
          <div style="display: flex; justify-content: center; margin-top: 16px;">
          <div class="rules-pagination">
            <el-pagination v-model:current-page="page" v-model:page-size="pageSize" :page-sizes="[10, 20, 50, 100]" :total="total" layout="total, sizes, prev, pager, next" @current-change="fetchRules" @size-change="fetchRules" />
          </div>
          </div>
        </el-tab-pane>
      <el-tab-pane label="自定义规则" name="custom">
            <div class="table-toolbar">
              <el-button v-if="!isReadOnly" type="primary" :icon="Plus" @click="openRuleDialog()">新建规则</el-button>
            </div>
            <el-table :data="customRulesPaged" v-loading="loadingCustom" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="">
            <template #empty><el-empty description="暂无自定义规则" :image-size="60" /></template>
            <el-table-column prop="name" label="规则名称" min-width="150">
              <template #default="{ row }">
                <el-link type="primary" :disabled="isReadOnly" @click="openRuleDialog(row)">{{ row.name }}</el-link>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
            <el-table-column label="条件" min-width="250">
              <template #default="{ row }">
                <el-tag v-for="(cond, i) in row.conditions" :key="i" size="small" effect="plain" style="margin-right: 4px;">{{ cond.target }} {{ cond.operator }} {{ cond.pattern }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="动作" width="80" align="center">
              <template #default="{ row }">
                <el-tag :type="row.action === 'block' ? 'danger' : 'warning'" size="small" effect="light">{{ row.action === 'block' ? '拦截' : '记录' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="80" align="center">
              <template #default="{ row }">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small" effect="light">{{ row.enabled ? '启用' : '禁用' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="更新时间" width="170" align="center">
              <template #default="{ row }">{{ formatDate(row.updated_at) || '-' }}</template>
            </el-table-column>
            <el-table-column label="更新者" width="100" align="center">
              <template #default="{ row }">{{ getUpdaterName(row.updated_by) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="140" fixed="right">
              <template #default="{ row }">
                <el-button size="small" link type="primary" :disabled="isReadOnly" @click="openRuleDialog(row)">编辑</el-button>
                <el-button size="small" link type="danger" :disabled="isReadOnly" @click="deleteCustomRule(row)">删除</el-button>
            </template>
            </el-table-column>
          </el-table>
          <div class="rules-pagination">
            <el-pagination v-model:current-page="customPage" v-model:page-size="customPageSize" :total="customRules.length" layout="total, sizes, prev, pager, next" @size-change="customPage = 1" />
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-dialog v-model="contentDialogVisible" :title="currentFilename" width="900px" top="5vh">
      <div v-loading="loadingContent"><SyntaxHighlight :content="currentContent" language="apacheconf" /></div>
    </el-dialog>

    <el-dialog v-model="ruleDialogVisible" :title="editingRuleId ? (isReadOnly ? '查看自定义规则' : '编辑自定义规则') : '新建自定义规则'" width="760px">
      <el-form :model="ruleForm" label-width="80px" label-position="right" :disabled="isReadOnly">
        <el-form-item label="名称" required>
          <el-input v-model="ruleForm.name" placeholder="规则名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="ruleForm.description" placeholder="规则描述" />
        </el-form-item>
        <el-form-item label="条件">
          <div style="width: 100%">
            <div v-for="(cond, idx) in ruleForm.conditions" :key="idx" class="rule-condition-row">
              <el-select v-model="cond.target" style="width: 120px" size="small">
                <el-option label="请求路径" value="uri" />
                <el-option label="请求参数" value="args" />
                <el-option label="请求头" value="headers" />
                <el-option label="请求体" value="body" />
                <el-option label="User-Agent" value="user_agent" />
              </el-select>
              <el-select v-model="cond.operator" style="width: 110px" size="small">
                <el-option label="包含" value="contains" />
                <el-option label="正则匹配" value="regex" />
                <el-option label="完全匹配" value="equals" />
                <el-option label="前缀匹配" value="starts_with" />
              </el-select>
              <div class="pattern-col">
                <div class="pattern-input-row">
                  <el-input v-model="cond.pattern" :placeholder="patternPlaceholder(cond)" size="small" :class="{ 'is-error': cond.operator === 'regex' && !isValidRegex(cond.pattern) }" />
                  <el-icon v-if="cond.operator === 'regex' && !isValidRegex(cond.pattern)" class="regex-error-icon"><WarningFilled /></el-icon>
                </div>
                <div v-if="cond.target === 'user_agent'" class="preset-section">
                  <div class="preset-header" @click="uaCollapsed[idx] = !uaCollapsed[idx]">
                    <span class="preset-toggle">{{ uaCollapsed[idx] ? '▶' : '▼' }} 快捷标签</span>
                  </div>
                  <div v-show="!uaCollapsed[idx]" class="preset-tags-block">
                    <div v-for="g in UA_PRESET_GROUPS" :key="g.label" class="preset-group">
                      <span class="preset-group-label">{{ g.label }}</span>
                      <div class="preset-group-tags">
                        <el-tag v-for="t in g.values" :key="t.value" size="small" effect="plain" class="preset-tag" @click="cond.pattern = t.value">{{ t.label }}</el-tag>
                      </div>
                    </div>
                    <div class="preset-hint">标签写入真实 UA 片段（contains 精确匹配，区分大小写）</div>
                  </div>
                </div>
                <div v-if="cond.operator === 'regex'" class="preset-section">
                  <div class="preset-header" @click="regexCollapsed[idx] = !regexCollapsed[idx]">
                    <span class="preset-toggle">{{ regexCollapsed[idx] ? '▶' : '▼' }} 正则模板与测试</span>
                  </div>
                  <div v-show="!regexCollapsed[idx]" class="regex-extras">
                    <div class="regex-presets">
                      <el-link v-for="p in REGEX_PRESETS" :key="p.label" type="primary" :underline="false" class="regex-preset-link" @click="cond.pattern = p.value">{{ p.label }}</el-link>
                    </div>
                    <div class="regex-tester">
                      <el-input v-model="regexTestStrings[idx]" placeholder="输入测试字符串" size="small" class="regex-test-input" />
                      <span class="regex-test-result" :class="regexResultClass(cond, idx)">{{ regexResultText(cond, idx) }}</span>
                    </div>
                  </div>
                </div>
              </div>
              <el-button link type="danger" size="small" @click="removeCondition(idx)">删除</el-button>
            </div>
            <el-button size="small" type="primary" plain class="add-condition-btn" @click="ruleForm.conditions.push({ target: 'uri', operator: 'contains', pattern: '' })">
              + 添加条件
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="动作">
          <el-radio-group v-model="ruleForm.action">
            <el-radio value="block">拦截</el-radio>
            <el-radio value="log">仅记录</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="异常分值">
          <el-select v-model="ruleForm.score" style="width: 160px">
            <el-option :value="1" label="轻微（1）" />
            <el-option :value="3" label="较低（3）" />
            <el-option :value="5" label="中等（5）" />
            <el-option :value="10" label="较高（10）" />
            <el-option :value="20" label="严重（20）" />
          </el-select>
          <span class="form-tip-inline">匹配此规则时累加的异常分值，达到策略异常阈值后触发拦截</span>
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="ruleForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="ruleDialogVisible = false">取消</el-button>
        <el-button type="primary" :disabled="isReadOnly" :loading="savingRule" @click="saveCustomRule">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="updateDialogVisible"
      title="更新 CRS 规则库"
      width="min(900px, 94vw)"
      destroy-on-close
      @opened="onUpdateDialogOpened"
      @closed="onUpdateDialogClosed"
    >
      <div class="update-status-row">
        <span>当前状态</span>
        <el-tag :type="crsStatusTagType(updateInfo?.status || 'idle')" size="small" effect="light">{{ crsStatusLabel(updateInfo?.status || 'idle') }}</el-tag>
      </div>
      <div ref="updateLogRef" class="update-log-container">
        <pre v-if="updateLog" class="update-log-content">{{ updateLog }}</pre>
        <el-empty v-else description="暂无更新日志" :image-size="60" />
      </div>
      <template #footer>
        <el-button @click="updateDialogVisible = false">关闭</el-button>
        <el-button v-if="!crsUpdateRunning" type="primary" :loading="startingUpdate" @click="confirmUpdate">立即更新</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="ip2regionUpdateDialogVisible"
      title="更新 IP 库"
      width="min(900px, 94vw)"
      destroy-on-close
      @opened="onIP2RegionUpdateDialogOpened"
      @closed="onIP2RegionUpdateDialogClosed"
    >
      <div class="update-status-row">
        <span>当前状态</span>
        <el-tag :type="ip2regionStatusTagType(ip2regionUpdateInfo?.status || 'idle')" size="small" effect="light">{{ ip2regionStatusLabel(ip2regionUpdateInfo?.status || 'idle') }}</el-tag>
      </div>
      <div ref="ip2regionUpdateLogRef" class="update-log-container">
        <pre v-if="ip2regionUpdateLog" class="update-log-content">{{ ip2regionUpdateLog }}</pre>
        <el-empty v-else description="暂无更新日志" :image-size="60" />
      </div>
      <template #footer>
        <el-button @click="ip2regionUpdateDialogVisible = false">关闭</el-button>
        <el-button v-if="!ip2regionUpdateRunning" type="primary" :loading="startingIP2RegionUpdate" @click="confirmIP2RegionUpdate">立即更新</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, nextTick } from 'vue'
import { Search, Notebook, Plus, WarningFilled } from '@element-plus/icons-vue'
import { formatDate } from '@/utils/date'
import SyntaxHighlight from '@/components/SyntaxHighlight.vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, ApiRequestError } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { useAuthStore } from '@/stores/auth'
import type { UserListItem } from '@/types'

interface APIResponse<T> { code: number; message: string; data: T }
interface CRSRuleFile { filename: string; category: string; size: number; updated_at: string }
interface CustomRuleCondition { target: string; operator: string; pattern: string }
interface CustomRule { id: number; name: string; description: string; conditions: CustomRuleCondition[]; action: string; score: number; enabled: boolean; updated_at: string; updated_by: number }
interface CRSUpdateInfo { readonly status: string; readonly trigger: string; readonly started_at: string; readonly finished_at: string; readonly message: string; readonly version: string }
interface IP2RegionUpdateInfo { readonly status: string; readonly trigger: string; readonly started_at: string; readonly finished_at: string; readonly message: string; readonly version: string }

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)

const users = ref<UserListItem[]>([])
const getUpdaterName = (userId?: number) => {
  if (!userId || userId === 0) return '-'
  const user = users.value.find(u => u.id === userId)
  return user?.display_name || user?.username || '-'
}

const crsStageLabels: Record<string, string> = {
  checking: '检查更新',
  downloading: '下载规则库',
  installing: '安装规则库',
  reloading: '重载配置',
  success: '更新成功',
  failed: '更新失败',
  idle: '空闲',
}
const crsStatusLabel = (s: string): string => crsStageLabels[s] || s || '—'

const crsStatusTagType = (s: string): 'success' | 'warning' | 'danger' | 'info' => {
  if (!s || s === 'idle') return 'info'
  if (s === 'checking' || s === 'downloading' || s === 'installing' || s === 'reloading') return 'warning'
  if (s === 'success' || s === '已最新' || s === '更新成功') return 'success'
  if (s === 'failed' || s === '更新失败') return 'danger'
  if (s.includes('失败') || s.includes('错误')) return 'danger'
  if (s.includes('最新')) return 'success'
  if (s.includes('中')) return 'warning'
  return 'info'
}

const crsInfo = ref({ version: '', auto_update: true, updated_at: '', next_update: '', update_status: '', message: '' })
const crsFailureMessage = computed(() => {
  const s = crsInfo.value.update_status
  return (s === 'failed' || s === '更新失败') ? crsInfo.value.message : ''
})

const ip2regionStageLabels: Record<string, string> = {
  checking: '检查更新',
  downloading: '下载IP库',
  installing: '安装',
  success: '更新成功',
  failed: '更新失败',
  idle: '空闲',
}
const ip2regionStatusLabel = (s: string): string => ip2regionStageLabels[s] || s || '—'
const ip2regionStatusTagType = (s: string): 'success' | 'warning' | 'danger' | 'info' => {
  if (!s || s === 'idle') return 'info'
  if (s === 'checking' || s === 'downloading' || s === 'installing') return 'warning'
  if (s === 'success') return 'success'
  if (s === 'failed') return 'danger'
  return 'info'
}
const ip2regionInfo = ref({ version: '', db_size: 0, auto_update: true, updated_at: '', next_update: '', update_status: '', message: '' })
const ip2regionFailureMessage = computed(() => {
  const s = ip2regionInfo.value.update_status
  return (s === 'failed' || s === '更新失败') ? ip2regionInfo.value.message : ''
})

const activeTab = ref('rules')
const loadingRules = ref(false)
const rules = ref<CRSRuleFile[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(10)
const searchQuery = ref('')
const contentDialogVisible = ref(false)
const loadingContent = ref(false)
const currentFilename = ref('')
const currentContent = ref('')

const customRules = ref<CustomRule[]>([])
const customPage = ref(1)
const customPageSize = ref(10)
const customRulesPaged = computed(() => {
  const start = (customPage.value - 1) * customPageSize.value
  return customRules.value.slice(start, start + customPageSize.value)
})
const loadingCustom = ref(false)
const ruleDialogVisible = ref(false)
const editingRuleId = ref<number | null>(null)
const savingRule = ref(false)
const ruleForm = ref({ name: '', description: '', conditions: [] as CustomRuleCondition[], action: 'block', score: 5, enabled: true })

const PATTERN_PLACEHOLDERS: Record<string, string> = {
  uri: '如 /admin',
  args: '如 debug=1',
  headers: '如 X-Custom-Header',
  body: '如 password',
  user_agent: '如 sqlmap',
}
const patternPlaceholder = (cond: CustomRuleCondition): string => {
  if (cond.operator === 'regex') return '如 ^/admin/.*$'
  return PATTERN_PLACEHOLDERS[cond.target] ?? '匹配值'
}

// User-Agent 快捷预设：标签为用户友好文案，value 为真实 UA 中的准确片段
// （@contains 大小写敏感，value 必须与线上 UA 实际大小写一致才能命中）
const UA_PRESET_GROUPS: ReadonlyArray<{ label: string; values: ReadonlyArray<{ label: string; value: string }> }> = [
  { label: '攻击工具', values: [
    { label: 'sqlmap', value: 'sqlmap/' },
    { label: 'Nikto', value: 'Nikto/' },
    { label: 'Nmap NSE', value: 'Nmap Scripting Engine' },
    { label: 'masscan', value: 'masscan/' },
    { label: 'hydra', value: 'Hydra' },
  ] },
  { label: '爬虫', values: [
    { label: '机器人', value: 'bot' },
    { label: 'Spider 爬虫', value: 'spider' },
    { label: 'Python 脚本', value: 'python-requests' },
    { label: 'Go 脚本', value: 'Go-http-client' },
    { label: 'curl', value: 'curl/' },
    { label: 'Wget', value: 'Wget/' },
  ] },
  { label: '浏览器', values: [
    { label: 'Chromium', value: 'Chrome/' },
    { label: 'Firefox', value: 'Firefox/' },
    { label: 'Safari', value: 'Safari/' },
    { label: 'Edge', value: 'Edg' },
  ] },
  { label: '系统', values: [
    { label: 'Windows', value: 'Windows NT' },
    { label: 'Linux 桌面', value: 'X11; Linux' },
    { label: 'macOS', value: 'Macintosh' },
    { label: 'iPhone', value: 'iPhone' },
    { label: 'Android', value: 'Android' },
  ] },
]

// 正则模板：点击即填充
const REGEX_PRESETS: ReadonlyArray<{ label: string; value: string }> = [
  { label: 'SQL注入', value: '(?i)(union|select|insert|drop)' },
  { label: 'XSS', value: '(?i)(<script|javascript:|onerror=)' },
  { label: '路径穿越', value: '\\.\\.[\\\\/]' },
  { label: '命令注入', value: '(?i)(;|\\|\\||&&|\\$\\()' },
  { label: '敏感文件', value: '(?i)(\\.(env|git|svn|htaccess))' },
  { label: 'Linux 服务器', value: '(?i)linux (x86_64|aarch64|armv7l|armv6l|armv8l|i686|riscv64)' },
  { label: '手机浏览器', value: '(?i)(iphone|android)' },
]

// 每条 regex 条件的临时测试字符串（按 idx 索引；条件删除时同步重排避免错位）
const regexTestStrings = ref<Record<number, string>>({})
const uaCollapsed = ref<Record<number, boolean>>({})
const regexCollapsed = ref<Record<number, boolean>>({})

const regexResultClass = (cond: CustomRuleCondition, idx: number): string => {
  if (!cond.pattern) return ''
  const { re, valid } = buildJSRegex(cond.pattern)
  if (!valid) return 'regex-invalid'
  const ts = regexTestStrings.value[idx] || ''
  if (!ts) return ''
  return re!.test(ts) ? 'regex-match' : 'regex-nomatch'
}

const regexResultText = (cond: CustomRuleCondition, idx: number): string => {
  if (!cond.pattern) return ''
  const { re, valid } = buildJSRegex(cond.pattern)
  if (!valid) return '正则语法错误'
  const ts = regexTestStrings.value[idx] || ''
  if (!ts) return ''
  return re!.test(ts) ? '匹配 ✓' : '不匹配 ✗'
}

const isValidRegex = (pattern: string): boolean => {
  if (!pattern) return true
  return buildJSRegex(pattern).valid
}

function buildJSRegex(pattern: string): { re: RegExp | null; valid: boolean } {
	let flags = ''
	let src = pattern
	const m = pattern.match(/^\(\?([a-z])\)(.*)/)
	if (m) { flags = m[1]; src = m[2] }
	if (/\(\?<?[=!]/.test(src)) { return { re: null, valid: false } }
	try { return { re: new RegExp(src, flags), valid: true } } catch { return { re: null, valid: false } }
}

const removeCondition = (idx: number) => {
  ruleForm.value.conditions.splice(idx, 1)
  // 同步重排 regex 测试字符串的 idx 键，避免错位显示
  const prev = regexTestStrings.value
  const next: Record<number, string> = {}
  for (const k of Object.keys(prev)) {
    const n = Number(k)
    if (n < idx) next[n] = prev[n]
    else if (n > idx) next[n - 1] = prev[n]
  }
  regexTestStrings.value = next
}

const fetchCRS = async () => { try { const res = await request.get<APIResponse<typeof crsInfo.value>>('/security/crs'); if (res.data) crsInfo.value = res.data } catch {} }
const fetchRules = async () => {
  loadingRules.value = true
  try { const p = new URLSearchParams({ page: String(page.value), page_size: String(pageSize.value) }); if (searchQuery.value) p.set('search', searchQuery.value); const res = await request.get<APIResponse<{ rules: CRSRuleFile[]; total: number }>>(`/security/crs/rules?${p}`); rules.value = res.data?.rules || []; total.value = res.data?.total || 0 } catch { rules.value = [] } finally { loadingRules.value = false }
}
const fetchCustomRules = async () => { loadingCustom.value = true; try { const res = await request.get<APIResponse<CustomRule[]>>('/security/custom-rules'); customRules.value = res.data || [] } catch { customRules.value = [] } finally { loadingCustom.value = false } }
const fetchUsers = async () => { try { const res = await request.get<APIResponse<UserListItem[]>>('/users'); users.value = res.data || [] } catch {} }

const openRuleContent = async (row: CRSRuleFile) => { currentFilename.value = row.filename; contentDialogVisible.value = true; loadingContent.value = true; currentContent.value = ''; try { const res = await request.get<APIResponse<{ content: string; size: number }>>(`/security/crs/rules/${encodeURIComponent(row.filename)}`); currentContent.value = res.data?.content || '(空文件)' } catch { currentContent.value = '加载失败' } finally { loadingContent.value = false } }
const toggleAutoUpdate = async (val: boolean) => { try { await request.put('/security/crs/auto-update', { auto_update: val }); ElMessage.success('已更新') } catch { crsInfo.value.auto_update = !val; ElMessage.error('更新失败') } }
const fetchIP2RegionInfo = async () => { try { const res = await request.get<APIResponse<typeof ip2regionInfo.value>>('/security/ip2region'); if (res.data) ip2regionInfo.value = res.data } catch {} }
const toggleIP2RegionAutoUpdate = async (val: boolean) => { try { await request.put('/security/ip2region/auto-update', { auto_update: val }); ElMessage.success('已更新') } catch { ip2regionInfo.value.auto_update = !val; ElMessage.error('更新失败') } }

const updateDialogVisible = ref(false)
const updateInfo = ref<CRSUpdateInfo | null>(null)
const updateLog = ref('')
const updateLogRef = ref<HTMLDivElement | null>(null)
let updateRequestSeq = 0
let updatePollTimer: ReturnType<typeof setInterval> | null = null

const startingUpdate = ref(false)
const crsUpdateRunning = computed(() => {
  const s = updateInfo.value?.status || ''
  return s === 'checking' || s === 'downloading' || s === 'installing' || s === 'reloading'
})

const manualUpdate = () => {
  updateRequestSeq++
  updateInfo.value = null
  updateLog.value = ''
  updateDialogVisible.value = true
}

// 打开弹框只拉取一次当前状态与既有日志；若有任务在跑则继续实时轮询
const onUpdateDialogOpened = async () => {
  await refreshUpdateStatus()
  if (crsUpdateRunning.value) {
    startUpdatePolling()
  }
}

// 确认触发更新：409 表示已有任务在运行，跳过触发直接轮询进度
const confirmUpdate = async () => {
  startingUpdate.value = true
  try {
    await request.post<APIResponse<{ status: string; trigger: string }>>('/security/crs/update', undefined, { silent: true })
  } catch (error) {
    if (!(error instanceof ApiRequestError && error.status === 409)) {
      ElMessage.error(error instanceof Error ? error.message : '触发更新失败')
    }
  } finally {
    startingUpdate.value = false
  }
  if (!updateDialogVisible.value) return
  await refreshUpdateStatus()
  if (!updateDialogVisible.value) return
  startUpdatePolling()
}

const onUpdateDialogClosed = () => {
  updateRequestSeq++
  stopUpdatePolling()
  updateInfo.value = null
  updateLog.value = ''
}

const startUpdatePolling = () => {
  stopUpdatePolling()
  updatePollTimer = setInterval(refreshUpdateStatus, 2000)
}

const stopUpdatePolling = () => {
  if (updatePollTimer) {
    clearInterval(updatePollTimer)
    updatePollTimer = null
  }
}

const refreshUpdateStatus = async () => {
  if (!updateDialogVisible.value) return
  const requestSeq = ++updateRequestSeq
  const [statusResult, logsResult] = await Promise.allSettled([
    request.get<APIResponse<CRSUpdateInfo>>('/security/crs/update/status', { silent: true }),
    request.get<APIResponse<{ content: string }>>('/security/crs/update/logs', { silent: true }),
  ])
  if (!updateDialogVisible.value || requestSeq !== updateRequestSeq) return
  if (statusResult.status === 'fulfilled') {
    updateInfo.value = statusResult.value.data || null
  } else {
    console.error('Failed to fetch CRS update status:', statusResult.reason)
  }
  if (logsResult.status === 'fulfilled') {
    updateLog.value = logsResult.value.data?.content || ''
    await scrollUpdateLogToBottom()
  } else {
    console.error('Failed to fetch CRS update logs:', logsResult.reason)
  }
  const status = updateInfo.value?.status
  if (status === 'success' || status === 'failed') {
    stopUpdatePolling()
    if (status === 'success') {
      fetchCRS()
      fetchRules()
    }
  }
}

const scrollUpdateLogToBottom = async () => {
  await nextTick()
  if (updateLogRef.value) {
    updateLogRef.value.scrollTop = updateLogRef.value.scrollHeight
  }
}

const ip2regionUpdateDialogVisible = ref(false)
const ip2regionUpdateInfo = ref<IP2RegionUpdateInfo | null>(null)
const ip2regionUpdateLog = ref('')
const ip2regionUpdateLogRef = ref<HTMLDivElement | null>(null)
let ip2regionRequestSeq = 0
let ip2regionPollTimer: ReturnType<typeof setInterval> | null = null

const startingIP2RegionUpdate = ref(false)
const ip2regionUpdateRunning = computed(() => {
  const s = ip2regionUpdateInfo.value?.status || ''
  return s === 'checking' || s === 'downloading' || s === 'installing'
})

const manualIP2RegionUpdate = () => {
  ip2regionRequestSeq++
  ip2regionUpdateInfo.value = null
  ip2regionUpdateLog.value = ''
  ip2regionUpdateDialogVisible.value = true
}

// 打开弹框只拉取一次当前状态与既有日志；若有任务在跑则继续实时轮询
const onIP2RegionUpdateDialogOpened = async () => {
  await refreshIP2RegionUpdateStatus()
  if (ip2regionUpdateRunning.value) {
    startIP2RegionPolling()
  }
}

// 确认触发更新：409 表示已有任务在运行，跳过触发直接轮询进度
const confirmIP2RegionUpdate = async () => {
  startingIP2RegionUpdate.value = true
  try {
    await request.post<APIResponse<{ status: string; trigger: string }>>('/security/ip2region/update', undefined, { silent: true })
  } catch (error) {
    if (!(error instanceof ApiRequestError && error.status === 409)) {
      ElMessage.error(error instanceof Error ? error.message : '触发更新失败')
    }
  } finally {
    startingIP2RegionUpdate.value = false
  }
  if (!ip2regionUpdateDialogVisible.value) return
  await refreshIP2RegionUpdateStatus()
  if (!ip2regionUpdateDialogVisible.value) return
  startIP2RegionPolling()
}

const onIP2RegionUpdateDialogClosed = () => {
  ip2regionRequestSeq++
  stopIP2RegionPolling()
  ip2regionUpdateInfo.value = null
  ip2regionUpdateLog.value = ''
}

const startIP2RegionPolling = () => {
  stopIP2RegionPolling()
  ip2regionPollTimer = setInterval(refreshIP2RegionUpdateStatus, 2000)
}

const stopIP2RegionPolling = () => {
  if (ip2regionPollTimer) {
    clearInterval(ip2regionPollTimer)
    ip2regionPollTimer = null
  }
}

const refreshIP2RegionUpdateStatus = async () => {
  if (!ip2regionUpdateDialogVisible.value) return
  const requestSeq = ++ip2regionRequestSeq
  const [statusResult, logsResult] = await Promise.allSettled([
    request.get<APIResponse<IP2RegionUpdateInfo>>('/security/ip2region/update/status', { silent: true }),
    request.get<APIResponse<{ content: string }>>('/security/ip2region/update/logs', { silent: true }),
  ])
  if (!ip2regionUpdateDialogVisible.value || requestSeq !== ip2regionRequestSeq) return
  if (statusResult.status === 'fulfilled') {
    ip2regionUpdateInfo.value = statusResult.value.data || null
  } else {
    console.error('Failed to fetch IP2Region update status:', statusResult.reason)
  }
  if (logsResult.status === 'fulfilled') {
    ip2regionUpdateLog.value = logsResult.value.data?.content || ''
    await scrollIP2RegionUpdateLogToBottom()
  } else {
    console.error('Failed to fetch IP2Region update logs:', logsResult.reason)
  }
  const status = ip2regionUpdateInfo.value?.status
  if (status === 'success' || status === 'failed') {
    stopIP2RegionPolling()
    if (status === 'success') {
      fetchIP2RegionInfo()
    }
  }
}

const scrollIP2RegionUpdateLogToBottom = async () => {
  await nextTick()
  if (ip2regionUpdateLogRef.value) {
    ip2regionUpdateLogRef.value.scrollTop = ip2regionUpdateLogRef.value.scrollHeight
  }
}

const openRuleDialog = (row?: CustomRule) => {
  editingRuleId.value = row?.id ?? null
  if (row) {
    ruleForm.value = { name: row.name, description: row.description, conditions: [...row.conditions], action: row.action, score: row.score, enabled: row.enabled }
  } else {
    ruleForm.value = { name: '', description: '', conditions: [{ target: 'uri', operator: 'contains', pattern: '' }], action: 'block', score: 5, enabled: true }
  }
  ruleDialogVisible.value = true
}

const saveCustomRule = async () => {
  if (!ruleForm.value.name.trim()) { ElMessage.warning('请输入规则名称'); return }
  for (const cond of ruleForm.value.conditions) {
    if (!cond.pattern.trim()) { ElMessage.error('每个条件必须填写匹配值'); return }
    if (cond.operator === 'regex' && !isValidRegex(cond.pattern)) { ElMessage.error(`正则表达式语法错误：${cond.pattern}`); return }
  }
  savingRule.value = true
  try {
    const res = editingRuleId.value
      ? await request.put(`/security/custom-rules/${editingRuleId.value}`, ruleForm.value)
      : await request.post('/security/custom-rules', ruleForm.value)
    showSaveResult(res, '保存成功'); ruleDialogVisible.value = false; fetchCustomRules()
  } catch { ElMessage.error('保存失败') } finally { savingRule.value = false }
}

const deleteCustomRule = (row: CustomRule) => {
  ElMessageBox.confirm(`确定删除规则"${row.name}"？`, '确认', { type: 'warning' })
    .then(async () => { await request.delete(`/security/custom-rules/${row.id}`); ElMessage.success('已删除'); fetchCustomRules() }).catch(() => {})
}

const formatSize = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`

onMounted(() => {
  const urlTab = new URLSearchParams(location.search).get('tab')
  if (urlTab && ['rules', 'custom'].includes(urlTab)) {
    activeTab.value = urlTab
  } else {
    const tab = localStorage.getItem('security-rules-tab')
    if (tab) { activeTab.value = tab; localStorage.removeItem('security-rules-tab') }
  }
  fetchCRS(); fetchIP2RegionInfo(); fetchRules(); fetchCustomRules(); fetchUsers()
})

onUnmounted(() => {
  updateRequestSeq++
  stopUpdatePolling()
  ip2regionRequestSeq++
  stopIP2RegionPolling()
})
</script>

<style scoped>
.crs-card :deep(.el-card__header) .crs-header { display: flex; justify-content: space-between; align-items: center; width: 100%; }
.crs-card :deep(.el-card__header) .crs-header-title { display: flex; align-items: center; gap: 12px; }
.crs-card :deep(.el-card__header) .crs-header-actions { display: flex; gap: 8px; }
.crs-card :deep(.el-descriptions__table) { table-layout: fixed; width: 100%; }
.crs-card :deep(.el-descriptions__cell) { height: 48px; vertical-align: middle; }
.crs-card .ip2region-desc { margin-top: 20px; }
.crs-cell-flex { display: flex; align-items: center; height: 24px; }
.rule-condition-row { display: flex; gap: 8px; margin-bottom: 8px; align-items: flex-start; flex-wrap: wrap; padding: 8px; background: #f9fafb; border: 1px solid #f3f4f6; border-radius: 4px; }
.pattern-col { flex: 1; min-width: 220px; display: flex; flex-direction: column; gap: 6px; }
.pattern-input-row { display: flex; align-items: center; gap: 6px; }
.preset-section { margin-top: 4px; }
.preset-header { cursor: pointer; padding: 2px 0; user-select: none; }
.preset-toggle { font-size: 12px; color: #6b7280; }
.preset-tags-block { display: flex; flex-direction: column; gap: 4px; padding: 6px 8px; background: #fff; border: 1px dashed #e5e7eb; border-radius: 4px; margin-left: 0; }
.preset-group { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
.preset-group-label { font-size: 12px; color: #6b7280; flex: 0 0 56px; text-align: right; line-height: 1; }
.preset-hint { font-size: 12px; color: #9ca3af; margin-top: 6px; line-height: 1.4; }
.preset-group-tags { display: inline-flex; flex-wrap: wrap; gap: 4px; flex: 1; align-items: center; }
.preset-group-tags .el-tag { margin: 0; }
.preset-group-tags .preset-tag { cursor: pointer; }
.regex-extras { display: flex; flex-direction: column; gap: 6px; padding: 6px 8px; background: #fff; border: 1px dashed #e5e7eb; border-radius: 4px; }
.regex-presets { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }
.regex-preset-link { font-size: 12px; }
.regex-tester { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.regex-test-input { width: 240px; }
.regex-test-result { font-size: 12px; font-weight: 500; white-space: nowrap; }
.regex-test-result.regex-match { color: #10b981; }
.regex-test-result.regex-nomatch { color: #ef4444; }
.regex-test-result.regex-invalid { color: #f59e0b; }
.add-condition-btn { margin-top: 4px; }
.table-toolbar { display: flex; justify-content: flex-end; margin-bottom: 16px; }
.search-input { width: 280px; }
.rules-pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
.update-status-row { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
.update-log-container { max-height: 480px; overflow: auto; background: #1e293b; border-radius: 6px; padding: 16px; }
.update-log-content { margin: 0; color: #e4e4e7; font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-all; }
</style>
