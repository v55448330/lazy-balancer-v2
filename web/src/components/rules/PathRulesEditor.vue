<template>
  <div class="path-rules-editor">
    <div class="editor-section-header">
      <div class="editor-heading-copy">
        <h3 class="editor-title">自定义路由</h3>
        <el-text type="info" size="small">按顺序匹配，先命中先生效；未命中走默认上游</el-text>
      </div>
      <el-button type="primary" :icon="Plus" @click="addRule">添加路径规则</el-button>
    </div>

    <div class="path-rules-list">
      <el-card
        v-for="(rule, index) in pathRules"
        :key="rule.id ?? `new-${index}`"
        shadow="never"
        class="path-rule-card"
      >
        <!-- 组内层次(用户裁定重构):徽标+操作行 → 匹配行 → 自定义上游开关行 → 缩进上游表格 -->
        <div class="path-rule-head">
          <span class="path-rule-order">规则 {{ index + 1 }}</span>
          <div class="path-rule-actions">
            <el-tooltip content="上移" placement="top">
              <el-button :icon="ArrowUp" size="small" plain :disabled="index === 0" aria-label="上移路径规则" @click="moveRule(index, -1)" />
            </el-tooltip>
            <el-tooltip content="下移" placement="top">
              <el-button :icon="ArrowDown" size="small" plain :disabled="index === pathRules.length - 1" aria-label="下移路径规则" @click="moveRule(index, 1)" />
            </el-tooltip>
            <el-tooltip content="删除" placement="top">
              <el-button :icon="Delete" size="small" type="danger" plain aria-label="删除路径规则" @click="removeRule(index)" />
            </el-tooltip>
          </div>
        </div>

        <!-- 匹配行:三字段同一基线;行内标签与向导 el-form-item label 同源样式 -->
        <div class="path-rule-match-row">
          <label class="rule-field match-type-field">
            <span class="rule-field-label">匹配方式</span>
            <el-select v-model="rule.match_type" class="match-type-select" size="small" aria-label="匹配方式">
              <el-option label="前缀匹配" value="prefix" />
              <el-option label="精确匹配" value="exact" />
            </el-select>
          </label>

          <label class="rule-field path-field">
            <span class="rule-field-label">路径</span>
            <div class="rule-field-control">
              <el-input
                v-model="rule.path"
                size="small"
                :aria-label="`路径规则 ${index + 1} 的路径`"
                placeholder="例如：/api"
                :class="{ 'is-error-input': rowError(index) }"
              />
              <span v-if="rowError(index)" class="path-field-error">{{ rowError(index) }}</span>
              <span v-else-if="rowShadowWarning(index)" class="path-field-warning">{{ rowShadowWarning(index) }}</span>
            </div>
          </label>

          <label class="rule-field upstream-path-field">
            <span class="rule-field-label">
              上游路径
              <!-- 语义说明合并为单一 tooltip:留空语义 + 前缀/精确改写示例 -->
              <el-tooltip placement="top">
                <template #content>
                  留空=原样转发；填写后改写转发路径。前缀匹配 /api + /v1 → /api/users 变 /v1/users（剥匹配前缀后前置）；精确匹配则转发路径整体替换为该值
                </template>
                <el-icon class="field-hint-icon" aria-label="上游路径改写说明"><QuestionFilled /></el-icon>
              </el-tooltip>
            </span>
            <div class="rule-field-control">
              <el-input
                v-model="rule.upstream_path"
                size="small"
                :aria-label="`路径规则 ${index + 1} 的上游路径`"
                placeholder="留空=原样转发"
                :class="{ 'is-error-input': upstreamError(index) }"
              />
              <span v-if="upstreamError(index)" class="path-field-error">{{ upstreamError(index) }}</span>
            </div>
          </label>
        </div>

        <div class="custom-upstream-toggle">
          <span class="custom-upstream-title">使用自定义上游</span>
          <el-switch :model-value="rule.upstreams !== null" @change="toggleCustomUpstreams(rule, $event)" />
          <el-text type="info" size="small">关闭时使用规则的默认上游服务器</el-text>
        </div>

        <div v-if="rule.upstreams !== null" class="custom-upstream-editor">
          <div class="upstream-grid upstream-grid-header" aria-hidden="true">
            <span>协议</span>
            <span>地址</span>
            <span>端口</span>
            <span>权重 %</span>
            <span>操作</span>
          </div>
          <div v-for="(upstream, upstreamIndex) in rule.upstreams" :key="upstreamIndex" class="upstream-grid upstream-row">
            <label class="upstream-field">
              <span class="mobile-field-label">协议</span>
              <el-select v-model="upstream.protocol" size="small" aria-label="协议">
                <el-option value="http" label="HTTP" />
                <el-option value="https" label="HTTPS" />
              </el-select>
            </label>
            <label class="upstream-field upstream-address-field">
              <span class="mobile-field-label">地址</span>
              <el-input v-model="upstream.address" size="small" :aria-label="`路径规则 ${index + 1} 自定义上游 ${upstreamIndex + 1} 地址`" placeholder="IP 或域名" />
            </label>
            <label class="upstream-field">
              <span class="mobile-field-label">端口</span>
              <el-input-number v-model="upstream.port" size="small" :min="1" :max="65535" aria-label="端口" controls-position="right" />
            </label>
            <label class="upstream-field">
              <span class="mobile-field-label">权重</span>
              <el-input v-model.number="upstream.weight" size="small" type="number" :min="1" :max="100" aria-label="权重百分比" @change="onWeightChange(rule, upstreamIndex)">
                <template #suffix>%</template>
              </el-input>
            </label>
            <el-button :icon="Delete" type="danger" link aria-label="删除自定义上游" @click="removeUpstream(rule, upstreamIndex)" />
          </div>
          <div class="add-upstream-actions">
            <el-button class="add-upstream-button" size="small" plain :icon="Plus" :disabled="rule.upstreams.length >= MAX_UPSTREAM_ROWS" @click="addUpstream(rule)">添加上游</el-button>
            <el-text v-if="rule.upstreams.length >= MAX_UPSTREAM_ROWS" type="info" size="small">最多添加 {{ MAX_UPSTREAM_ROWS }} 个上游</el-text>
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ArrowDown, ArrowUp, Delete, Plus, QuestionFilled } from '@element-plus/icons-vue'
import type { PathRule, PathRuleUpstream } from '@/types'
import { MAX_UPSTREAM_ROWS, normalizeWeights, redistributeWeight } from '@/utils/upstreamWeights'
import { canonicalPathKey } from '@/utils/ruleValidation'

const pathRules = defineModel<PathRule[]>({ required: true })

const rowError = (index: number): string => {
  const rule = pathRules.value[index]
  if (!rule) return ''
  // M32：与后端/validatePathRules 同口径——前缀校验用原始串（后端 HasPrefix 在
  // TrimSpace 之前），查重与跨类型遮蔽互查用 canonicalPathKey 归一。
  if (rule.path !== '' && !rule.path.startsWith('/')) return '必须以 / 开头'
  if (/[*?{}]/.test(rule.path)) return '不能包含 * ? { } 通配字符'
  if (rule.path.trim() === '') return ''
  const canonical = canonicalPathKey(rule.match_type, rule.path)
  const dupIndex = pathRules.value.findIndex((other, otherIndex) =>
    otherIndex !== index && other.path.trim() !== '' && canonicalPathKey(other.match_type, other.path) === canonical)
  if (dupIndex >= 0) {
    const other = pathRules.value[dupIndex]
    if (!other) return ''
    return other.match_type === rule.match_type
      ? `与规则 ${dupIndex + 1} 重复`
      : `与规则 ${dupIndex + 1} 同路径前缀+精确互相遮蔽`
  }
  return ''
}

// LB41-6(第 41 轮,P5):前序 prefix 规则遮蔽提示——后端有意放行(测试钉住),
// 仅 UI 非阻断警告。判定口径与 services/caddy.go pathMatcherSpecs + terminal
// 路由一致:prefix 渲染 [root, root/*] 双 matcher(root=剥尾 / 与 *,剥空=
// /* 全匹配),路由按 sort_order 稳定排序、先命中即终结,故前序 prefix P 遮蔽
// 后序规则 Q 当且仅当 canonical(Q)===root(P) 或以 root(P)+"/" 开头。
const shadowedByIndex = (index: number): number => {
  const rule = pathRules.value[index]
  if (!rule) return -1
  // 非法/空路径由 rowError 负责,不参与遮蔽判定(避免提示噪音)
  if (rule.path !== '' && !rule.path.startsWith('/')) return -1
  if (/[*?{}]/.test(rule.path)) return -1
  if (rule.path.trim() === '') return -1
  const canonical = canonicalPathKey(rule.match_type, rule.path)
  for (let priorIndex = 0; priorIndex < index; priorIndex++) {
    const prior = pathRules.value[priorIndex]
    if (!prior || prior.match_type !== 'prefix') continue
    if (prior.path.trim() === '' || !prior.path.startsWith('/') || /[*?{}]/.test(prior.path)) continue
    const root = canonicalPathKey('prefix', prior.path)
    if (root === '/' || canonical === root || canonical.startsWith(`${root}/`)) return priorIndex
  }
  return -1
}

const rowShadowWarning = (index: number): string => {
  const priorIndex = shadowedByIndex(index)
  if (priorIndex < 0) return ''
  const prior = pathRules.value[priorIndex]
  return `被前序前缀规则 ${priorIndex + 1}（${prior?.path.trim() ?? ''}）遮蔽，不会生效`
}

const normalizeOrder = (): void => {
  pathRules.value.forEach((rule, index) => { rule.sort_order = index })
}

// 上游路径改写：与后端 validateRuleFeatures 同口径——非空须以 / 开头且
// 不含空格 ? #（query/fragment 不允许）；空串=原样转发。返回空串即无错误。
const upstreamError = (index: number): string => {
  const rule = pathRules.value[index]
  if (!rule || !rule.upstream_path) return ''
  if (!rule.upstream_path.startsWith('/')) return '必须以 / 开头'
  if (/[\s?#]/.test(rule.upstream_path)) return '不能包含空格 ? # 字符'
  return ''
}

const addRule = (): void => {
  pathRules.value.push({ match_type: 'prefix', path: '/', upstream_path: '', sort_order: pathRules.value.length, upstreams: null })
}

const removeRule = (index: number): void => {
  pathRules.value.splice(index, 1)
  normalizeOrder()
}

const moveRule = (index: number, direction: -1 | 1): void => {
  const targetIndex = index + direction
  if (targetIndex < 0 || targetIndex >= pathRules.value.length) return
  const current = pathRules.value[index]
  const target = pathRules.value[targetIndex]
  if (!current || !target) return
  pathRules.value.splice(index, 1, target)
  pathRules.value.splice(targetIndex, 1, current)
  normalizeOrder()
}

const defaultUpstream = (): PathRuleUpstream => ({ protocol: 'http', address: '', port: 80, weight: 100 })

const toggleCustomUpstreams = (rule: PathRule, enabled: string | number | boolean): void => {
  rule.upstreams = Boolean(enabled) ? [defaultUpstream()] : null
}

const addUpstream = (rule: PathRule): void => {
  const upstreams = rule.upstreams
  if (!upstreams || upstreams.length >= MAX_UPSTREAM_ROWS) return
  const upstream = defaultUpstream()
  upstream.weight = 1
  upstreams.push(upstream)
  redistributeWeight(upstreams, upstreams.length - 1)
}

const removeUpstream = (rule: PathRule, index: number): void => {
  const upstreams = rule.upstreams
  if (!upstreams) return
  upstreams.splice(index, 1)
  normalizeWeights(upstreams)
}

const onWeightChange = (rule: PathRule, index: number): void => {
  if (rule.upstreams) redistributeWeight(rule.upstreams, index)
}
</script>

<style scoped>
.path-rules-editor { display: flex; flex-direction: column; gap: 16px; padding: 0 20px; }
.editor-section-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.editor-heading-copy { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.editor-title { margin: 0; color: var(--text-primary); font-size: 14px; font-weight: 600; }
.path-rules-list { display: flex; flex-direction: column; gap: 12px; }
.path-rule-card :deep(.el-card__body) { padding: 12px 14px; }
/* 层次一：徽标 + 行内操作，动作列固定右上不随字段挤压 */
.path-rule-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.path-rule-order { padding: 4px 8px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-secondary); color: var(--text-secondary); font-size: 12px; font-weight: 600; white-space: nowrap; }
/* 匹配行：三字段同一基线，start 对齐——校验文案只在字段下方出现，不再推移输入框 */
.path-rule-match-row { display: grid; grid-template-columns: auto minmax(0, 1fr) minmax(0, 1fr); align-items: start; gap: 12px; }
/* flex-start：control 含 18px 预留带高于 input，center 会让标签相对输入行上浮；
   顶对齐后 24px 标签与首行 24px 输入框（size=small，2026-09-25 用户裁定紧凑化）中线恒对齐 */
.rule-field { display: flex; min-width: 0; align-items: flex-start; gap: 8px; }
.rule-field-label { display: inline-flex; align-items: center; flex-shrink: 0; gap: 4px; height: 24px; color: var(--el-text-color-regular); font-size: 13px; }
.match-type-select { width: 128px; }
/* 报错间距恒定预留（2026-09-21 用户裁定）：错误/提示文案绝对定位于字段下方预留带内,
   出现与否不改变任何兄弟区块位置,三字段基线对齐恒定 */
.rule-field-control { position: relative; display: flex; min-width: 0; flex: 1; flex-direction: column; margin-bottom: 18px; }
.field-hint-icon { color: var(--el-text-color-placeholder); cursor: help; }
.path-rule-actions { display: flex; align-items: center; gap: 4px; }
.path-rule-actions :deep(.el-button + .el-button) { margin-left: 0; }
/* 层次二/三：开关行单句说明 + 满宽次级卡片（左右贴齐外层卡片内容缘，双侧同 padding），行距统一 12px */
.custom-upstream-title { color: var(--el-text-color-regular); font-size: 13px; }
.custom-upstream-editor { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; padding: 10px 12px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-secondary); }
.upstream-grid { display: grid; grid-template-columns: minmax(0, 0.45fr) minmax(0, 1fr) minmax(0, 0.4fr) minmax(0, 0.4fr) auto; align-items: center; gap: 8px; }
.upstream-grid-header { color: var(--text-secondary); font-size: 12px; font-weight: 500; }
.upstream-field { display: flex; min-width: 0; flex-direction: column; gap: 4px; }
.upstream-field :deep(.el-input-number) { width: 100%; }
.mobile-field-label { display: none; color: var(--text-regular); font-size: 13px; font-weight: 500; }
.add-upstream-button { align-self: flex-start; }
.add-upstream-actions { display: flex; align-items: center; gap: 8px; }

@media (max-width: 767px) {
  .path-rules-editor { padding: 0; }
  .editor-section-header { align-items: flex-start; flex-direction: column; }
  .path-rule-match-row { grid-template-columns: 1fr; }
  .match-type-select { width: 100%; }
  .upstream-grid-header { display: none; }
  .upstream-row { grid-template-columns: minmax(0, 0.8fr) minmax(0, 1.2fr); align-items: end; padding-top: 8px; border-top: 1px solid var(--border); }
  .upstream-row:first-of-type { padding-top: 0; border-top: 0; }
  .mobile-field-label { display: inline; }
  .upstream-row > .el-button { justify-self: end; }
}
/* 校验提示：绝对定位于字段下方预留带（18px），不挤推兄弟区块（对齐 EP 表单错误态度量 12px/行高 1） */
.path-field-error {
  position: absolute;
  top: calc(100% + 2px);
  left: 0;
  white-space: nowrap;
  font-size: 12px;
  line-height: 1;
  color: var(--el-color-danger);
}
.path-field-warning {
  position: absolute;
  top: calc(100% + 2px);
  left: 0;
  white-space: nowrap;
  font-size: 12px;
  line-height: 1;
  color: var(--el-color-warning);
}
.is-error-input :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--el-color-danger) inset;
}
</style>
