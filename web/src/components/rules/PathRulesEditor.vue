<template>
  <div class="path-rules-editor">
    <div class="editor-section-header">
      <DialogSectionHeader title="自定义路由" description="按顺序匹配，先命中先生效；未命中走默认上游" />
      <el-button type="primary" size="small" :icon="Plus" @click="addRule">添加路径规则</el-button>
    </div>

    <div class="path-rules-list">
      <el-card
        v-for="(rule, index) in pathRules"
        :key="rule.id ?? `new-${index}`"
        shadow="never"
        class="path-rule-card dialog-panel dialog-panel--flush"
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
                :class="{ 'is-error-input': rowDiagnostics[index]?.pathError }"
              />
              <span v-if="rowDiagnostics[index]?.pathError" class="path-field-error">{{ rowDiagnostics[index]?.pathError }}</span>
              <span v-else-if="rowDiagnostics[index]?.shadow" class="path-field-warning">{{ rowDiagnostics[index]?.shadow }}</span>
            </div>
          </label>

          <label v-if="isForwardResponseMode(rule)" class="rule-field upstream-path-field">
            <span class="rule-field-label">
              上游路径
              <!-- 语义说明合并为单一 tooltip:留空语义 + 前缀/精确改写示例 -->
              <FieldHelpIcon content="留空=原样转发；填写后改写转发路径。前缀匹配 /api + /v1 → /api/users 变 /v1/users（剥匹配前缀后前置）；精确匹配则转发路径整体替换为该值" />
            </span>
            <div class="rule-field-control">
              <el-input
                v-model="rule.upstream_path"
                size="small"
                :aria-label="`路径规则 ${index + 1} 的上游路径`"
                placeholder="留空=原样转发"
                :class="{ 'is-error-input': rowDiagnostics[index]?.upstreamError }"
              />
              <span v-if="rowDiagnostics[index]?.upstreamError" class="path-field-error">{{ rowDiagnostics[index]?.upstreamError }}</span>
            </div>
          </label>
        </div>

        <!-- 响应方式行（2026-10-10 用户裁定）：转发上游（默认）/直接返回/301 跳转 -->
        <div class="rule-field path-rule-mode-row">
          <span class="rule-field-label">响应方式</span>
          <el-select v-model="rule.response_mode" size="small" style="width: 160px;" aria-label="响应方式" @change="applyResponseMode(rule)">
            <!-- forward 为 UI 哨兵（el-select 空串选项不显示标签）——提交归一 '' -->
            <el-option label="转发上游（默认）" value="forward" />
            <el-option label="直接返回" value="static" />
            <el-option label="301 跳转" value="redirect" />
          </el-select>
          <span class="form-tip-inline" v-if="isForwardResponseMode(rule)">按路径转发到上游</span>
          <span class="form-tip-inline" v-else-if="rule.response_mode === 'static'">不访问上游，直接返回指定状态码与内容（该路径不经安全链：信任/IP 访问控制/限流/WAF 不生效）</span>
          <span class="form-tip-inline" v-else>不访问上游，301 永久跳转到目标地址（该路径不经安全链：信任/IP 访问控制/限流/WAF 不生效）</span>
        </div>

        <!-- 直接返回字段行 -->
        <div v-if="rule.response_mode === 'static'" class="path-rule-response-row">
          <label class="rule-field">
            <span class="rule-field-label">状态码</span>
            <!-- 标准全称显示（2026-10-10 用户裁定）：值仍为数字状态码 -->
            <el-select v-model="rule.response_status" size="small" style="width: 210px;" aria-label="状态码">
              <el-option v-for="code in STATIC_RESPONSE_STATUSES" :key="code" :label="`${code} ${STATIC_RESPONSE_STATUS_REASONS[code]}`" :value="code" />
            </el-select>
          </label>
          <label class="rule-field">
            <span class="rule-field-label">格式</span>
            <el-select v-model="rule.response_content_type" size="small" style="width: 130px;" aria-label="响应格式">
              <el-option label="纯文本" value="text/plain" />
              <el-option label="JSON" value="application/json" />
              <el-option label="HTML" value="text/html" />
            </el-select>
          </label>
          <label class="rule-field" style="flex: 1;">
            <span class="rule-field-label">内容</span>
            <div class="rule-field-control">
              <el-input v-model="rule.response_body" size="small" maxlength="64" show-word-limit placeholder="不超过 64 个字符，可留空" :aria-label="`路径规则 ${index + 1} 的响应内容`" />
            </div>
          </label>
        </div>

        <!-- 301 跳转字段行 -->
        <div v-if="rule.response_mode === 'redirect'" class="path-rule-response-row">
          <label class="rule-field" style="flex: 1;">
            <span class="rule-field-label">跳转地址</span>
            <div class="rule-field-control">
              <el-input v-model="rule.redirect_to" size="small" placeholder="https://example.com/new 或 /new/" :aria-label="`路径规则 ${index + 1} 的跳转地址`" :class="{ 'is-error-input': rowDiagnostics[index]?.responseError }" />
              <span v-if="rowDiagnostics[index]?.responseError" class="path-field-error">{{ rowDiagnostics[index]?.responseError }}</span>
            </div>
          </label>
        </div>

        <div v-if="isForwardResponseMode(rule)" class="custom-upstream-toggle">
          <span class="custom-upstream-title">使用自定义上游</span>
          <el-switch :model-value="rule.upstreams !== null" @change="toggleCustomUpstreams(rule, $event)" />
          <span class="form-tip-inline">关闭时使用规则的默认上游服务器</span>
        </div>

        <div v-if="rule.upstreams !== null" class="custom-upstream-editor dialog-panel">
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
            <label class="upstream-field">
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
            <el-text v-if="rule.upstreams.length > MAX_UPSTREAM_ROWS" type="warning" size="small">已有 {{ rule.upstreams.length }} 个上游（超过编辑器 {{ MAX_UPSTREAM_ROWS }} 行上限）：权重仍可调整且不再被清零，保存前请删至 {{ MAX_UPSTREAM_ROWS }} 个以内，或通过 API 维护</el-text>
            <el-text v-else-if="rule.upstreams.length >= MAX_UPSTREAM_ROWS" type="info" size="small">最多添加 {{ MAX_UPSTREAM_ROWS }} 个上游</el-text>
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ArrowDown, ArrowUp, Delete, Plus } from '@element-plus/icons-vue'
import FieldHelpIcon from '@/components/common/FieldHelpIcon.vue'
import DialogSectionHeader from '@/components/DialogSectionHeader.vue'
import type { PathRule, PathRuleUpstream } from '@/types'
import { MAX_UPSTREAM_ROWS, normalizeWeights, redistributeWeight } from '@/utils/upstreamWeights'
import { STATIC_RESPONSE_STATUSES, STATIC_RESPONSE_STATUS_REASONS, upstreamPathRuleError } from '@/utils/ruleValidation'
import {
  applyResponseMode,
  isForwardResponseMode,
  pathRuleResponseError,
  pathRuleRowError,
  pathRuleShadowWarning,
} from '@/utils/pathRulesEditor'

const pathRules = defineModel<PathRule[]>({ required: true })

const normalizeOrder = (): void => {
  pathRules.value.forEach((rule, index) => { rule.sort_order = index })
}

// 上游路径改写：与后端 validateRuleFeatures 同口径——非空须以 / 开头且
// 不含空格 ? #（query/fragment 不允许）；空串=原样转发。判据单源在
// utils/ruleValidation.upstreamPathRuleError。返回空串即无错误。
const upstreamError = (index: number): string => {
  const rule = pathRules.value[index]
  if (!rule) return ''
  return upstreamPathRuleError(rule.upstream_path ?? '') ?? ''
}

// 每轮响应式求值只为每行计算一次诊断；模板多属性读取共享结果，
// 不再为同一行重复执行全表重复/遮蔽扫描。
const rowDiagnostics = computed(() => pathRules.value.map((_, index) => ({
  pathError: pathRuleRowError(pathRules.value, index),
  shadow: pathRuleShadowWarning(pathRules.value, index),
  upstreamError: upstreamError(index),
  responseError: pathRuleResponseError(pathRules.value[index]),
})))

const addRule = (): void => {
  pathRules.value.push({ match_type: 'prefix', path: '/', upstream_path: '', sort_order: pathRules.value.length, upstreams: null, response_mode: 'forward', response_status: 200, response_body: '', response_content_type: '', redirect_to: '' })
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
.path-rules-editor { display: flex; flex-direction: column; gap: 6px; padding: 0 20px; }
.editor-section-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.path-rules-list { display: flex; flex-direction: column; }
.path-rule-card :deep(.el-card__body) { padding: 12px; }
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
.path-rule-actions { display: flex; align-items: center; gap: 4px; }
.path-rule-actions :deep(.el-button + .el-button) { margin-left: 0; }
/* 响应方式行 + 直接返回/301 跳转字段行（2026-10-10） */
.path-rule-mode-row { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
.path-rule-response-row { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px; }
/* 层次二/三：开关行单句说明 + 满宽次级卡片（左右贴齐外层卡片内容缘，双侧同 padding），行距统一 12px */
.custom-upstream-toggle { display: flex; align-items: center; gap: 8px; min-height: 24px; }
.custom-upstream-title { color: var(--el-text-color-regular); font-size: 13px; }
.custom-upstream-editor { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }
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
