<template>
  <div class="basic-stack">
    <el-card class="settings-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><Setting /></el-icon>
            <span>基础设置</span>
          </div>
        </div>
      </template>
        <el-form :model="settings" label-width="120px" class="settings-form" :disabled="isReadOnly">
          <el-form-item label="日志级别">
            <el-select v-model="settings.log_level" style="width: 140px">
              <el-option label="Debug" value="debug" />
              <el-option label="Info" value="info" />
              <el-option label="Warning" value="warn" />
              <el-option label="Error" value="error" />
            </el-select>
            <el-text type="info" size="small" class="tip-inline">控制 Lazy Balancer 自身日志详细程度</el-text>
          </el-form-item>
          <el-form-item label="任务日志大小">
            <el-input-number v-model="settings.cert_job_log_size_mb" :min="1" :max="1024" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">MB，证书/CRS/IP 库轮转阈值（建议 10-50）</el-text>
          </el-form-item>
          <el-form-item label="审计日志大小">
          <el-input-number v-model="settings.audit_log_size_mb" :min="1" :max="512" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">MB，WAF 审计日志轮转阈值（建议 10-100）</el-text>
          </el-form-item>
          <el-form-item label="运行日志大小">
            <el-input-number v-model="settings.runtime_log_size_mb" :min="1" :max="1024" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">MB，轮转阈值（建议 50-200）</el-text>
          </el-form-item>
          <el-form-item label="日志保留">
            <el-input-number v-model="settings.audit_retention_months" :min="1" :max="12" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">个月，操作/运行/安全事件日志超期清理（建议 3-6）</el-text>
          </el-form-item>
          <el-form-item label="登录过期">
            <el-input-number v-model="settings.jwt_expire_minutes" :min="1" :max="1440" controls-position="right" style="width: 120px;" />
            <el-text type="info" size="small" class="tip-inline">分钟，登录令牌有效期（默认 20）</el-text>
          </el-form-item>
          <el-form-item label="时区">
            <el-select v-model="settings.timezone" filterable class="compact-select">
              <el-option label="Asia/Shanghai (UTC+8)" value="Asia/Shanghai" />
              <el-option label="Asia/Hong_Kong (UTC+8)" value="Asia/Hong_Kong" />
              <el-option label="Asia/Tokyo (UTC+9)" value="Asia/Tokyo" />
              <el-option label="Asia/Singapore (UTC+8)" value="Asia/Singapore" />
              <el-option label="Asia/Seoul (UTC+9)" value="Asia/Seoul" />
              <el-option label="Asia/Bangkok (UTC+7)" value="Asia/Bangkok" />
              <el-option label="Asia/Kolkata (UTC+5:30)" value="Asia/Kolkata" />
              <el-option label="Asia/Dubai (UTC+4)" value="Asia/Dubai" />
              <el-option label="Europe/London (UTC+0，夏令时 UTC+1)" value="Europe/London" />
              <el-option label="Europe/Paris (UTC+1，夏令时 UTC+2)" value="Europe/Paris" />
              <el-option label="Europe/Berlin (UTC+1，夏令时 UTC+2)" value="Europe/Berlin" />
              <el-option label="Europe/Moscow (UTC+3)" value="Europe/Moscow" />
              <el-option label="America/New_York (UTC-5，夏令时 UTC-4)" value="America/New_York" />
              <el-option label="America/Chicago (UTC-6，夏令时 UTC-5)" value="America/Chicago" />
              <el-option label="America/Denver (UTC-7，夏令时 UTC-6)" value="America/Denver" />
              <el-option label="America/Los_Angeles (UTC-8，夏令时 UTC-7)" value="America/Los_Angeles" />
              <el-option label="America/Sao_Paulo (UTC-3)" value="America/Sao_Paulo" />
              <el-option label="Australia/Sydney (UTC+10，夏令时 UTC+11)" value="Australia/Sydney" />
              <el-option label="UTC" value="UTC" />
            </el-select>
            <el-text type="info" size="small" class="tip-block">影响日志时间戳与证书时间；标注夏令时的时区会随夏令时自动偏移；仅 Caddy 日志需重启服务生效</el-text>
          </el-form-item>
          <el-form-item label="GitHub 加速">
            <el-select v-model="githubProxyUrl" style="width: 160px">
              <el-option
                v-for="option in githubProxyOptions"
                :key="option.value"
                :label="option.label"
                :value="option.value"
              />
            </el-select>
            <el-text type="info" size="small" class="tip-inline">CRS 规则库与 IP2Region 的下载代理</el-text>
          </el-form-item>
          <el-form-item label="写操作验证">
            <el-switch v-model="settings.mfa_write_guard" />
            <el-text type="info" size="small" class="tip-inline">写操作需 1 分钟内的 MFA 验证</el-text>
            <el-link type="info" underline="never" size="small" class="tip-link" style="margin-left: 6px" @click="mfaScopeVisible = true">支持的操作</el-link>
          </el-form-item>
          <el-form-item label="登录失败锁定">
            <el-switch v-model="settings.mfa_lockout_enabled" />
            <el-text type="info" size="small" class="tip-inline">密码或验证码失败 5 次锁 10 分钟（关闭则不锁定）</el-text>
          </el-form-item>
          <el-form-item label="强制 HTTPS">
            <el-switch v-model="adminTls.enabled" @change="onAdminTlsToggle" />
            <el-button v-if="adminTls.enabled" size="small" style="margin-left: 8px;" @click="openAdminTlsDialog">配置证书</el-button>
            <el-text v-if="adminTlsDirty" type="warning" size="small" class="tip-inline">已暂存，点击下方保存后生效</el-text>
            <el-text v-else type="info" size="small" class="tip-inline">启用后 :8000 仅经 HTTPS 访问，需重启服务生效</el-text>
          </el-form-item>
          <el-form-item label="运行日志">
            <el-button size="small" :icon="View" @click="openAppLogDialog">查看日志</el-button>
            <el-text type="info" size="small" class="tip-inline">查看 Lazy Balancer 自身运行日志</el-text>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" :disabled="isReadOnly" @click="handleSave">
              <el-icon><Check /></el-icon>
              <span class="btn-text">保存</span>
            </el-button>
          </el-form-item>
        </el-form>
    </el-card>

    <el-card class="info-card">
      <template #header>
        <div class="card-header">
          <div class="card-title">
            <el-icon><InfoFilled /></el-icon>
            <span>系统信息</span>
          </div>
        </div>
      </template>
      <div class="info-list">
        <div class="info-item">
          <span class="info-label">版本</span>
          <el-tag type="info" size="small">{{ appVersion }}</el-tag>
        </div>
        <div class="info-item">
          <span class="info-label">运行模式</span>
          <el-tag :type="authStore.nodeMode === 'master' ? 'success' : 'warning'" size="small">
            {{ authStore.nodeMode === 'master' ? '主节点' : '从节点' }}
          </el-tag>
        </div>
        <div class="info-item">
          <span class="info-label">配置备份</span>
          <div class="backup-actions">
            <el-button size="small" :icon="Download" :disabled="backupDisabled" :loading="exporting" @click="openExportDialog">导出</el-button>
            <el-button size="small" :icon="Upload" :disabled="backupDisabled" @click="triggerImport">导入</el-button>
            <el-button size="small" :icon="Timer" :disabled="backupDisabled" @click="openAutoBackupDialog">自动备份</el-button>
          </div>
        </div>

        <div class="info-item">
          <span class="info-label">重启服务</span>
          <el-button size="small" type="danger" plain :disabled="isReadOnly" :loading="restarting" @click="handleRestart">重启</el-button>
        </div>
        <el-text type="info" size="small" class="backup-tip">备份包含全部配置、规则、用户、密钥与证书任务（含凭证与私钥，请加密保管）；导入将覆盖当前配置，仅主节点可用</el-text>
      </div>
    </el-card>

    <el-dialog v-model="adminTlsDialogVisible" title="HTTPS 证书配置" width="min(520px, 92vw)" destroy-on-close @closed="onAdminTlsDialogClose">
      <el-form label-width="110px">
        <!-- 自管标签行(ClusterModeCard 范式):el-radio-group 会把组容器 DIV id
             注册为表单输入 id,el-form-item label for 随之指向 DIV——Firefox 报
             「Incorrect use of <label for>」;改 role=group+aria-label 语义等价 -->
        <div class="form-radio-row" role="group" aria-label="证书来源">
          <span class="form-radio-row-label">证书来源</span>
          <div class="form-radio-row-content">
            <el-radio-group v-model="adminTlsForm.mode">
              <el-radio value="selfsigned">本地自签名证书</el-radio>
              <el-radio value="upload">上传证书</el-radio>
            </el-radio-group>
          </div>
        </div>
        <template v-if="adminTlsForm.mode === 'upload'">
          <el-form-item label="证书文件">
            <input type="file" accept=".crt,.pem,.cer" @change="(e) => onTlsFile(e, 'cert')" />
          </el-form-item>
          <el-form-item label="私钥文件">
            <input type="file" accept=".key,.pem" @change="(e) => onTlsFile(e, 'key')" />
          </el-form-item>
          <el-form-item v-if="adminTlsForm.inspecting" label=" ">
            <el-text type="info" size="small">解析中…</el-text>
          </el-form-item>
          <template v-if="adminTlsForm.certInfo">
            <el-form-item label="证书信息">
              <div class="tls-cert-info">
                <div>域名：{{ adminTlsForm.certInfo.domain }}</div>
                <div>签发者：{{ adminTlsForm.certInfo.issuer }}</div>
                <div>过期时间：{{ adminTlsForm.certInfo.not_after }}（剩余 {{ adminTlsForm.certInfo.days_left }} 天）</div>
              </div>
            </el-form-item>
          </template>
        </template>
        <el-form-item v-if="adminTlsForm.mode === 'selfsigned'" label="说明">
          <el-text type="info" size="small">自动生成自签名证书，浏览器会提示不受信任；集群同步会自动跳过自签验证</el-text>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="adminTlsDialogVisible = false">取消</el-button>
        <el-button type="primary" :disabled="adminTlsForm.mode === 'upload' && (!adminTlsForm.certInfo || adminTlsForm.certInfo.days_left <= 0)" @click="confirmAdminTls">确定</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="appLogVisible" title="Lazy Balancer 运行日志" width="min(1100px, 94vw)" destroy-on-close @opened="onAppLogOpened" @closed="onAppLogClosed">
      <div class="log-toolbar">
        <el-switch v-model="appLogAutoRefresh" active-text="自动刷新" />
        <el-button size="small" :loading="appLogLoading" @click="fetchAppLogs">刷新</el-button>
      </div>
      <div ref="appLogContainer" class="log-viewer"><pre>{{ appLogContent || '暂无日志' }}</pre></div>
      <template #footer><el-button @click="appLogVisible = false">关闭</el-button></template>
    </el-dialog>

    <el-dialog v-model="importDialogVisible" width="min(720px, 92vw)" :close-on-click-modal="false" class="backup-dialog" @close="onImportDialogClosed">
      <template #header>
        <div class="backup-dialog-header">
          <el-icon class="backup-dialog-icon"><Upload /></el-icon>
          <div>
            <div class="backup-dialog-title">导入配置备份</div>
            <div class="backup-dialog-sub">选择备份文件与要导入的分类</div>
          </div>
        </div>
      </template>
      <div class="import-picker">
        <el-button :icon="Upload" @click="chooseImportFile">选择备份文件</el-button>
        <span v-if="importFileName" class="import-filename">{{ importFileName }}</span>
        <span v-else class="import-hint">支持 V2 完整备份与 V1（nginx 版）备份</span>
      </div>
      <input ref="importInput" type="file" accept="application/json,.json,.bak,.lbbak,application/gzip" class="import-input" @change="handleImportFile" />

      <div v-if="importValidating" v-loading="true" class="import-validating">正在校验备份文件...</div>

      <template v-if="importValidation && !importValidating">
        <el-alert v-if="!importValidation.valid" :title="importValidation.error || '备份文件校验失败'" type="error" :closable="false" show-icon class="import-alert" />
        <template v-else>
          <div class="import-result">
  <div class="import-sections">
              <div class="import-sections-label">导入分类（未选分类保持现状）</div>
              <div class="section-chips">
                <button
                  v-for="sec in BACKUP_SECTIONS" :key="sec.key"
                  type="button" class="section-chip"
                  :class="{ 'is-active': importSections.includes(sec.key), 'is-disabled': importValidation.type === 'v1' && sec.key !== 'rules' }"
                  @click="toggleImportSection(sec.key)"
                >{{ sec.label }}</button>
              </div>
              <el-text v-if="importValidation.type === 'v1'" type="info" size="small" class="import-v1-hint">V1 备份仅支持负载均衡规则导入</el-text>
            </div>
            <el-tag :type="importValidation.type === 'v1' ? 'warning' : 'success'" size="small">
              {{ importValidation.type === 'v1' ? 'V1 兼容导入' : 'V2 完整备份' }}
            </el-tag>
            <div class="import-summary">
              <span v-for="(count, key) in importValidation.summary" :key="key" class="import-summary-chip" :class="{ 'is-zero': !count }">
                {{ summaryLabels[key] || key }}·{{ count }}
              </span>
            </div>
            <!-- C2-41-2:勾选「安全防护」但备份无规则库文件时预览提示(后端兜底
                 跳过规则库版本记录表并在导入结果 warnings 中说明) -->
            <el-text
              v-if="importValidation.has_waf_files === false && importSections.includes('security')"
              type="warning" size="small" class="import-waf-hint"
            >该备份不含规则库文件，导入「安全防护」将跳过规则库版本记录</el-text>
            <ul v-if="importValidation.warnings?.length" class="import-warnings">
              <li v-for="(warning, index) in importValidation.warnings" :key="index">{{ warning }}</li>
            </ul>
            <ul v-if="importValidation.disabled_conflicts.length" class="import-warnings import-conflicts">
              <li v-for="conflict in importValidation.disabled_conflicts" :key="conflict.caddy_id || conflict.name">
                {{ formatImportConflict(conflict) }}
              </li>
            </ul>
            <el-alert
              v-if="importValidation.type !== 'v1'"
              :title="importSections.length === BACKUP_SECTIONS.length ? '导入将覆盖当前全部配置（规则、用户、密钥、证书任务）' : `将仅覆盖所选分类：${importSections.map((k) => BACKUP_SECTIONS.find((s) => s.key === k)?.label || k).join('、')}，未选分类保持现状`"
              type="warning"
              :closable="false"
              show-icon
              class="import-alert"
            />
            <el-alert
              v-else
              title="仅导入负载均衡规则，其他数据不受影响"
              type="info"
              :closable="false"
              show-icon
              class="import-alert"
            />
          </div>
        </template>
      </template>

      <template #footer>
        <el-button @click="importDialogVisible = false">取消</el-button>
        <el-button type="primary" :disabled="!importValidation?.valid" :loading="importing" @click="confirmImport">确认导入</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="exportDialogVisible" width="min(720px, 92vw)" :close-on-click-modal="false" class="backup-dialog">
      <template #header>
        <div class="backup-dialog-header">
          <el-icon class="backup-dialog-icon"><Download /></el-icon>
          <div>
            <div class="backup-dialog-title">导出配置备份</div>
            <div class="backup-dialog-sub">选择要导出的配置分类</div>
          </div>
        </div>
      </template>
      <div class="section-chips">
        <button
          v-for="sec in BACKUP_SECTIONS" :key="sec.key"
          type="button" class="section-chip" :class="{ 'is-active': exportSections.includes(sec.key) }"
          @click="toggleExportSection(sec.key)"
        >{{ sec.label }}</button>
      </div>
      <div class="backup-dialog-actions">
        <el-button text size="small" @click="exportSections = []">全不选</el-button>
        <el-button text size="small" @click="exportSections = BACKUP_SECTIONS.map((s) => s.key)">全选</el-button>
      </div>
      <el-alert type="warning" :closable="false" show-icon class="mt8"
        title="导出为 .lbbak 备份包（勾选「安全防护」时含 CRS/IP2Region 规则库文件）；包含凭证与证书材料，请加密保管" />
      <template #footer>
        <el-button @click="exportDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="exporting" :disabled="exportSections.length === 0" @click="exportBackup">
          确认导出{{ exportSections.length ? `（${exportSections.length}/${BACKUP_SECTIONS.length}）` : '' }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="autoBackupVisible" width="min(760px, 94vw)" :close-on-click-modal="false" class="backup-dialog" destroy-on-close @opened="onAutoBackupOpened">
      <template #header>
        <div class="backup-dialog-header">
          <el-icon class="backup-dialog-icon"><Timer /></el-icon>
          <div>
            <div class="backup-dialog-title">自动备份</div>
            <div class="backup-dialog-sub">定时将配置备份到服务器 backup 目录（仅主节点）</div>
          </div>
        </div>
      </template>
      <el-form label-width="110px" class="auto-backup-form">
        <el-form-item label="启用">
          <el-switch v-model="autoBackupForm.enabled" />
          <el-text type="info" size="small" class="tip-inline">调度器仅主节点运行；主从切换后自动开始，无需重启进程</el-text>
        </el-form-item>
        <!-- 自管标签行(同上 a11y 范式):radio+select 兄弟同行,role=group 收口 -->
        <div class="form-radio-row" role="group" aria-label="频率">
          <span class="form-radio-row-label">频率</span>
          <div class="form-radio-row-content">
            <el-radio-group v-model="autoBackupForm.frequency">
              <el-radio value="daily">日</el-radio>
              <el-radio value="weekly">周</el-radio>
              <el-radio value="monthly">月</el-radio>
            </el-radio-group>
            <el-select v-if="autoBackupForm.frequency === 'weekly'" v-model="autoBackupForm.day" size="small" style="width: 110px; margin-left: 12px">
              <el-option v-for="(label, idx) in AUTO_BACKUP_WEEKDAYS" :key="label" :value="idx + 1" :label="label" />
            </el-select>
            <el-select v-else-if="autoBackupForm.frequency === 'monthly'" v-model="autoBackupForm.day" size="small" style="width: 110px; margin-left: 12px">
              <el-option v-for="d in 28" :key="d" :value="d" :label="`${d} 日`" />
            </el-select>
          </div>
        </div>
        <el-form-item label="备份时间">
          <el-time-select v-model="autoBackupForm.time" start="00:00" end="23:30" step="00:30" style="width: 120px" />
          <el-text type="info" size="small" class="tip-inline">按系统配置时区执行；停机跨槽会在下次启动补跑一次</el-text>
        </el-form-item>
        <el-form-item label="保留份数">
          <el-input-number v-model="autoBackupForm.keep" :min="1" :max="30" controls-position="right" style="width: 120px" />
          <el-text type="info" size="small" class="tip-inline">1-30 份，超出自动清理；失败记录另保留最近 20 条</el-text>
        </el-form-item>
        <el-form-item label="备份范围">
          <div class="section-chips auto-backup-chips">
            <button
              v-for="sec in BACKUP_SECTIONS" :key="sec.key"
              type="button" class="section-chip"
              :class="{ 'is-active': autoBackupSections.includes(sec.key) }"
              @click="toggleAutoBackupSection(sec.key)"
            >{{ sec.label }}</button>
          </div>
          <div class="auto-backup-chips-actions">
            <el-button size="small" plain @click="autoBackupSections = []">全不选</el-button>
            <el-button size="small" plain @click="autoBackupSections = BACKUP_SECTIONS.map((s) => s.key)">全选</el-button>
            <el-text type="info" size="small" class="auto-backup-scope-hint">至少选择一个分类（未选分类不进入备份）</el-text>
          </div>
        </el-form-item>
      </el-form>
      <div class="auto-backup-list-head">
        <el-text type="info" size="small">
          上次执行：{{ autoBackupLastRunLabel }}<template v-if="autoBackupNextRunLabel"> · 下次备份：{{ autoBackupNextRunLabel }}</template>
        </el-text>
      </div>
      <div class="auto-backup-list">
        <el-table v-loading="autoBackupLoading" :data="autoBackupRows" size="small" :max-height="320">
          <el-table-column label="备份时间" width="150">
            <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="状态" width="70">
            <template #default="{ row }">
              <el-tag :type="row.status === 'success' ? 'success' : 'danger'" size="small" effect="light">
                {{ row.status === 'success' ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="内容" min-width="200" show-overflow-tooltip>
            <template #default="{ row }">{{ autoBackupScopeSummary(row) }}</template>
          </el-table-column>
          <el-table-column label="大小" width="90">
            <template #default="{ row }">{{ formatBackupSize(row.size_bytes) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="140" align="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="downloadAutoBackup(row)">下载</el-button>
              <el-button v-if="row.status === 'success'" link type="warning" size="small" @click="restoreAutoBackup(row)">还原</el-button>
              <el-button link type="danger" size="small" @click="deleteAutoBackup(row)">删除</el-button>
            </template>
          </el-table-column>
          <template #empty><el-empty description="暂无备份" :image-size="70" /></template>
        </el-table>
      </div>
      <template #footer>
        <el-button @click="autoBackupVisible = false">取消</el-button>
        <el-button type="primary" plain :loading="autoBackupRunning" :disabled="!autoBackupSectionsValid" title="按已保存的自动备份设置执行一次备份；上方表单改动需先保存设置" @click="runAutoBackupNow">
          立即备份
        </el-button>
        <el-button type="primary" :loading="autoBackupSaving" :disabled="!autoBackupSectionsValid" @click="saveAutoBackupSettings">
          保存设置
        </el-button>
      </template>
    </el-dialog>
  </div>

  <!-- R72 十四次（用户裁决）：写操作验证「支持的操作」清单——与后端 mfaStepUpGuard
       实际覆盖面一致（全部 RESTful 写端点：POST/PUT/PATCH/DELETE，排除测试/预览/
       解析类只读 POST 与 MFA 自身端点）。 -->
  <el-dialog v-model="mfaScopeVisible" title="写操作验证支持的操作" width="640px">
    <el-text type="info" size="small" style="display: block; margin-bottom: 12px">
      开启后，以下操作需要 1 分钟内验证过 MFA（TOTP 同片不可重用，验证后 60 秒内的连续操作免重复弹码）。测试连接、预览、解析类操作不受影响。
    </el-text>
    <div class="mfa-scope-list">
      <div v-for="group in mfaScopeGroups" :key="group.title" class="mfa-scope-row">
        <div class="mfa-scope-title">{{ group.title }}</div>
        <div class="mfa-scope-items">{{ group.items.join('、') }}</div>
      </div>
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, h, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { reloadAfterRestart } from '@/utils/restart'
import { formatDate } from '@/utils/date'
import { Setting, InfoFilled, Check, View, Upload, Download, Timer } from '@element-plus/icons-vue'
import type { SystemInfo } from '@/types'

const authStore = useAuthStore()
const isReadOnly = computed(() => authStore.readOnlyReason !== null)
const backupDisabled = computed(() => isReadOnly.value || authStore.nodeMode !== 'master')
const exporting = ref(false)
const importing = ref(false)
const appVersion = ref('-')

onMounted(async () => {
  try {
    const res = await request.get<{ data: SystemInfo }>('/system/info')
    appVersion.value = res.data.version || '-'
  } catch {
    appVersion.value = '-'
  }
})

const appLogVisible = ref(false)
const appLogContent = ref('')
const appLogLoading = ref(false)
const appLogAutoRefresh = ref(true)
const appLogContainer = ref<HTMLElement | null>(null)
let appLogTimer: ReturnType<typeof setInterval> | null = null

// （R69 过度修复审查 REMOVE：appLogRequestSeq 已删——入口 loading 门 +
// appLogVisible 析取使其作为裁决条件永不为真。）
const fetchAppLogs = async (): Promise<void> => {
  // 后台标签页暂停轮询：定时器空转跳过，回到可见后的下一个 tick 立即补拉
  if (appLogLoading.value || document.hidden) return
  appLogLoading.value = true
  try {
    const res = await request.get<{ data?: { content?: string } }>('/system/logs', { silent: true })
    if (!appLogVisible.value) return
    appLogContent.value = res.data?.content || ''
    await nextTick()
    if (appLogContainer.value) appLogContainer.value.scrollTop = appLogContainer.value.scrollHeight
  } catch (error) {
    console.error('Failed to fetch app logs:', error)
  } finally {
    appLogLoading.value = false
  }
}

const stopAppLogTimer = (): void => {
  if (appLogTimer) {
    clearInterval(appLogTimer)
    appLogTimer = null
  }
}

const openAppLogDialog = (): void => {
  appLogVisible.value = true
}

const onAppLogOpened = (): void => {
  void fetchAppLogs()
  stopAppLogTimer()
  if (appLogAutoRefresh.value) appLogTimer = setInterval(() => void fetchAppLogs(), 3000)
}

const onAppLogClosed = (): void => {
  stopAppLogTimer()
  appLogLoading.value = false
  appLogContent.value = ''
}

watch(appLogAutoRefresh, (enabled) => {
  if (!appLogVisible.value) return
  stopAppLogTimer()
  if (enabled) appLogTimer = setInterval(() => void fetchAppLogs(), 3000)
})

onUnmounted(() => {
  disposed = true
  stopAppLogTimer()
  if (tlsProtocolFallbackTimer) clearTimeout(tlsProtocolFallbackTimer)
  tlsProtocolFallbackTimer = null
})

// 三分类合并(2026-09-19 用户裁定):备份分类收敛为 3 类,与集群同步节同构
// ——全局配置并入「系统数据」、规则库并入「安全防护」。默认全选。
const BACKUP_SECTIONS = [
  { key: 'users', label: '系统数据' },
  { key: 'rules', label: '负载规则' },
  { key: 'security', label: '安全防护' },
] as const

// legacy 分类键归一(与后端 normalizeBackupSectionKeys 同映射):升级前保存的
// 自动备份范围/历史备份行可能携带 global_config/waf_files,读出即归一。
const LEGACY_SECTION_ALIASES: Record<string, string> = { global_config: 'users', waf_files: 'security' }
const normalizeBackupSectionKeys = (keys: string[]): string[] => {
  const seen = new Set<string>()
  const out: string[] = []
  for (const key of keys) {
    const normalized = LEGACY_SECTION_ALIASES[key] ?? key
    if (seen.has(normalized)) continue
    seen.add(normalized)
    out.push(normalized)
  }
  return out
}
const exportSections = ref<string[]>(BACKUP_SECTIONS.map((s) => s.key))
const exportDialogVisible = ref(false)
const toggleImportSection = (key: string): void => {
  const validation = importValidation.value
  if (!validation?.valid) return
  if (validation.type === 'v1' && key !== 'rules') return
  importSections.value = importSections.value.includes(key)
    ? importSections.value.filter((k) => k !== key)
    : [...importSections.value, key]
}

const toggleExportSection = (key: string): void => {
  exportSections.value = exportSections.value.includes(key)
    ? exportSections.value.filter((k) => k !== key)
    : [...exportSections.value, key]
}
const openExportDialog = (): void => {
  if (backupDisabled.value || exporting.value) return
  exportDialogVisible.value = true
}
const exportBackup = async (): Promise<void> => {
  if (backupDisabled.value || exporting.value) return
  exporting.value = true
  try {
    // 备份含全部证书与私钥，体积可能很大，禁用 30s 默认超时
    const blob = await request.get<Blob>('/config/export', {
      responseType: 'blob', timeout: 0,
      params: { sections: exportSections.value.join(',') },
    })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `lazy-balancer-backup-${new Date().toISOString().slice(0, 10)}.lbbak`
    link.click()
    // Safari 下立即回收 objectURL 会截断下载文件，延迟 1s 再释放
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    exportDialogVisible.value = false
    mfaAwareSuccess('配置备份已导出')
  } catch {
    // 错误提示已由全局拦截器（含 Blob 错误体解析）展示
  } finally {
    exporting.value = false
  }
}

// —— 自动备份（v2.3.x）：设置/手动备份/列表/下载/还原/删除 ——
const AUTO_BACKUP_WEEKDAYS = ['周一', '周二', '周三', '周四', '周五', '周六', '周日']

interface AutoBackupRow {
  id: number
  filename: string
  created_at: string
  status: string
  size_bytes: number
  sections: string[]
  trigger_type: string
  message: string
}

interface AutoBackupSettingsResponse {
  enabled: boolean
  frequency: string
  time: string
  day: number
  keep: number
  sections: string[]
  last_run: string | null
  backups: AutoBackupRow[]
}

const autoBackupVisible = ref(false)
const autoBackupLoading = ref(false)
const autoBackupSaving = ref(false)
const autoBackupRunning = ref(false)
const autoBackupForm = ref({ enabled: false, frequency: 'daily', time: '03:00', day: 1, keep: 7 })
const autoBackupSections = ref<string[]>(BACKUP_SECTIONS.map((s) => s.key))
const autoBackupRows = ref<AutoBackupRow[]>([])
const autoBackupLastRun = ref<string | null>(null)

const autoBackupLastRunLabel = computed(() => (autoBackupLastRun.value ? formatDate(autoBackupLastRun.value) : '—'))

// 下一次备份时刻(启用态才有):镜像后端 autoBackupDueSlot 的「下一槽」语义——
// 日=当日/次日 HH:MM;周=下一个目标周几;月=当月/次月 day 日(短月收敛到月末)。
// 时区取基础设置 timezone(与调度器 CurrentLocation 同源;未保存的时区编辑即时预览)。
const autoBackupNextRunLabel = computed<string | null>(() => {
  const form = autoBackupForm.value
  if (!autoBackupVisible.value || !form.enabled) return null
  const [hh, mm] = form.time.split(':').map(Number)
  if (!Number.isFinite(hh) || !Number.isFinite(mm)) return null
  const tz = settings.value.timezone || 'Asia/Shanghai'
  try {
    // 配置时区的当前墙钟(Intl 受保护构造——非法 tz 走 catch 返回 null)
    const partsFmt = new Intl.DateTimeFormat('en-US', {
      timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false, weekday: 'short',
    })
    const parts: Record<string, string> = {}
    for (const part of partsFmt.formatToParts(new Date())) parts[part.type] = part.value
    const WD: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }
    const nowCarrier = Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day), Number(parts.hour) % 24, Number(parts.minute))
    const wallNow = new Date(nowCarrier)
    const slotCarrier = (y: number, mo: number, d: number): number => Date.UTC(y, mo - 1, d, hh, mm)
    const daysInMonth = (y: number, mo: number): number => new Date(Date.UTC(y, mo, 0)).getUTCDate()
    let candidate: number
    if (form.frequency === 'weekly') {
      const target = (form.day || 1) % 7 // 本包 1=周一…7=周日 → JS 0=周日
      const delta = (target - WD[parts.weekday ?? 'Sun'] + 7) % 7
      const targetDate = new Date(wallNow.getTime() + delta * 86400000)
      candidate = slotCarrier(targetDate.getUTCFullYear(), targetDate.getUTCMonth() + 1, targetDate.getUTCDate())
      if (candidate <= wallNow.getTime()) candidate += 7 * 86400000
    } else if (form.frequency === 'monthly') {
      const day = Math.min(Math.max(form.day || 1, 1), 28)
      const y = wallNow.getUTCFullYear()
      const mo = wallNow.getUTCMonth() + 1
      candidate = slotCarrier(y, mo, Math.min(day, daysInMonth(y, mo)))
      if (candidate <= nowCarrier) {
        const ny = mo === 12 ? y + 1 : y
        const nmo = mo === 12 ? 1 : mo + 1
        candidate = slotCarrier(ny, nmo, Math.min(day, daysInMonth(ny, nmo)))
      }
    } else {
      candidate = slotCarrier(wallNow.getUTCFullYear(), wallNow.getUTCMonth() + 1, wallNow.getUTCDate())
      if (candidate <= wallNow.getTime()) candidate += 86400000
    }
    // 墙钟 → 瞬时:用该时区在候选时刻的偏移换算(DST 边界二次收敛)
    const offsetAt = (instant: number): number => {
      const p: Record<string, string> = {}
      for (const part of partsFmt.formatToParts(new Date(instant))) p[part.type] = part.value
      return Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour) % 24, Number(p.minute)) - Math.floor(instant / 60000) * 60000
    }
    const guess = candidate - offsetAt(candidate)
    const epoch = candidate - offsetAt(guess)
    // 展示走 formatDate(配置时区)——与列表时间同口径;formatDate 契约只收
    // 字符串(Date 对象被 parseDateValue 判为非法返回空串),传 ISO 形态
    return formatDate(new Date(epoch).toISOString())
  } catch {
    return null
  }
})
// 与导出按钮同口径：范围非空(users 恒有表,不存在不可还原形态)
const autoBackupSectionsValid = computed(() => autoBackupSections.value.length > 0)

const openAutoBackupDialog = (): void => {
  if (backupDisabled.value) return
  autoBackupVisible.value = true
}

const fetchAutoBackup = async (): Promise<void> => {
  autoBackupLoading.value = true
  try {
    const res = await request.get<{ data: AutoBackupSettingsResponse }>('/settings/auto-backup', { silent: true })
    const d = res.data
    autoBackupForm.value = {
      enabled: d.enabled,
      frequency: d.frequency || 'daily',
      time: d.time || '03:00',
      day: d.day || 1,
      keep: d.keep || 7,
    }
    autoBackupSections.value = d.sections?.length ? normalizeBackupSectionKeys(d.sections) : BACKUP_SECTIONS.map((s) => s.key)
    autoBackupRows.value = d.backups || []
    autoBackupLastRun.value = d.last_run ?? null
  } catch {
    // silent：打开弹框时拉取失败保持空态，全局拦截器已提示
  } finally {
    autoBackupLoading.value = false
  }
}

const onAutoBackupOpened = (): void => {
  void fetchAutoBackup()
}

const toggleAutoBackupSection = (key: string): void => {
  autoBackupSections.value = autoBackupSections.value.includes(key)
    ? autoBackupSections.value.filter((k) => k !== key)
    : [...autoBackupSections.value, key]
}

const saveAutoBackupSettings = async (): Promise<boolean> => {
  if (!autoBackupSectionsValid.value || autoBackupSaving.value) return false
  autoBackupSaving.value = true
  try {
    await request.put('/settings/auto-backup', { ...autoBackupForm.value, sections: autoBackupSections.value })
    mfaAwareSuccess('自动备份设置已保存')
    return true
  } catch {
    // 全局拦截器已提示（含 428 MFA 弹码重试）
    return false
  } finally {
    autoBackupSaving.value = false
  }
}

// 「立即备份」只触发执行,不保存/修改设置(2026-09-20 用户裁定)——备份按
// 已保存的设置(频率/范围等)执行;弹框中未保存的表单改动对本次手动备份
// 不生效,避免每次手动备份都重写设置并产生多余的「备份设置」审计事件。
const runAutoBackupNow = async (): Promise<void> => {
  if (autoBackupRunning.value) return
  if (!autoBackupSectionsValid.value) {
    ElMessage.warning('备份范围至少需选择一个分类')
    return
  }
  autoBackupRunning.value = true
  try {
    await request.post('/auto-backup/run')
    mfaAwareSuccess('手动备份完成')
    await fetchAutoBackup()
  } catch {
    // 全局拦截器已提示
  } finally {
    autoBackupRunning.value = false
  }
}

const formatBackupSize = (bytes: number): string => {
  if (!bytes || bytes <= 0) return '-'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

const autoBackupScopeSummary = (row: AutoBackupRow): string => {
  const labels = normalizeBackupSectionKeys(row.sections || []).map((k) => BACKUP_SECTIONS.find((s) => s.key === k)?.label || k)
  const scope = labels.length > 0 ? labels.join('、') : '-'
  const trigger = row.trigger_type === 'manual' ? '手动' : '定时'
  // 「（定时）」置于内容尾部,避免黏在最后一个分类名后(2026-09-19 用户报障)
  return row.message ? `${scope} · ${row.message}（${trigger}）` : `${scope}（${trigger}）`
}

const downloadAutoBackup = async (row: AutoBackupRow): Promise<void> => {
  try {
    // 备份含证书与私钥，体积可能较大，禁用 30s 默认超时
    const blob = await request.get<Blob>(`/auto-backup/${row.id}/download`, { responseType: 'blob', timeout: 0 })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = row.filename
    link.click()
    // Safari 下立即回收 objectURL 会截断下载文件，延迟 1s 再释放
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch {
    // 全局拦截器已提示（含 Blob 错误体解析）
  }
}

const restoreAutoBackup = async (row: AutoBackupRow): Promise<void> => {
  try {
    await ElMessageBox.confirm(
      `将使用备份「${row.filename}」覆盖当前全部配置（规则、用户、API 密钥、证书任务及全部凭证），此操作不可撤销。确认还原？`,
      '还原配置',
      { type: 'warning', confirmButtonText: '确认还原', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  try {
    // 还原走导入 core(config_backup.go importConfigBackupCore),响应同样携带
    // data.warnings(操作账户替换/会话吊销/ACME 悬挂等)——与导入同口径展示
    const res = await request.post<{ message?: string; data?: { warnings?: string[] } }>(`/auto-backup/${row.id}/restore`)
    autoBackupVisible.value = false
    const warnings = res.data?.warnings ?? []
    const resultLines = [res.message || '配置还原成功', ...warnings]
    await ElMessageBox.alert(
      h('div', resultLines.map((line) => h('div', line))),
      '还原完成',
      {
        confirmButtonText: '刷新页面',
        type: warnings.length > 0 ? 'warning' : 'success',
        showClose: false,
        closeOnClickModal: false,
        closeOnPressEscape: false,
      },
    )
    window.location.reload()
  } catch {
    // 全局拦截器已提示（还原失败已回滚，配置未受影响）
  }
}

const deleteAutoBackup = async (row: AutoBackupRow): Promise<void> => {
  try {
    await ElMessageBox.confirm(`确认删除备份「${row.filename}」？删除后不可恢复。`, '删除备份', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  try {
    await request.delete(`/auto-backup/${row.id}`)
    mfaAwareSuccess('备份已删除')
    await fetchAutoBackup()
  } catch {
    // 全局拦截器已提示
  }
}

interface ImportValidation {
  valid: boolean
  type?: string
  has_waf_files?: boolean
  error?: string
  summary?: Record<string, number>
  warnings?: string[]
  disabled_conflicts: DisabledRuleConflict[]
}

interface RuleConflictOpponent {
  name?: string
  caddy_id?: string
  reason: string
}

interface DisabledRuleConflict {
  name?: string
  caddy_id?: string
  reason: string
  conflicts_with: RuleConflictOpponent[]
}

interface ImportResult {
  imported?: number
  summary?: string
  warnings?: string[]
  disabled_conflicts: DisabledRuleConflict[]
}

interface ImportResponse {
  message?: string
  data?: ImportResult
}

const importDialogVisible = ref(false)
const importFileName = ref('')
const importSections = ref<string[]>([])
const importFileIsLbbak = ref(false)
const importFileContent = ref<string | ArrayBuffer>('')
const importValidation = ref<ImportValidation | null>(null)
const importValidating = ref(false)
const importInput = ref<HTMLInputElement | null>(null)
let importValidationSeq = 0

const summaryLabels: Record<string, string> = {
  lb_rules: '规则',
  upstreams: '上游',
  users: '用户',
  api_keys: 'API 密钥',
  ca_providers: 'CA 提供商',
  certificate_configs: 'DNS 提供商',
  cert_jobs: '证书任务',
  rules: '规则',
  tls_rules: '其中 TLS 规则',
  security_crs_version: 'CRS 版本',
  security_ip2region_version: 'IP2Region 版本',
}

const conflictIdentifier = (conflict: { name?: string; caddy_id?: string }): string => conflict.name || conflict.caddy_id || '未命名规则'

const formatImportConflict = (conflict: DisabledRuleConflict): string => {
  const opponents = conflict.conflicts_with
    .map((opponent) => `${conflictIdentifier(opponent)}（${opponent.reason}）`)
    .join('；')
  return `规则 ${conflictIdentifier(conflict)} 将被禁用：与${opponents}冲突`
}

const triggerImport = (): void => {
  if (backupDisabled.value) return
  importValidationSeq++
  importValidating.value = false
  importFileName.value = ''
  importFileContent.value = ''
  importValidation.value = null
  importDialogVisible.value = true
}

const onImportDialogClosed = (): void => {
  importValidationSeq++
  importValidating.value = false
  // C2-4:关闭即释放备份内容(最大 48MB ArrayBuffer/字符串),不驻留至下次选择
  importFileContent.value = ''
  importFileName.value = ''
  importFileIsLbbak.value = false
  importValidation.value = null
  importSections.value = []
}

const chooseImportFile = (): void => {
  importInput.value?.click()
}

const handleImportFile = async (event: Event): Promise<void> => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  const validationSeq = ++importValidationSeq
  importFileName.value = file.name
  importValidation.value = null
  if (file.size > 48 * 1024 * 1024) {
    // C2-5:先于全量读入内存拒绝(后端 413 同口径),防超大文件撑爆标签页
    importValidation.value = { valid: false, error: '备份文件不能超过 48MB', disabled_conflicts: [] }
    return
  }
  importValidating.value = true
  try {
    // v2.3.0 lbbak 为二进制 tar.gz——按魔数选择读取与提交方式
    const head = new Uint8Array(await file.slice(0, 2).arrayBuffer())
    const isLbbak = head[0] === 0x1f && head[1] === 0x8b
    importFileIsLbbak.value = isLbbak
    const fileContent = isLbbak ? await file.arrayBuffer() : await file.text()
    const res = await request.post<{ data: ImportValidation }>('/config/import/validate', fileContent, {
      headers: { 'Content-Type': isLbbak ? 'application/octet-stream' : 'application/json' },
    })
    if (validationSeq !== importValidationSeq) return
    importFileContent.value = fileContent
    importValidation.value = res.data
    // V1 仅负载规则(锁定);V2 默认全选。无 WAF 规则库文件的备份不整类剔除
    // 「安全防护」(该分类同时含策略表)——后端兜底:跳过规则库版本记录表,
    // 并在响应 warnings 中说明(下方结果弹框展示)
    if (res.data?.type === 'v1') {
      importSections.value = ['rules']
    } else {
      importSections.value = BACKUP_SECTIONS.map((sec) => sec.key)
    }
  } catch {
    if (validationSeq === importValidationSeq) {
      importValidation.value = { valid: false, error: '校验请求失败，请重试', disabled_conflicts: [] }
    }
  } finally {
    if (validationSeq === importValidationSeq) {
      importValidating.value = false
    }
  }
}

const confirmImport = async (): Promise<void> => {
  const validation = importValidation.value
  if (!validation?.valid || importing.value) return
  // FE44-6：未选分类先于最终确认弹框拦截（V1 路径强制 ['rules']，不可达此分支）
  if (importSections.value.length === 0) { ElMessage.warning('请至少选择一个导入分类'); return }
  // R62 D-3：全量导入是全仓破坏性最强的操作（覆盖规则、用户、密钥、证书任务与全部凭证），
  // 此前是唯一缺二次确认弹框的破坏性操作——「确认导入」按钮与警示文案不足以兜底误点。
  try {
    const isFullImport = validation.type === 'v1' || importSections.value.length === BACKUP_SECTIONS.length
    await ElMessageBox.confirm(
      isFullImport
        ? '导入将覆盖当前全部配置（规则、用户、API 密钥、证书任务及全部凭证），此操作不可撤销。确认导入？'
        : `将仅覆盖所选分类：${importSections.value.map((k) => BACKUP_SECTIONS.find((s) => s.key === k)?.label || k).join('、')}，未选分类保持现状。此操作不可撤销。确认导入？`,
      '最终确认',
      { type: 'warning', confirmButtonText: '确认导入', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  importing.value = true
  try {
    let endpoint = validation.type === 'v1' ? '/config/import/v1' : '/config/import'
    let importBody: string | ArrayBuffer = importFileContent.value
    if (!importFileIsLbbak.value && validation.type !== 'v1') {
      // 顶层注入 sections(不重排原 JSON)
      try {
        const raw = typeof importFileContent.value === 'string' ? importFileContent.value : ''
        const parsed = JSON.parse(raw) as Record<string, unknown>
        parsed.sections = importSections.value
        importBody = JSON.stringify(parsed)
      } catch { /* 原样提交(后端会 400 校验失败) */ }
    }
    if (importFileIsLbbak.value && validation.type !== 'v1') {
      // R39-1:lbbak 二进制无法体内携带 sections——分类选择经 query 传输
      endpoint = `/config/import?sections=${encodeURIComponent(importSections.value.join(','))}`
    }
    const res = await request.post<ImportResponse>(endpoint, importBody, {
      headers: { 'Content-Type': importFileIsLbbak.value ? 'application/octet-stream' : 'application/json' },
    })
    importDialogVisible.value = false
    const disabledConflicts = res.data?.disabled_conflicts ?? []
    // C2-41-1:后端 data.warnings(操作账户替换/会话吊销/ACME 悬挂/规则库元数据
    // 跳过)此前被丢弃——与冲突同级展示,非空时结果至少 warning 级
    const warnings = res.data?.warnings ?? []
    const resultLines = [
      res.message || '配置导入成功',
      ...warnings,
      `冲突置为禁用：${disabledConflicts.length} 条`,
      ...disabledConflicts.map(formatImportConflict),
    ]
    await ElMessageBox.alert(
      h('div', resultLines.map((line) => h('div', line))),
      '导入完成',
      {
        confirmButtonText: '刷新页面',
        type: disabledConflicts.length > 0 || warnings.length > 0 ? 'warning' : 'success',
        showClose: false,
        closeOnClickModal: false,
        closeOnPressEscape: false,
      },
    )
    window.location.reload()
  } catch (error: unknown) {
    // 全局拦截器已弹 toast，这里仅记录避免 unhandled rejection
    console.error('Failed to import config:', error)
  } finally {
    importing.value = false
  }
}

interface BasicSettingsConfig {
  log_level: string
  cert_job_log_size_mb: number
  audit_log_size_mb: number
  runtime_log_size_mb: number
  audit_retention_months: number
  jwt_expire_minutes: number
  timezone: string
  mfa_write_guard: boolean
  mfa_lockout_enabled: boolean
  // 可选：父级 Settings.vue 的 SettingsConfig 尚未声明此键（vue-tsc 模板检查
  // 要求父类型可赋值给本接口），由下方 computed 兜底默认值
  github_proxy_url?: string
}

// GitHub 加速代理固定选项（CRS / IP2Region 下载）
interface GithubProxyOption {
  label: string
  value: string
}

const DEFAULT_GITHUB_PROXY_URL = 'https://v4.gh-proxy.org/'
const githubProxyOptions: GithubProxyOption[] = [
  { label: 'Cloudflare (v4)', value: 'https://v4.gh-proxy.org/' },
  { label: 'AxisNow (v4)', value: 'https://axisnow.gh-proxy.org/' },
  { label: 'Fastly (v4)', value: 'https://cdn.gh-proxy.org/' },
]

interface ConfigPreviewResponse {
  data?: {
    changed: boolean
    section: string
    changes: string[]
  }
}

interface AdminTlsCertInfo {
  domain: string
  issuer: string
  not_after: string
  days_left: number
}

interface AdminTlsForm {
  mode: string
  certFile: File | null
  keyFile: File | null
  certInfo: AdminTlsCertInfo | null
  inspecting: boolean
}

const mfaScopeVisible = ref(false)
const mfaScopeGroups = [
  { title: '负载规则', items: ['创建', '编辑', '删除', '启用', '禁用', '复制'] },
  { title: '证书与 DNS', items: ['DNS 配置增删改', 'CA 提供商修改', '触发证书签发', '证书任务重试/删除'] },
  { title: '安全防护', items: ['安全策略增删改/绑定', '自定义规则增删改', '拦截页面增删改', 'CRS/IP 库更新与自动更新开关'] },
  { title: '用户与密钥', items: ['用户增删改/启停/重置密码（管理员）', '个人资料修改', 'API 密钥创建/启停/删除（含自己的）', '重置 MFA（含管理员代重置）', '启用/禁用/重新生成恢复码（自己的）'] },
  { title: '系统与服务', items: ['基础设置/Caddy 全局配置保存', '配置重载/校验', '配置导入（v1/v2）', '配置导出与自动备份（设置保存/立即备份/删除/还原/下载）', '管理 TLS 设置修改', 'OIDC 配置修改/删除', 'Caddy 服务启动/停止/重启', 'Caddyfile 手动编辑', '系统重启'] },
  { title: '集群管理', items: ['节点审批/拒绝/删除', '访问地址修改', '注册令牌生成', '主从模式切换/提升', '手动同步', '集群同步设置', '登录从节点（票据签发，每次验证）'] },
]

const settings = defineModel<BasicSettingsConfig>('settings', { required: true })
const emit = defineEmits<{
  (e: 'save'): void
}>()

// 未加载/后端未返回该键时兜底为默认代理，避免 select 显示空值
const githubProxyUrl = computed<string>({
  get: () => settings.value.github_proxy_url || DEFAULT_GITHUB_PROXY_URL,
  set: (value: string) => {
    settings.value.github_proxy_url = value
  },
})

// 父级 Settings.vue 的 applyBasicKeys 仅合并其已知键，此键由本卡片自行拉取回填
// （同 loadAdminTls 先例），保证整页刷新后已保存的非默认代理不回落为默认值
const loadGithubProxyUrl = async (): Promise<void> => {
  try {
    const res = await request.get<{ data?: { github_proxy_url?: string } }>('/config')
    settings.value.github_proxy_url = res.data?.github_proxy_url || DEFAULT_GITHUB_PROXY_URL
  } catch {
    // 拉取失败保持默认值，保存时仍会提交当前选择
  }
}
loadGithubProxyUrl()

const saving = ref(false)

const adminTls = ref({ enabled: false, mode: 'selfsigned' })
const adminTlsSaved = ref({ enabled: false, mode: 'selfsigned' })
const adminTlsHasCert = ref(false)
const adminTlsForm = ref<AdminTlsForm>({ mode: 'selfsigned', certFile: null, keyFile: null, certInfo: null, inspecting: false })
const stagedAdminTlsCert = ref<{ certFile: File; keyFile: File; certInfo: AdminTlsCertInfo } | null>(null)
const adminTlsDialogVisible = ref(false)

const adminTlsDirty = computed(() => {
  if (adminTls.value.enabled !== adminTlsSaved.value.enabled) return true
  if (!adminTls.value.enabled) return false
  return adminTls.value.mode !== adminTlsSaved.value.mode || stagedAdminTlsCert.value !== null
})

const loadAdminTls = async () => {
  try {
    const res = await request.get('/admin-tls')
    if (res.data) {
      const saved = { enabled: res.data.enabled, mode: res.data.mode || 'selfsigned' }
      adminTlsSaved.value = saved
      adminTls.value = { ...saved }
      adminTlsHasCert.value = res.data.cert_info != null || saved.mode === 'selfsigned'
      stagedAdminTlsCert.value = null
    }
  } catch { /* ignore */ }
}

const openAdminTlsDialog = () => {
  adminTlsForm.value = {
    mode: adminTls.value.mode === 'upload' ? 'upload' : 'selfsigned',
    certFile: stagedAdminTlsCert.value?.certFile ?? null,
    keyFile: stagedAdminTlsCert.value?.keyFile ?? null,
    certInfo: stagedAdminTlsCert.value?.certInfo ?? null,
    inspecting: false,
  }
  adminTlsDialogVisible.value = true
}

const onAdminTlsDialogClose = () => {
  tlsInspectSeq++
  adminTlsForm.value = { mode: 'selfsigned', certFile: null, keyFile: null, certInfo: null, inspecting: false }
  // 由开关触发的弹窗若未点「确定」就关闭，开关回退到已保存状态
  if (tlsDialogFromToggle) {
    tlsDialogFromToggle = false
    adminTls.value.enabled = adminTlsSaved.value.enabled
  }
}

// 开关仅暂存，实际生效由底部「保存」统一提交（含关闭操作）
let tlsDialogFromToggle = false
const onAdminTlsToggle = (val: string | number | boolean) => {
  if (val) {
    tlsDialogFromToggle = true
    openAdminTlsDialog()
  }
}

const formDataOf = (fields: Record<string, string>): FormData => {
  const fd = new FormData()
  for (const [k, v] of Object.entries(fields)) fd.append(k, v)
  return fd
}

let tlsInspectSeq = 0
let tlsProtocolFallbackTimer: ReturnType<typeof setTimeout> | null = null
let disposed = false

const onTlsFile = async (e: Event, kind: 'cert' | 'key') => {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  if (kind === 'cert') adminTlsForm.value.certFile = file
  else adminTlsForm.value.keyFile = file
  adminTlsForm.value.certInfo = null
  if (adminTlsForm.value.certFile && adminTlsForm.value.keyFile) {
    const seq = ++tlsInspectSeq
    adminTlsForm.value.inspecting = true
    try {
      const fd = new FormData()
      fd.append('cert_file', adminTlsForm.value.certFile)
      fd.append('key_file', adminTlsForm.value.keyFile)
      const res = await request.post<{ data?: AdminTlsCertInfo }>('/admin-tls/inspect', fd)
      if (seq === tlsInspectSeq) {
        adminTlsForm.value.certInfo = res.data ?? null
      }
    } catch {
      if (seq === tlsInspectSeq) {
        adminTlsForm.value.certInfo = null
      }
    } finally {
      if (seq === tlsInspectSeq) {
        adminTlsForm.value.inspecting = false
      }
    }
  }
}

const notifyTlsRestarting = (toHttps: boolean) => {
  const target = `${toHttps ? 'https' : 'http'}://${location.host}/`
  // 不盲跳：新进程 HTTPS listener 在完整启动序列后才 bind，固定延时跳转必中连接拒绝窗口
  // （R38 D-1）。停留当前页，弹窗给出可点击的目标链接，由用户就绪后自行访问。
  ElMessageBox.alert(
    `已保存，服务正在自动重启（从节点同步后将自动重启生效），就绪后请访问：<a href="${target}" target="_blank" rel="noopener noreferrer" style="word-break: break-all;">${target}</a>`,
    '正在重启',
    {
      confirmButtonText: '知道了',
      type: 'success',
      showClose: false,
      closeOnClickModal: false,
      closeOnPressEscape: false,
      dangerouslyUseHTMLString: true,
    },
  )
    .catch((err) => { console.error('TLS restart notification failed:', err) })
  if (tlsProtocolFallbackTimer) clearTimeout(tlsProtocolFallbackTimer)
  // 兜底提醒（不导航）：无论是否已关闭弹窗，15s 后提示一次手动访问新地址
  tlsProtocolFallbackTimer = setTimeout(() => {
    if (!disposed) ElMessage.warning(`若未自动跳转请手动访问新地址：${target}`)
  }, 15000)
}

// 弹窗「确定」仅暂存证书选择，不发请求；随底部「保存」统一提交
const confirmAdminTls = () => {
  const { mode, certFile, keyFile, certInfo } = adminTlsForm.value
  if (mode === 'upload' && (!certFile || !keyFile || !certInfo || certInfo.days_left <= 0)) return
  tlsDialogFromToggle = false
  adminTls.value.mode = mode
  stagedAdminTlsCert.value = mode === 'upload' && certFile && keyFile && certInfo
    ? { certFile, keyFile, certInfo }
    : null
  adminTlsDialogVisible.value = false
}

loadAdminTls()
const restarting = ref(false)

const handleRestart = async () => {
  if (isReadOnly.value || restarting.value) return
  try {
    await ElMessageBox.confirm('重启期间服务短暂不可用，容器将自动拉起，就绪后自动刷新页面。确认重启？', '重启服务', {
      confirmButtonText: '重启',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch {
    return
  }
  restarting.value = true
  try {
    await request.post('/system/restart')
  } catch {
    // 重启请求失败（全局拦截器已提示），复位按钮允许重试
    restarting.value = false
    return
  }
  mfaAwareSuccess('服务正在重启，就绪后自动刷新页面')
  // 保持 restarting=true 直到 reload（防就绪等待窗口内二次点击）；超时或失败才复位
  const reloaded = await reloadAfterRestart(() => disposed)
  if (!reloaded) restarting.value = false
}

const handleSave = async () => {
  if (isReadOnly.value) return
  if (saving.value) return
  const tlsPending = adminTlsDirty.value
  if (tlsPending && adminTls.value.enabled && adminTls.value.mode === 'upload' && !stagedAdminTlsCert.value && !adminTlsHasCert.value) {
    ElMessage.warning('请先在「配置证书」中选择并校验上传证书')
    return
  }
  saving.value = true
  try {
    const payload = {
      log_level: settings.value.log_level,
      cert_job_log_size_mb: settings.value.cert_job_log_size_mb,
      audit_log_size_mb: settings.value.audit_log_size_mb,
      runtime_log_size_mb: settings.value.runtime_log_size_mb,
      audit_retention_months: settings.value.audit_retention_months,
      jwt_expire_minutes: settings.value.jwt_expire_minutes,
      timezone: settings.value.timezone,
      mfa_write_guard: settings.value.mfa_write_guard,
      mfa_lockout_enabled: settings.value.mfa_lockout_enabled,
      github_proxy_url: githubProxyUrl.value,
      source: 'basic',
    }
    const preview = await request.post<ConfigPreviewResponse>('/config/preview', payload)
    const changes = [...(preview.data?.changes ?? [])]
    if (tlsPending) {
      changes.unshift(
        adminTls.value.enabled
          ? `强制 HTTPS：启用（${adminTls.value.mode === 'upload' ? '上传证书' : '本地自签名证书'}），保存后服务将重启`
          : '强制 HTTPS：禁用，保存后服务将重启',
      )
    }
    if (preview.data?.changed || tlsPending) {
      await ElMessageBox.confirm(changes.length > 0 ? changes.join('；') : '检测到配置变更', `确认保存${preview.data?.section || '基础设置'}？`, {
        confirmButtonText: '确认',
        cancelButtonText: '取消',
        type: 'warning',
      })
    }
    await request.put('/config', payload)
    // 保存成功后立即刷新全局配置，让 timezone 在 authStore 中立竿见影（date.ts formatDate 展示侧即时生效）；
    // silent：保存已成功，随后的 GET /config 刷新失败不应再弹误导性错误 toast
    await authStore.fetchConfig(true)
    if (tlsPending) {
      const fd = formDataOf({ enabled: String(adminTls.value.enabled), mode: adminTls.value.mode })
      const staged = stagedAdminTlsCert.value
      if (adminTls.value.enabled && adminTls.value.mode === 'upload' && staged) {
        fd.append('cert_file', staged.certFile)
        fd.append('key_file', staged.keyFile)
      }
      await request.put('/admin-tls', fd)
      adminTlsSaved.value = { ...adminTls.value }
      adminTlsHasCert.value = adminTlsHasCert.value || adminTls.value.enabled
      stagedAdminTlsCert.value = null
      notifyTlsRestarting(adminTls.value.enabled)
    } else {
      mfaAwareSuccess('保存成功')
    }
    emit('save')
  } catch (error) {
    // MessageBox 仅以 'cancel'/'close' 字符串 reject（用户取消），静默短路；
    // 其余错误（HTTP 等）已由全局拦截器 toast，此处仅记录。
    if (error === 'cancel' || error === 'close') return
    console.error('Failed to save basic settings:', error)
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.backup-sections-item { flex-direction: column; align-items: flex-start; gap: 4px; }
/* 备份弹框 */
.backup-dialog-header { display: flex; align-items: center; gap: 12px; }
.backup-dialog-icon {
  width: 38px; height: 38px; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  background: var(--el-color-primary-light-9); color: var(--el-color-primary);
  font-size: 18px; flex-shrink: 0;
}
.backup-dialog-title { font-size: 16px; font-weight: 600; color: var(--el-text-color-primary); }
.backup-dialog-sub { font-size: 12.5px; color: var(--el-text-color-secondary); margin-top: 2px; }
.section-chips { display: flex; flex-wrap: wrap; gap: 8px; }
.section-chip {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 999px;
  background: var(--el-fill-color-blank);
  color: var(--el-text-color-regular);
  font-size: 12.5px;
  padding: 5px 14px;
  cursor: pointer;
  transition: all .15s ease;
}
.section-chip:hover { border-color: var(--el-color-primary-light-5); }
.section-chip.is-active {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
  font-weight: 500;
}
.section-chip.is-disabled { cursor: not-allowed; opacity: .5; }
.import-summary-chip {
  display: inline-flex; align-items: center;
  border-radius: 5px; padding: 2px 8px; margin: 0 6px 6px 0;
  background: var(--el-fill-color); color: var(--el-text-color-regular);
  font-size: 12px; font-variant-numeric: tabular-nums;
}
.import-summary-chip.is-zero { opacity: .45; }
.import-v1-hint { margin-top: 6px; display: inline-block; }
.section-card.is-active { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.section-hint { font-size: 11.5px; color: var(--el-text-color-placeholder); }
/* 全选/全不选与告警条之间留出间距;chips 单行不换行(弹框 720px) */
.backup-dialog-actions { display: flex; justify-content: flex-end; gap: 4px; margin-top: 8px; margin-bottom: 14px; }
.backup-dialog .section-chips, .import-sections .section-chips { flex-wrap: nowrap; }
.import-sections { border: 1px solid var(--el-border-color-lighter); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.import-sections-label { font-size: 13px; font-weight: 600; margin-bottom: 6px; }

.basic-stack { display: flex; flex-direction: column; gap: 20px; }
.card-header { display: flex; align-items: center; }
.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: #111827;
}
.settings-form { padding: 4px 0; }
.compact-select { width: 240px; max-width: 100%; }
.tip-inline { margin-left: 8px; line-height: 1.5; }
.tip-block { display: block; flex-basis: 100%; margin-top: 4px; line-height: 1.5; }
.info-list { padding: 4px 0; }
.info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid var(--border-lighter);
}
.info-item:last-child { border-bottom: none; }
.info-label { color: var(--text-secondary); font-size: 13px; }
.btn-text { margin-left: 4px; }
.backup-actions { display: flex; align-items: center; gap: 8px; }
.import-input { display: none; }
.backup-tip { display: block; margin-top: 8px; line-height: 1.5; }
.log-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.log-viewer { height: 60vh; min-height: 320px; overflow: auto; padding: 12px 16px; background: #0f172a; border-radius: var(--radius-sm, 6px); }
.log-viewer pre { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; line-height: 1.7; color: #e2e8f0; white-space: pre-wrap; word-break: break-all; }
.import-picker { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.import-filename { font-size: 13px; color: var(--el-text-color-primary); }
.import-hint { font-size: 12px; color: var(--el-text-color-secondary); }
.import-validating { padding: 24px 0; text-align: center; color: var(--el-text-color-secondary); font-size: 13px; }
.import-result { display: flex; flex-direction: column; gap: 12px; }
.import-summary { display: flex; flex-wrap: wrap; gap: 8px 16px; font-size: 13px; color: var(--el-text-color-primary); }
.import-warnings { margin: 0; padding-left: 18px; font-size: 12px; color: var(--el-text-color-secondary); line-height: 1.8; }
.import-conflicts { color: var(--el-color-warning-dark-2); }
.import-alert { margin-top: 4px; }

/* R72 十六次→十七次：el-descriptions 的表格布局压不动 label 宽（仍折行）——
   改自绘行布局：标题列 flex 定宽 + nowrap，内容列自动换行。 */
.mfa-scope-list {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 4px;
  overflow: hidden;
}
.mfa-scope-row {
  display: flex;
  align-items: stretch;
}
.mfa-scope-row + .mfa-scope-row {
  border-top: 1px solid var(--el-border-color-lighter);
}
.mfa-scope-title {
  flex: 0 0 130px;
  padding: 8px 12px;
  font-weight: 600;
  white-space: nowrap;
  background: var(--el-fill-color-light);
  border-right: 1px solid var(--el-border-color-lighter);
}
.mfa-scope-items {
  flex: 1;
  padding: 8px 12px;
  line-height: 1.8;
}

/* R72 十五次：「支持的操作」链接与描述文字同色（info），保留可点击/hover 链接语义 */
:deep(.tip-link.el-link) {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
:deep(.tip-link.el-link:hover) {
  color: var(--el-color-info);
}

/* 自动备份弹框 */
.auto-backup-form { padding: 4px 0; }
.auto-backup-form :deep(.el-form-item) { margin-bottom: 14px; }
.auto-backup-chips { flex-wrap: wrap; }
/* 全选/全不选与提示换行置于分类选项下方,左对齐(el-form-item__content 为
 * flex 行,flex-basis:100% 强制换行;2026-09-19 用户样式裁定) */
/* 与 el-table 单元格 .cell 的 12px 内边距对齐——标题/说明文字与表格内容同缘 */
.auto-backup-list-head { display: flex; align-items: baseline; justify-content: flex-end; margin-top: 12px; margin-bottom: 8px; padding: 0 8px; }
.auto-backup-chips-actions { flex-basis: 100%; display: flex; align-items: center; gap: 8px; margin-top: 8px; }
.auto-backup-chips-actions .el-button + .el-button { margin-left: 0; }
.auto-backup-scope-hint { margin-left: 0; }
.auto-backup-list { border-top: 1px solid var(--el-border-color-lighter); padding-top: 10px; }

/* 自管标签行(ClusterModeCard 范式,FE41-1):复刻 EP .el-form-item__label 计算
 * 样式(右对齐/32px 行高/12px 右内边距),110px 与两弹框 label-width 一致;
 * role=group+aria-label 替代 el-form-item label,规避 el-radio-group 组容器
 * DIV 被 label for 指向的 Firefox a11y 告警 */
.form-radio-row { display: flex; margin-bottom: 18px; }
.auto-backup-form .form-radio-row { margin-bottom: 14px; }
.form-radio-row-label { width: 110px; flex-shrink: 0; height: 32px; line-height: 32px; text-align: right; padding-right: 12px; box-sizing: border-box; color: var(--el-text-color-regular); font-size: var(--el-form-label-font-size, 14px); }
.form-radio-row-content { flex: 1; min-width: 0; display: flex; align-items: center; }
.import-waf-hint { display: block; }
</style>
