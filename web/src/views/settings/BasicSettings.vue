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
        <el-form :model="settings" label-width="120px" class="settings-form" :disabled="formFrozen">
          <el-form-item label="日志级别">
            <el-select v-model="settings.log_level" :disabled="formFrozen" style="width: 140px">
              <el-option label="Debug" value="debug" />
              <el-option label="Info" value="info" />
              <el-option label="Warning" value="warn" />
              <el-option label="Error" value="error" />
            </el-select>
            <span class="form-tip-inline">控制 Lazy Balancer 自身日志详细程度</span>
          </el-form-item>
          <el-form-item label="任务日志大小">
            <el-input-number v-model="settings.task_log_size_mb" :disabled="formFrozen" :min="1" :max="1024" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">MB，任务与库更新日志轮转阈值</span>
          </el-form-item>
          <el-form-item label="审计日志大小">
          <el-input-number v-model="settings.audit_log_size_mb" :disabled="formFrozen" :min="1" :max="512" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">MB，WAF 审计日志轮转阈值</span>
          </el-form-item>
          <el-form-item label="运行日志大小">
            <el-input-number v-model="settings.runtime_log_size_mb" :disabled="formFrozen" :min="1" :max="1024" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">MB，轮转阈值</span>
          </el-form-item>
          <el-form-item label="操作审计保留">
            <el-input-number v-model="settings.audit_retention_months" :disabled="formFrozen" :min="1" :max="12" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">个月，仅操作审计日志超期自动清理</span>
          </el-form-item>
          <el-form-item label="安全事件保留">
            <el-input-number v-model="seRetentionDays" :disabled="formFrozen" :min="1" :max="3650" :step="30" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">天</span>
            <el-input-number v-model="seRowCap" :disabled="formFrozen" :min="1" :max="100000000" :step="100000" controls-position="right" style="width: 170px; margin-left: 10px;" />
            <span class="form-tip-inline">行数上限</span>
            <div class="form-tip-line">安全事件日志每日清理：超出保留天数或行数上限时按最旧优先删除（行数上限在两次清理之间可能短暂超出）。默认 90 天 / 1,000,000 行；高攻击流量部署可按需上调。</div>
          </el-form-item>
          <el-form-item label="登录过期">
            <el-input-number v-model="settings.jwt_expire_minutes" :disabled="formFrozen" :min="1" :max="1440" controls-position="right" style="width: 120px;" />
            <span class="form-tip-inline">分钟，登录令牌有效期</span>
          </el-form-item>
          <el-form-item label="时区">
            <el-select v-model="settings.timezone" :disabled="formFrozen" filterable allow-create default-first-option class="compact-select">
              <el-option v-for="opt in timezoneOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
            </el-select>
            <div class="form-tip-line">影响日志时间戳与证书时间；标注夏令时的时区会随夏令时自动偏移；标注「自定义」的值为 API/备份写入、不在常用列表内的 IANA 时区（可继续使用或改选）；仅 Caddy 日志需重启服务生效</div>
          </el-form-item>
          <el-form-item label="大屏本站坐标">
            <el-select v-model="siteLocationKey" :disabled="formFrozen" filterable clearable placeholder="选择省份或国家" style="width: 260px" @change="applySiteLocation">
              <el-option-group label="中国省份">
                <el-option v-for="item in CHINA_SITE_CHOICES" :key="item.key" :label="item.label" :value="item.key" />
              </el-option-group>
              <el-option-group label="海外国家">
                <el-option v-for="item in COUNTRY_SITE_CHOICES" :key="item.key" :label="item.label" :value="item.key" />
              </el-option-group>
            </el-select>
            <span class="form-tip-inline">纬度 {{ (settings.server_map_lat ?? 0).toFixed(4) }} · 经度 {{ (settings.server_map_lon ?? 0).toFixed(4) }}</span>
            <div class="form-tip-line">威胁大屏地图本站信标坐标；选择中国省份或海外国家后自动换算经纬度。未选择表示未设置，按地图视觉中心显示。</div>
          </el-form-item>
          <el-form-item label="大屏视觉模式">
            <el-radio-group v-model="threatScreenMode" :disabled="formFrozen">
              <el-radio value="map">360° 地图 · 雷达扫掠</el-radio>
              <el-radio value="globe">3D 地球 · 垂直扫描</el-radio>
            </el-radio-group>
            <div class="form-tip-line">威胁大屏中央攻击流光的呈现方式；进入大屏时生效（已打开的大屏重新进入后切换）</div>
          </el-form-item>
          <el-form-item label="流量采样">
            <el-select v-model="trafficSampleN" :disabled="formFrozen" style="width: 160px">
              <el-option label="自适应（推荐）" :value="-1" />
              <el-option label="关闭逐请求光流" :value="0" />
            </el-select>
            <div class="form-tip-line">大屏逐请求光流的采样开关；自适应从全量起步，并随事件量在 1/4、1/8 档之间自动切换。关闭后仅保留聚合流量统计，不影响安全事件日志。</div>
          </el-form-item>
          <el-form-item label="下载代理">
            <el-select v-model="githubProxyUrl" :disabled="formFrozen || !githubProxyLoaded" style="width: 160px" :placeholder="githubProxyLoaded ? '选择代理' : '未加载'">
              <el-option
                v-for="option in githubProxyOptions"
                :key="option.value"
                :label="option.label"
                :value="option.value"
              />
            </el-select>
            <span v-if="githubProxyLoaded" class="form-tip-inline">GitHub 下载代理，加速 CRS 规则库与 IP2Region</span>
            <span v-else class="form-tip-inline">代理设置未加载：已禁用编辑且保存不会写入该项</span>
          </el-form-item>
          <el-form-item label="访问令牌">
            <el-input
              v-model="githubTokenInput"
              type="password"
              show-password
              style="width: 320px"
              :placeholder="settings.has_github_token ? '已配置（留空保持不变）' : '未配置（未认证限流 60 次/小时）'"
              :disabled="formFrozen"
              maxlength="255"
              @input="githubTokenClearPending = false"
            />
            <el-button v-if="settings.has_github_token && !githubTokenClearPending" type="danger" link size="small" style="margin-left: 8px" :disabled="formFrozen" @click="clearGithubToken">清除</el-button>
            <el-text v-if="githubTokenClearPending" type="danger" size="small" style="margin-left: 8px">已标记清除，保存后生效</el-text>
            <div class="form-tip-line">可选 GITHUB_TOKEN：令牌认证后 GitHub API 限流由 60 提升至 5000 次/小时，缓解规则库自动更新 403；令牌仅随 GitHub 直连发送，不经第三方代理；点「清除」可撤销已配置令牌（保存后生效）。<el-link type="primary" href="https://github.com/settings/tokens" target="_blank" rel="noopener">前往 GitHub 创建令牌</el-link>（只需公共仓库只读权限，无需勾选任何 scope）</div>
          </el-form-item>
          <el-form-item label="写操作验证">
            <el-switch v-model="settings.mfa_write_guard" :disabled="formFrozen" />
            <span class="form-tip-inline">写操作需 1 分钟内的 MFA 验证</span>
            <AccessibleLink type="info" underline="never" size="small" class="tip-link" style="margin-left: 6px" @click="mfaScopeVisible = true">支持的操作</AccessibleLink>
          </el-form-item>
          <el-form-item label="登录失败锁定">
            <el-switch v-model="settings.mfa_lockout_enabled" :disabled="formFrozen" />
            <span class="form-tip-inline">密码或验证码失败 5 次锁 10 分钟（关闭则不锁定）</span>
          </el-form-item>
          <el-form-item label="强制加密">
            <el-switch v-model="adminTls.enabled" :disabled="formFrozen || !adminTlsLoaded" @change="onAdminTlsToggle" />
            <el-button v-if="adminTls.enabled" size="small" style="margin-left: 8px;" :disabled="formFrozen" @click="openAdminTlsDialog">配置证书</el-button>
            <!-- 降级读优先于暂存/失败提示：开关当前显示的是后端降级值，
                 用户必须先知道「不可信」再考虑其它动作（重试走同一读路径）。 -->
            <template v-if="adminTlsUnavailable">
              <el-text type="danger" size="small" style="margin-left: 8px">配置读取失败，显示的开关不可信</el-text>
              <AccessibleLink type="primary" underline="never" size="small" style="margin-left: 6px" @click="retryLoadAdminTls">重试</AccessibleLink>
            </template>
            <el-text v-else-if="adminTlsDirty" type="warning" size="small" style="margin-left: 8px">已暂存，点击下方保存后生效</el-text>
            <!-- 读取失败显性化 + 重试（与 githubProxyLoaded 的提示同口径）-->
            <template v-else-if="adminTlsLoadFailed">
              <el-text type="danger" size="small" style="margin-left: 8px">TLS 配置读取失败，开关暂不可用</el-text>
              <AccessibleLink type="primary" underline="never" size="small" style="margin-left: 6px" @click="retryLoadAdminTls">重试</AccessibleLink>
            </template>
            <span v-else class="form-tip-inline">启用后 :8000 仅经 HTTPS 访问，需重启服务生效</span>
            <!-- 库内证书不可读（fail-visible）：后端以 cert_info_error 显式申报，
                 页面必须消费——否则损坏证书与「未配置证书」在界面上无法区分。 -->
            <div v-if="adminTlsCertBroken" class="info-note-bar">
              <el-text type="danger" size="small" class="info-note-desc">
                已保存的管理面板证书无法解析（{{ adminTlsCertError }}），HTTPS 可能无法正常访问；请点「配置证书」重新上传，或切换为自签名后保存以修复。
              </el-text>
            </div>
          </el-form-item>
          <el-form-item label="运行日志">
            <el-button size="small" :icon="View" @click="openAppLogDialog">查看日志</el-button>
            <span class="form-tip-inline">查看 Lazy Balancer 自身运行日志</span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" :disabled="isReadOnly || !props.configLoaded" @click="handleSave">
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
          <el-tag :type="authStore.nodeMode === 'master' ? 'success' : authStore.nodeMode === 'slave' ? 'warning' : 'info'" size="small">
            {{ authStore.nodeMode === 'master' ? '主节点' : authStore.nodeMode === 'slave' ? '从节点' : '加载中' }}
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

    <el-dialog v-model="adminTlsDialogVisible" class="dialog-body-inset" width="min(560px, 92vw)" destroy-on-close @closed="onAdminTlsDialogClose">
      <template #header>
        <DialogHeader :icon="Lock" title="HTTPS 证书配置"
          subtitle="管理面板（:8000）强制 HTTPS 使用的证书，保存后服务重启生效" />
      </template>
      <el-form label-width="110px">
        <el-form-item label="证书来源">
          <el-radio-group v-model="adminTlsForm.mode" aria-label="证书来源">
            <el-radio value="selfsigned">本地自签名证书</el-radio>
            <el-radio value="upload">上传证书</el-radio>
          </el-radio-group>
        </el-form-item>
        <template v-if="adminTlsForm.mode === 'upload'">
          <div v-if="adminTlsReuseSaved" class="info-note-bar"><span class="info-note-desc">库内已有可用的上传证书：不选择新文件即沿用该证书，无需重新上传</span></div>
          <el-form-item label="证书文件">
            <div class="tls-file-field">
              <el-button size="small" @click="pickTlsFile('cert')">选择文件</el-button>
              <span class="tls-file-name" :class="{ 'is-empty': !adminTlsForm.certFile }">{{ adminTlsForm.certFile?.name ?? '未选择（支持 .crt / .pem / .cer）' }}</span>
            </div>
          </el-form-item>
          <el-form-item label="私钥文件">
            <div class="tls-file-field">
              <el-button size="small" @click="pickTlsFile('key')">选择文件</el-button>
              <span class="tls-file-name" :class="{ 'is-empty': !adminTlsForm.keyFile }">{{ adminTlsForm.keyFile?.name ?? '未选择（支持 .key / .pem）' }}</span>
            </div>
          </el-form-item>
          <el-form-item v-if="adminTlsForm.inspecting" label=" ">
            <el-text type="info" size="small">解析中…</el-text>
          </el-form-item>
          <!-- 失败原因必须常驻弹框内（toast 一闪而过；「确定」变灰需可解释） -->
          <div v-if="adminTlsForm.inspectError && !adminTlsForm.inspecting" class="info-note-bar">
            <el-text type="danger" size="small" class="info-note-desc">{{ adminTlsForm.inspectError }}</el-text>
          </div>
          <div v-else-if="adminTlsMissingPairHint && !adminTlsForm.inspecting" class="info-note-bar">
            <span class="info-note-desc">{{ adminTlsMissingPairHint }}</span>
          </div>
          <template v-if="adminTlsForm.certInfo">
            <el-form-item label="证书信息">
              <div class="tls-cert-info">
                <div class="tls-cert-info-row"><span class="tls-cert-info-label">域名</span><span>{{ adminTlsForm.certInfo.domain }}</span></div>
                <div class="tls-cert-info-row"><span class="tls-cert-info-label">签发者</span><span>{{ adminTlsForm.certInfo.issuer }}</span></div>
                <div class="tls-cert-info-row"><span class="tls-cert-info-label">过期时间</span><span :class="{ 'is-expired': adminTlsForm.certInfo.days_left <= 0 }">{{ adminTlsForm.certInfo.not_after }}（剩余 {{ adminTlsForm.certInfo.days_left }} 天）</span></div>
              </div>
            </el-form-item>
          </template>
        </template>
        <div v-if="adminTlsForm.mode === 'selfsigned'" class="info-note-bar"><span class="info-note-desc">自动生成自签名证书，浏览器会提示不受信任；集群同步会自动跳过自签验证</span></div>
      </el-form>
      <template #footer>
        <el-button @click="adminTlsDialogVisible = false">取消</el-button>
        <el-button type="primary" :disabled="adminTlsConfirmBlocked" @click="confirmAdminTls">确定</el-button>
      </template>
    </el-dialog>
    <!-- 隐藏文件选择器（弹框 destroy-on-close 会销毁内部 input——置于弹框外，
         由「选择文件」按钮代理触发；onTlsFile 逻辑不变） -->
    <input ref="tlsCertFileInput" type="file" accept=".crt,.pem,.cer" style="display: none" @change="(e) => onTlsFile(e, 'cert')" />
    <input ref="tlsKeyFileInput" type="file" accept=".key,.pem" style="display: none" @change="(e) => onTlsFile(e, 'key')" />

    <el-dialog v-model="appLogVisible" width="min(1100px, 94vw)" top="5vh" destroy-on-close @opened="onAppLogOpened" @closed="onAppLogClosed">
      <template #header>
        <DialogHeader :icon="Document" title="Lazy Balancer 运行日志" subtitle="实时查看应用运行日志与自愈事件（最近 500 行）" />
      </template>
      <div class="log-toolbar">
        <el-switch v-model="appLogAutoRefresh" active-text="自动刷新" />
        <el-text v-if="appLogError" type="danger" size="small">日志加载失败，自动重试中（当前展示上一次内容）</el-text>
        <el-button size="small" :loading="appLogLoading" @click="fetchAppLogs">刷新</el-button>
      </div>
      <div ref="appLogContainer" class="log-viewer"><pre>{{ appLogContent || appLogEmptyText }}</pre></div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <LogStorageBar log-key="runtime" style="margin-right: auto" />
          <el-button @click="appLogVisible = false">关闭</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="importDialogVisible" width="min(720px, 92vw)" :close-on-click-modal="false" class="backup-dialog dialog-body-inset" @close="onImportDialogClosed">
      <template #header>
        <DialogHeader :icon="Upload" title="导入配置备份" subtitle="选择备份文件与要导入的分类" />
      </template>
      <div class="import-picker">
        <el-button :icon="Upload" @click="chooseImportFile">选择备份文件</el-button>
        <span v-if="importFileName" class="import-filename">{{ importFileName }}</span>
        <span v-else class="import-hint">支持 V2 完整备份与 V1（nginx 版）备份</span>
      </div>
      <input ref="importInput" type="file" accept="application/json,.json,.bak,.lbbak,application/gzip" class="import-input" @change="handleImportFile" />

      <div v-if="importValidating" v-loading="true" class="import-validating">正在校验备份文件...</div>

      <template v-if="importValidation && !importValidating">
        <div v-if="!importValidation.valid" class="info-note-bar import-alert"><span class="info-note-desc">{{ importValidation.error || '备份文件校验失败' }}</span></div>
        <!-- 预览无效时分类 chip 保持可见可用——取消勾选坏行分类后
             revalidateImport 自动重校验恢复 valid 即解锁确认（「未选分类
             坏行不误拒」契约的 UI 可达面）；空分类选择仍由确认时拦截 -->
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
            <el-text v-else-if="!importValidation.valid" type="warning" size="small" class="import-v1-hint">校验未通过——取消勾选包含异常数据的分类后将自动重新校验</el-text>
          </div>
          <!-- 0 选择时摘要/冲突/覆盖范围必须一并隐藏（否则与「本次不会
               覆盖任何数据」并存，展示的是上次选择的陈旧预览）。 -->
          <template v-if="importValidation.valid && importPreviewSelected">
            <el-tag :type="importValidation.type === 'v1' ? 'warning' : 'success'" size="small">
              {{ importValidation.type === 'v1' ? 'V1 兼容导入' : 'V2 完整备份' }}
            </el-tag>
            <div class="import-summary">
              <span v-for="(count, key) in importValidation.summary" :key="key" class="import-summary-chip" :class="{ 'is-zero': !count }">
                {{ importSummaryLabel(key) }}·{{ count }}
              </span>
            </div>
            <!-- 勾选「安全防护」但备份无规则库文件时预览提示(后端兜底
                 跳过规则库版本记录表并在导入结果 warnings 中说明)
                 has_waf_files 已纳入威胁库名单条目，
                 本提示仅剩「CRS/IP2Region/威胁名单条目全无」形态——文案按真实能力
                 点明缺失的是规则库版本文件，避免与「导入将落盘名单文件」矛盾 -->
            <el-text
              v-if="importValidation.has_waf_files === false && importSections.includes('security')"
              type="warning" size="small" class="import-waf-hint"
            >该备份不含规则库版本文件（CRS/IP2Region 与威胁库名单条目），导入「安全防护」将跳过规则库版本记录</el-text>
            <ul v-if="importValidation.warnings?.length" class="import-warnings">
              <li v-for="(warning, index) in importValidation.warnings" :key="index">{{ warning }}</li>
            </ul>
            <ul v-if="importValidation.disabled_conflicts.length" class="import-warnings import-conflicts">
              <li v-for="conflict in importValidation.disabled_conflicts" :key="conflict.caddy_id || conflict.name">
                {{ formatImportConflict(conflict) }}
              </li>
            </ul>
            <!-- 空分类选择不再拼出「将仅覆盖所选分类：，」残句
                 （0 选择的文案已由下方 v-else 分支承担，本块恒有 ≥1 分类） -->
            <div v-if="importValidation.type !== 'v1'" class="info-note-bar import-alert"><span class="info-note-desc">{{ importSections.length === BACKUP_SECTIONS.length ? '导入将覆盖当前全部配置（规则、用户、密钥、证书任务、节点拓扑）' : `将仅覆盖所选分类：${importSections.map((k) => BACKUP_SECTIONS.find((s) => s.key === k)?.label || k).join('、')}，未选分类保持现状` }}</span></div>
            <div v-else class="info-note-bar" style="margin-top: 4px"><span class="info-note-desc">仅导入负载均衡规则，其他数据不受影响</span></div>
          </template>
          <div v-else-if="importValidation.valid" class="info-note-bar import-alert"><span class="info-note-desc">未选择导入分类——本次导入不会覆盖任何数据（请至少选择一个分类）</span></div>
        </div>
      </template>

      <template #footer>
        <el-button @click="importDialogVisible = false">取消</el-button>
        <!-- 0 选择与只读态一律置灰（函数级守卫见 confirmImport）-->
        <el-button type="primary" :disabled="!importValidation?.valid || !importPreviewSelected || isReadOnly" :loading="importing" @click="confirmImport">确认导入</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="exportDialogVisible" width="min(720px, 92vw)" :close-on-click-modal="false" class="backup-dialog dialog-body-inset">
      <template #header>
        <DialogHeader :icon="Download" title="导出配置备份" subtitle="选择要导出的配置分类" />
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
      <div class="info-note-bar" style="margin-top: 8px"><span class="info-note-desc">导出为 .lbbak 备份包（勾选「安全防护」时含 CRS/IP2Region 规则库文件；勾选「节点拓扑」时含从节点列表与站点坐标，含节点令牌哈希）；包含凭证与证书材料，请加密保管</span></div>
      <template #footer>
        <el-button @click="exportDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="exporting" :disabled="exportSections.length === 0" @click="exportBackup">
          确认导出{{ exportSections.length ? `（${exportSections.length}/${BACKUP_SECTIONS.length}）` : '' }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="autoBackupVisible" width="min(880px, 96vw)" :close-on-click-modal="false" class="backup-dialog dialog-body-inset" destroy-on-close @opened="onAutoBackupOpened" @close="onAutoBackupClosed">
      <template #header>
        <DialogHeader :icon="Timer" title="自动备份" subtitle="定时将配置备份到服务器 backup 目录（仅主节点）" />
      </template>
      <el-form label-width="110px" class="auto-backup-form">
        <el-form-item label="启用">
          <el-switch v-model="autoBackupForm.enabled" />
          <span class="form-tip-inline">调度器仅主节点运行；主从切换后自动开始，无需重启进程</span>
        </el-form-item>
        <el-form-item label="频率">
          <el-radio-group v-model="autoBackupForm.frequency" aria-label="频率">
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
        </el-form-item>
        <el-form-item label="备份时间">
          <el-time-select v-model="autoBackupForm.time" start="00:00" end="23:30" step="00:30" style="width: 120px" />
          <span class="form-tip-inline">按系统配置时区执行；停机跨槽会在下次启动补跑一次</span>
        </el-form-item>
        <el-form-item label="保留份数">
          <el-input-number v-model="autoBackupForm.keep" :min="1" :max="30" controls-position="right" style="width: 120px" />
          <span class="form-tip-inline">1-30 份，超出自动清理；失败记录另保留最近 20 条</span>
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
          上次成功备份：{{ autoBackupLastRunLabel }}<template v-if="autoBackupNextRunLabel"> · 下次备份：{{ autoBackupNextRunLabel }}</template>
        </el-text>
      </div>
      <div class="auto-backup-list">
        <el-table v-loading="autoBackupLoading" :data="autoBackupRows" size="small" :max-height="320">
          <el-table-column label="备份时间" width="170">
            <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="版本号" width="110">
            <template #default="{ row }">{{ row.app_version || '—' }}</template>
          </el-table-column>
          <el-table-column label="状态" width="70">
            <template #default="{ row }">
              <el-tag :type="row.status === 'success' ? 'success' : 'danger'" size="small" effect="light">
                {{ row.status === 'success' ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <!-- 内容列只显备份范围（2026-09-21 用户裁定）；各表行数明细+触发方式移入 hover -->
          <el-table-column label="内容" width="230" class-name="auto-backup-scope-cell">
            <template #default="{ row }">
              <el-tooltip :content="autoBackupDetailTip(row)" placement="top" :show-after="150">
                <span class="auto-backup-scope-text" :class="{ 'is-warning': row.sections_error }">{{ autoBackupScopeText(row) }}</span>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="大小" width="90">
            <template #default="{ row }">{{ formatBackupSize(row.size_bytes) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="150" align="right">
            <template #default="{ row }">
              <el-button v-if="row.status === 'success'" link type="primary" size="small" :disabled="autoBackupActionBusy" @click="downloadAutoBackup(row)">下载</el-button>
              <el-button v-if="row.status === 'success'" link type="warning" size="small" :loading="restoringBackupId === row.id" :disabled="autoBackupActionBusy || backupDisabled" @click="restoreAutoBackup(row)">还原</el-button>
              <el-button link type="danger" size="small" :loading="deletingBackupId === row.id" :disabled="autoBackupActionBusy || backupDisabled" @click="deleteAutoBackup(row)">删除</el-button>
            </template>
          </el-table-column>
          <template #empty><el-empty description="暂无备份" :image-size="70" /></template>
        </el-table>
      </div>
      <template #footer>
        <el-button @click="autoBackupVisible = false">取消</el-button>
        <el-button type="primary" plain :loading="autoBackupRunning" :disabled="!autoBackupCanRunNow" title="按已保存的自动备份设置执行一次备份；上方表单改动需先保存设置" @click="runAutoBackupNow">
          立即备份
        </el-button>
        <el-button type="primary" :loading="autoBackupSaving" :disabled="!autoBackupSectionsValid || !autoBackupLoaded || autoBackupLoading" @click="saveAutoBackupSettings">
          保存设置
        </el-button>
      </template>
    </el-dialog>
  </div>

  <!-- 写操作验证「支持的操作」清单——与后端 mfaStepUpGuard
       实际覆盖面一致（admin/business 两组的 POST/PUT/PATCH/DELETE，排除
       readOnlyWriteRoutes 的只读语义写操作（含 DELETE 释放采集租约），以及
       step-up 机制本体 verify-step 与
       登出（DecideMFAStepUp 仅豁免此二者，setup/activate/disable/恢复码照常
       验码）；WS-05 起「测试」不再一概豁免：证书配置/CA 提供商的 test 会真实
       写 DNS TXT / 申请 EAB）。 -->
  <el-dialog v-model="mfaScopeVisible" class="dialog-body-inset" width="min(640px, 94vw)">
    <template #header>
      <DialogHeader :icon="Lock" title="写操作验证支持的操作" subtitle="覆盖全部管理写操作（只读语义写操作与 MFA 验码、登出端点除外）" />
    </template>
    <!-- 与 middleware.go 的 mfaStepUpGuard 挂载面（admin/business 两组级）
         及 readOnlyWriteRoutes 豁免清单同源。注意：证书配置/DNS 凭证/CA 提供商
         的「测试」会真实写入 DNS TXT 或自动申请 EAB——属写操作，需验证；仅
         OIDC 连接测试、配置预览/备份校验、证书解析、批量查询为读语义豁免。 -->
    <div class="info-note-bar"><span class="info-note-desc">开启后，以下操作需要 1 分钟内验证过 MFA（TOTP 同片不可重用，验证后 60 秒内的连续操作免重复弹码）。配置预览、备份校验、证书解析、批量证书状态查询与 OIDC 连接测试等只读语义操作不受影响。</span></div>
    <div class="mfa-scope-list">
      <div v-for="group in MFA_SCOPE_GROUPS" :key="group.title" class="mfa-scope-row">
        <div class="mfa-scope-title">{{ group.title }}</div>
        <div class="mfa-scope-items">{{ group.items.join('、') }}</div>
      </div>
    </div>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request, mfaAwareSuccess } from '@/utils/api'
import { formatBytes } from '@/utils/formatBytes'
import { useLogTailPolling } from '@/composables/useLogTailPolling'
import { useSettingsDraft, type AdminTlsCertInfo } from '@/composables/useSettingsDraft'
import { restartServiceWithFeedback } from '@/utils/restart'
import { adminTlsConfirmDisabled, adminTlsReusesSavedCert } from '@/utils/adminTlsGate'
import { formatDate } from '@/utils/date'
import { normalizeTrafficSampleN } from '@/utils/threatFlowRules'
import { shouldToastQuietPollError } from '@/utils/pollErrorToast'
import { displaySecurityEventsRetentionDays, displaySecurityEventsRowCap, displayThreatScreenMode, securityEventsWritePayload } from '@/utils/configValues'
import { CHINA_SITE_CHOICES, COUNTRY_SITE_CHOICES, coordsForSiteLocation, nearestSiteLocation } from '@/utils/siteLocation'
import { BACKUP_SECTIONS, importConfirmMessage, normalizeBackupSectionKeys } from '@/utils/backupSections'
import { createImportPreviewSession, importPreviewFingerprint, invalidateImportPreviews, type ImportPreviewSession } from '@/utils/importPreview'
import { createLatestReadSession } from '@/utils/viewAsyncState'
import { importFailureLines, importFailureReport } from '@/utils/importFailure'
import { importSummaryLabel } from '@/utils/importSummaryLabels'
import { MFA_SCOPE_GROUPS } from '@/utils/mfaScopeGroups'
import { Setting, InfoFilled, Check, View, Upload, Download, Timer, Lock, Document } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import AccessibleLink from '@/components/common/AccessibleLink.vue'
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
const appLogAutoRefresh = ref(true)
const appLogContainer = ref<HTMLElement | null>(null)
// 日志端点失败必须显性化：此前失败只写 console，模板继续以空内容渲染
// 「暂无日志」——排障最需要日志的时刻给出「没有日志」的错误结论。
const appLogError = ref(false)
const appLogEmptyText = computed(() => appLogError.value ? '日志加载失败（自动重试中）' : '暂无日志')

// （过度修复审查 REMOVE：appLogRequestSeq 已删——入口 loading 门 +
// appLogVisible 析取使其作为裁决条件永不为真。）
// 日志尾轮询收敛 useLogTailPolling 单源（hidden 暂停/单飞/滚底统一）。
const appLogTail = useLogTailPolling({
  interval: 3000,
  content: appLogContent,
  container: appLogContainer,
  isActive: () => appLogVisible.value,
  fetch: async () => {
    const res = await request.get<{ data?: { content?: string } }>('/system/logs', { silent: true })
    appLogError.value = false
    if (!appLogVisible.value) return null
    return res.data?.content || ''
  },
  onError: (error) => {
    appLogError.value = true
    console.error('Failed to fetch app logs:', error)
  },
})
const appLogLoading = appLogTail.loading

const fetchAppLogs = async (): Promise<void> => appLogTail.refresh()

const openAppLogDialog = (): void => {
  appLogError.value = false
  appLogVisible.value = true
}

const onAppLogOpened = (): void => {
  if (appLogAutoRefresh.value) appLogTail.start()
  else void appLogTail.refresh()
}

const onAppLogClosed = (): void => {
  appLogTail.stop()
  appLogContent.value = ''
  appLogError.value = false
}

watch(appLogAutoRefresh, (enabled) => {
  if (!appLogVisible.value) return
  if (enabled) appLogTail.start()
  else appLogTail.stop()
})

// onUnmounted 生命周期收尾移至 disposed/tlsProtocolFallbackTimer
// 声明之后（见下方 TLS 段尾），消除「引用其后声明的 let」的脆弱形态。

// 备份分类单源在 utils/backupSections（导出/自动备份/还原共用；后端
// configBackupSections 为其镜像，默认全选）。
const exportSections = ref<string[]>(BACKUP_SECTIONS.map((s) => s.key))
const exportDialogVisible = ref(false)
const toggleImportSection = (key: string): void => {
  const validation = importValidation.value
  // 预览无效时分类开关保持可用——剔除坏行分类后重校验
  // 即恢复可导入，「未选分类坏行不误拒」契约方才 UI 可达
  if (!validation) return
  if (validation.type === 'v1' && key !== 'rules') return
  importSections.value = importSections.value.includes(key)
    ? importSections.value.filter((k) => k !== key)
    : [...importSections.value, key]
  void revalidateImport()
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
  /** 行内 sections 列损坏（带外改写/旧版本遗留）时的说明：非空表示「范围未知」
   *  而不是「范围为空」——后端只在解析失败时给值，还原仍按包内 sections 走。 */
  sections_error?: string
  trigger_type: string
  message: string
  app_version: string
}

interface AutoBackupSettingsResponse {
  enabled: boolean
  frequency: string
  time: string
  day: number
  keep: number
  sections: string[]
  last_run: string | null
  last_success_at: string | null
  next_run_at: string | null
  catch_up_due: boolean
  backups: AutoBackupRow[]
}

const autoBackupVisible = ref(false)
const autoBackupLoading = ref(false)
// 读取失败/未完成时表单仍是默认值（enabled=false、daily/03:00/keep 7），
// 此时允许保存会用默认值覆盖服务端配置。
const autoBackupLoaded = ref(false)
// quiet 轮询失败 toast 节流水位（30s，对齐 usePollingErrorState 语义）
let lastAutoBackupErrorToastAt = 0
const autoBackupSaving = ref(false)
const autoBackupRunning = ref(false)
const autoBackupReadSession = createLatestReadSession()
const autoBackupForm = ref({ enabled: false, frequency: 'daily', time: '03:00', day: 1, keep: 7 })
// 频率切换必须重归 day：周视图上限 7、月视图上限 28（后端写侧门同值）。
// 月→周保留 20 会让下拉显示无匹配项的裸值，保存必 400「备份日期必须在 1-7 之间」。
watch(() => autoBackupForm.value.frequency, (frequency) => {
  const high = frequency === 'weekly' ? 7 : 28
  autoBackupForm.value.day = Math.min(Math.max(1, autoBackupForm.value.day), high)
})
const autoBackupSections = ref<string[]>(BACKUP_SECTIONS.map((s) => s.key))
const autoBackupRows = ref<AutoBackupRow[]>([])
// 立即备份只认最近一次成功读取/保存的服务端范围；未保存表单编辑不参与门控。
const autoBackupSavedSections = ref<string[]>([])
const autoBackupLastRun = ref<string | null>(null)
const autoBackupNextRunAt = ref<string | null>(null)
const autoBackupCatchUpDue = ref(false)
// 行级在途门（占位先于确认框，同 TaskMonitor/ClusterSettings 范式）：双击或
// 连点不同行不得叠出两个确认框、并发提交两次整库覆盖/删除。
const restoringBackupId = ref<number | null>(null)
const deletingBackupId = ref<number | null>(null)
const autoBackupActionBusy = computed(() => restoringBackupId.value !== null || deletingBackupId.value !== null)

const autoBackupLastRunLabel = computed(() => (autoBackupLastRun.value ? formatDate(autoBackupLastRun.value) : '—'))
const autoBackupNextRunLabel = computed<string | null>(() => {
  if (!autoBackupVisible.value || !autoBackupNextRunAt.value) return null
  const formatted = formatDate(autoBackupNextRunAt.value)
  if (!formatted) return null
  return autoBackupCatchUpDue.value ? `待补跑（${formatted}）` : formatted
})
const autoBackupCanRunNow = computed(() => autoBackupLoaded.value && !autoBackupLoading.value && autoBackupSavedSections.value.length > 0)
// 与导出按钮同口径：范围非空(users 恒有表,不存在不可还原形态)
const autoBackupSectionsValid = computed(() => autoBackupSections.value.length > 0)

const openAutoBackupDialog = (): void => {
  if (backupDisabled.value) return
  autoBackupNextRunAt.value = null
  autoBackupCatchUpDue.value = false
  autoBackupVisible.value = true
}

const applyAutoBackupStatus = (d: AutoBackupSettingsResponse): void => {
  autoBackupNextRunAt.value = d.next_run_at ?? null
  autoBackupCatchUpDue.value = d.catch_up_due === true
  autoBackupRows.value = d.backups || []
  // last_run 是调度水位线（off→on=now），不是执行事实；「上次成功备份」
  // 只认最近一次 success 行（last_success_at）。
  autoBackupLastRun.value = d.last_success_at ?? null
}

const fetchAutoBackup = async (quiet = false): Promise<void> => {
  if (quiet) {
    try {
      const res = await request.get<{ data: AutoBackupSettingsResponse }>('/settings/auto-backup', { silent: true })
      // quiet=true 来自「立即备份」轮询：只刷新列表与执行时间，不覆盖表单或加载门。
      applyAutoBackupStatus(res.data)
    } catch {
      console.error('Failed to poll auto-backup status')
      const now = Date.now()
      if (shouldToastQuietPollError(autoBackupLoaded.value, now, lastAutoBackupErrorToastAt)) {
        lastAutoBackupErrorToastAt = now
        ElMessage.error('自动备份状态刷新失败，将持续自动重试')
      }
    }
    return
  }

  await autoBackupReadSession.run(
    (signal) => request.get<{ data: AutoBackupSettingsResponse }>('/settings/auto-backup', { silent: true, signal }),
    {
      onStart: () => {
        autoBackupLoading.value = true
        autoBackupLoaded.value = false
      },
      onSuccess: (res) => {
        const d = res.data
        autoBackupForm.value = {
          enabled: d.enabled,
          frequency: d.frequency || 'daily',
          time: d.time || '03:00',
          day: d.day || 1,
          keep: d.keep || 7,
        }
        const loadedSections = d.sections?.length ? normalizeBackupSectionKeys(d.sections) : BACKUP_SECTIONS.map((s) => s.key)
        autoBackupSections.value = loadedSections
        autoBackupSavedSections.value = [...loadedSections]
        applyAutoBackupStatus(d)
        autoBackupLoaded.value = true
      },
      onError: () => {
        // silent 模式全局拦截器不会提示：只让当前会话披露失败。
        ElMessage.error('自动备份设置读取失败，请关闭弹框后重试；读取完成前无法保存')
      },
      onFinally: () => { autoBackupLoading.value = false },
    },
  )
}

const onAutoBackupClosed = (): void => {
  autoBackupReadSession.invalidate()
  autoBackupLoading.value = false
  autoBackupLoaded.value = false
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
  // 函数级纵深防御——角色/节点模式在弹框打开期间变化时不得仍发请求
  // （按钮禁用只是入口层，不能覆盖全部触发路径）。
  if (isReadOnly.value || !autoBackupSectionsValid.value || autoBackupSaving.value) return false
  if (!autoBackupLoaded.value || autoBackupLoading.value) {
    ElMessage.warning('自动备份设置尚未加载完成，暂不能保存')
    return false
  }
  autoBackupSaving.value = true
  try {
    await request.put('/settings/auto-backup', { ...autoBackupForm.value, sections: autoBackupSections.value })
    autoBackupSavedSections.value = [...autoBackupSections.value]
    autoBackupNextRunAt.value = null
    await fetchAutoBackup(true)
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
  if (isReadOnly.value || autoBackupRunning.value) return
  if (!autoBackupCanRunNow.value) {
    ElMessage.warning('自动备份设置尚未加载或已保存的备份范围为空，暂不能立即备份')
    return
  }
  // 异步契约：202 只代表已受理，不代表完成——记录基线 id，轮询
  // 备份列表直到出现本次新增的 manual 行（成功/失败都算落定）或 60s 超时。
  const baselineId = autoBackupRows.value.reduce((max, row) => Math.max(max, Number(row.id) || 0), 0)
  autoBackupRunning.value = true
  try {
    await request.post('/auto-backup/run')
    mfaAwareSuccess('备份已开始，完成后将自动刷新列表')
    const deadline = Date.now() + 60000
    let completed: AutoBackupRow | undefined
    // 组件卸载（切到其它设置页/离开系统设置）后必须终止轮询——原只以
    // 弹框可见为门，卸载后仍会每 2s 拉取最多 30 次并在其它页面弹结果 toast。
    while (!disposed && autoBackupVisible.value && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 2000))
      if (disposed) break
      await fetchAutoBackup(true)
      completed = autoBackupRows.value.find((row) => Number(row.id) > baselineId && row.trigger_type === 'manual')
      if (completed) break
    }
    if (disposed) return
    if (completed?.status === 'success') {
      mfaAwareSuccess('手动备份完成')
    } else if (completed) {
      ElMessage.error(completed.message || '手动备份失败')
    } else if (!completed && autoBackupVisible.value) {
      ElMessage.warning('60 秒内未检测到本次备份结果，任务可能仍在执行；请稍后刷新列表查看')
    }
  } catch {
    // 全局拦截器已提示（409=已有备份在执行）
  } finally {
    autoBackupRunning.value = false
  }
}

// 备份大小：零值占位 '-'，格式化走 formatBytes 单一事实源
const formatBackupSize = (bytes: number): string => (!bytes || bytes <= 0 ? '-' : formatBytes(bytes))

// 内容列只显备份范围；hover 明细=各表行数摘要+触发方式（2026-09-21 用户裁定）
const autoBackupScopeText = (row: AutoBackupRow): string => {
  // 范围损坏 ≠ 范围为空：行内 sections 列解析失败时显示「-」会被读成「不含任何
  // 分类的备份」而放弃一次内容完整的还原（还原按包内 sections 走，不读该列）。
  if (row.sections_error) return '范围损坏（见日志）'
  const labels = normalizeBackupSectionKeys(row.sections || []).map((k) => BACKUP_SECTIONS.find((s) => s.key === k)?.label || k)
  return labels.length > 0 ? labels.join('、') : '-'
}
const autoBackupDetailTip = (row: AutoBackupRow): string => {
  const trigger = row.trigger_type === 'manual' ? '手动' : '定时'
  return row.message ? `${row.message}（${trigger}）` : `${autoBackupScopeText(row)}（${trigger}）`
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
  // 写动作函数级守卫（还原会覆盖配置，仅主节点管理员可执行）+ 行动作在途门
  if (backupDisabled.value || autoBackupActionBusy.value) return
  restoringBackupId.value = row.id
  try {
    const scope = autoBackupScopeText(row)
    try {
      await ElMessageBox.confirm(
        `将使用备份「${row.filename}」覆盖该备份包含的分类：${scope}；未包含的分类保持现状。此操作不可撤销。确认还原？`,
        '还原配置',
        { type: 'warning', confirmButtonText: '确认还原', cancelButtonText: '取消' },
      )
    } catch {
      return
    }
    try {
      // 还原走导入 core(config_backup.go importConfigBackupCore),响应同样携带
      // data.warnings 与 data.disabled_conflicts——与导入弹框同口径展示：冲突
      // 自动禁用的规则若无提示，业务流量会在「还原成功」后静默切走。
      const res = await request.post<{ message?: string; data?: { warnings?: string[]; disabled_conflicts?: DisabledRuleConflict[] } }>(`/auto-backup/${row.id}/restore`, undefined, { timeout: 0 })
      autoBackupVisible.value = false
      const warnings = res.data?.warnings ?? []
      const disabledConflicts = res.data?.disabled_conflicts ?? []
      const resultLines = [
        res.message || '配置还原成功',
        ...warnings,
        ...(disabledConflicts.length > 0 ? [`冲突置为禁用：${disabledConflicts.length} 条`] : []),
        ...disabledConflicts.map((conflict) => formatImportConflict(conflict, true)),
      ]
      await ElMessageBox.alert(
        h('div', resultLines.map((line) => h('div', line))),
        '还原完成',
        {
          confirmButtonText: '刷新页面',
          type: warnings.length > 0 || disabledConflicts.length > 0 ? 'warning' : 'success',
          showClose: false,
          closeOnClickModal: false,
          closeOnPressEscape: false,
        },
      )
      window.location.reload()
    } catch (error: unknown) {
      // 全局拦截器已弹 message toast；失败响应携带的文件面判决（回退失败=文件与
      // 版本记录可能分裂 / 提交结果不确定=需人工核对）必须展示——回滚只覆盖库侧，
      // 回退失败或提交不确定时执行面可能已与库分叉，不得按「已回滚即无需动作」处理。
      await showImportFailure(error, '配置还原失败', '还原失败')
    }
  } finally {
    restoringBackupId.value = null
  }
}

const deleteAutoBackup = async (row: AutoBackupRow): Promise<void> => {
  // 写动作函数级守卫 + 行动作在途门（双击不得叠两个确认框/两次 DELETE）
  if (backupDisabled.value || autoBackupActionBusy.value) return
  deletingBackupId.value = row.id
  try {
    try {
      await ElMessageBox.confirm(`确认删除备份「${row.filename}」？删除后不可恢复。`, '删除备份', {
        type: 'warning',
        confirmButtonText: '删除',
        cancelButtonText: '取消',
      })
    } catch {
      return
    }
    await request.delete(`/auto-backup/${row.id}`)
    mfaAwareSuccess('备份已删除')
    // quiet=true：删除只影响列表——非 quiet 会用服务端值整体覆盖上方表单，
    // 把用户未保存的频率/时间/保留份数/范围静默回退（同保存与立即备份轮询口径）。
    await fetchAutoBackup(true)
  } catch {
    // 全局拦截器已提示
  } finally {
    deletingBackupId.value = null
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
const IMPORT_MAX_BYTES = 128 * 1024 * 1024
const importFileContent = ref<string | Blob>('')
const importValidation = ref<ImportValidation | null>(null)
const importValidating = ref(false)
// 0 个分类 = 无可导内容。原实现 revalidateImport 早退，弹框却继续显示
// 上一次选择的校验摘要/冲突，按钮也可点（点了才提示）——预览与按钮必须同门。
const importPreviewSelected = computed<boolean>(() => importSections.value.length > 0)
const importInput = ref<HTMLInputElement | null>(null)
let importValidationSeq = 0
// 预览会话：按「内容指纹 + 所选分类」复用上一次校验结果，分类连续切换时取消
// 上一轮在途请求——勾选分类不再重传整份备份（上限 128MB）。
let importPreviewSession: ImportPreviewSession<ImportValidation> | null = null

// 摘要标签单源 utils/importSummaryLabels（后端表集完整覆盖由跨栈测试钉住）——
// 原页内表只覆盖 12 个键，其余按原键回退，用户会在预览里看到后端表名。

const conflictIdentifier = (conflict: { name?: string; caddy_id?: string }): string => conflict.name || conflict.caddy_id || '未命名规则'

const formatImportConflict = (conflict: DisabledRuleConflict, alreadyDisabled = false): string => {
  const opponents = conflict.conflicts_with
    .map((opponent) => `${conflictIdentifier(opponent)}（${opponent.reason}）`)
    .join('；')
  return `规则 ${conflictIdentifier(conflict)} ${alreadyDisabled ? '已禁用' : '将被禁用'}：与${opponents}冲突`
}

// showImportFailure 导入/还原失败响应的处置结果弹框。
//
// 全局拦截器只弹 message toast（阶段 + 真实错误），而失败分支的事实披露在
// data.warnings：规则库文件面三态判决（已回退一致/回退失败可能分裂/提交结果
// 不确定的人工核对指引）与软跳过/归一化清单。丢在 toast 之外等于只有审计库
// 可见——运维会按「已回滚、无需动作」处理，而 WAF 执行面可能已与库分裂。
// 无附加事实时不重复弹框（toast 已覆盖）。
const showImportFailure = async (error: unknown, fallbackMessage: string, title: string): Promise<void> => {
  const report = importFailureReport(error, fallbackMessage)
  if (report.warnings.length === 0 && report.conflictCount === 0) return
  const lines = importFailureLines(report)
  try {
    await ElMessageBox.alert(
      h('div', lines.map((line) => h('div', line))),
      title,
      { confirmButtonText: '知道了', type: 'error' },
    )
  } catch {
    // 弹框被关闭（X/ESC）不影响任何状态：失败已由后端回滚或文件面判决披露。
  }
}

const triggerImport = (): void => {
  if (backupDisabled.value) return
  importValidationSeq++
  importValidating.value = false
  importPreviewSession?.dispose()
  importPreviewSession = null
  // 预览结果依赖打开弹框时的库状态（冲突/悬挂告警/策略引用都会随配置变化），
  // 故每次打开都清空跨会话缓存——否则同一份备份在配置改变后仍返回旧预览。
  invalidateImportPreviews()
  importFileName.value = ''
  importFileContent.value = ''
  importFileIsLbbak.value = false
  importSections.value = []
  importValidation.value = null
  importDialogVisible.value = true
}

const onImportDialogClosed = (): void => {
  importValidationSeq++
  importValidating.value = false
  // 关闭即取消在途预览上传并丢弃会话（缓存按内容指纹留在会话层之外）
  importPreviewSession?.dispose()
  importPreviewSession = null
  // 关闭即释放备份内容(lbbak Blob/JSON 字符串),不驻留至下次选择
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
  // 新文件一选定即作废旧内容；任何后续拒绝分支都不能让旧字节配新文件名。
  importFileContent.value = ''
  importFileIsLbbak.value = false
  importSections.value = []
  importValidation.value = null
  importValidating.value = false
  if (file.size > IMPORT_MAX_BYTES) {
    // 先于全量读入内存拒绝(后端 413 同口径),防超大文件撑爆标签页
    importValidation.value = { valid: false, error: '备份文件不能超过 128MB', disabled_conflicts: [] }
    return
  }
  importValidating.value = true
  try {
    // v2.3.0 lbbak 为二进制 tar.gz——按魔数选择读取与提交方式。
    // 先剥 UTF-8 BOM 再做魔数检测（与后端 config_backup.go
    // 同口径——BOM \xef\xbb\xbf 与 gzip 魔数不冲突，剥 BOM 必须在魔数检测之前），
    // 否则带 BOM 的 lbbak 前端误判为 JSON、带 BOM 的 JSON 提交体解析失败
    const bomProbe = new Uint8Array(await file.slice(0, 3).arrayBuffer())
    const bomLen = bomProbe[0] === 0xef && bomProbe[1] === 0xbb && bomProbe[2] === 0xbf ? 3 : 0
    const head = new Uint8Array(await file.slice(bomLen, bomLen + 2).arrayBuffer())
    const isLbbak = head[0] === 0x1f && head[1] === 0x8b
    importFileIsLbbak.value = isLbbak
    if (isLbbak) {
      importFileContent.value = file.slice(bomLen)
    } else {
      importFileContent.value = await file.slice(bomLen).text()
    }
    // 为本次备份建立预览会话（内容指纹只在换文件时算一次；首尾采样，
    // 不把整份 Blob 复制成第二个 ArrayBuffer）
    const fingerprint = await importPreviewFingerprint(importFileContent.value)
    if (validationSeq !== importValidationSeq) return
    importPreviewSession?.dispose()
    importPreviewSession = createImportPreviewSession<ImportValidation>({
      fingerprint,
      send: (sections, signal) => postImportValidation(sections, signal),
    })
    // 预览请求携带分类选择（初始=全选，与下方 V2 默认选择一致；
    // 备份不消费该参数）——预览与导入同参，预览结果按所选分类过滤
    const preview = await importPreviewSession.validate(BACKUP_SECTIONS.map((sec) => sec.key))
    const data = preview.value
    if (validationSeq !== importValidationSeq) return
    importValidation.value = data ?? null
    // 仅负载规则(锁定);V2 默认全选。无 WAF 规则库文件的备份不整类剔除
    // 「安全防护」(该分类同时含策略表)——后端兜底:跳过规则库版本记录表,
    // 并在响应 warnings 中说明(下方结果弹框展示)
    if (data?.type === 'v1') {
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

// 预览校验请求统一构造——携带当前分类选择（后端
// ValidateConfigImport 在校验前按 sections 过滤未选分类的表，坏行不误拒，
// summary/warnings 亦只含所选分类）。分类选择一律经 ?sections= query，请求体
// 保持原始字节：v3 纯 JSON 的体内 sections 参与校验和，改写会被判成「已篡改」。
// 请求可被 signal 取消：分类连续切换时旧轮次的上传不再占用带宽。
const postImportValidation = async (sections: readonly string[], signal: AbortSignal): Promise<ImportValidation> => {
  const isLbbak = importFileIsLbbak.value
  const endpoint = `/config/import/validate?sections=${encodeURIComponent(sections.join(','))}`
  const body: string | Blob = importFileContent.value
  const res = await request.post<{ data: ImportValidation }>(endpoint, body, {
    headers: { 'Content-Type': isLbbak ? 'application/octet-stream' : 'application/json' },
    timeout: 0,
    signal,
  })
  return res.data
}

// 分类切换后按所选分类重校验——预览结果始终反映当前选择（与导入同参）。
// 面板保持显示（不闪 loading）；同一份备份的同一分类集合直接命中会话缓存，
// 不再重传备份；并发切换经 importValidationSeq 只取最新响应（在途请求同时被
// 会话层取消）。
const revalidateImport = async (): Promise<void> => {
  const sections = importSections.value
  // 校验不消费分类（仅负载规则）；空选择无可导内容（确认时拦截）——不重发
  if (importValidation.value?.type === 'v1' || sections.length === 0) return
  if (!importFileContent.value || !importPreviewSession) return
  const session = importPreviewSession
  const validationSeq = ++importValidationSeq
  try {
    const data = (await session.validate(sections)).value
    if (validationSeq !== importValidationSeq) return
    importValidation.value = data ?? null
  } catch {
    if (validationSeq === importValidationSeq) {
      importValidation.value = { valid: false, error: '校验请求失败，请重试', disabled_conflicts: [] }
    }
  }
}

const confirmImport = async (): Promise<void> => {
  // 确认按钮的 isReadOnly 门之外，函数级再守一道（角色/节点模式在弹框
  // 打开期间变化时仍可能触发点击）。
  if (isReadOnly.value) return
  const validation = importValidation.value
  if (!validation?.valid || importing.value) return
  // 未选分类先于最终确认弹框拦截（路径强制 ['rules']，不可达此分支）
  if (importSections.value.length === 0) { ElMessage.warning('请至少选择一个导入分类'); return }
  // 全量导入是全仓破坏性最强的操作（覆盖规则、用户、密钥、证书任务与全部凭证），
  // 此前是唯一缺二次确认弹框的破坏性操作——「确认导入」按钮与警示文案不足以兜底误点。
  try {
    // 文案单源在 utils/backupSections（V1 仅覆盖规则及其策略绑定；V2 全量含
    // 节点拓扑）——预览与最终确认必须同一覆盖面口径。
    await ElMessageBox.confirm(
      importConfirmMessage(validation.type, importSections.value),
      '最终确认',
      { type: 'warning', confirmButtonText: '确认导入', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  importing.value = true
  try {
    let endpoint = validation.type === 'v1' ? '/config/import/v1' : '/config/import'
    // 分类选择一律经 query（v1 路径忽略该参数）：v3 纯 JSON 的体内 sections
    // 参与校验和，改写会被判成「已篡改」，请求体恒为原始字节。
    if (validation.type !== 'v1') {
      endpoint = `/config/import?sections=${encodeURIComponent(importSections.value.join(','))}`
    }
    const importBody: string | Blob = importFileContent.value
    const res = await request.post<ImportResponse>(endpoint, importBody, {
      headers: { 'Content-Type': importFileIsLbbak.value ? 'application/octet-stream' : 'application/json' },
      timeout: 0,
    })
    importDialogVisible.value = false
    const disabledConflicts = res.data?.disabled_conflicts ?? []
    // 后端 data.warnings(操作账户替换/会话吊销/ACME 悬挂/规则库元数据
    // 跳过)此前被丢弃——与冲突同级展示,非空时结果至少 warning 级
    const warnings = res.data?.warnings ?? []
    const resultLines = [
      res.message || '配置导入成功',
      ...warnings,
      // 无冲突时不占位——「冲突置为禁用：0 条」恒显属噪音行
      ...(disabledConflicts.length > 0 ? [`冲突置为禁用：${disabledConflicts.length} 条`] : []),
      ...disabledConflicts.map((conflict) => formatImportConflict(conflict)),
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
    // 全局拦截器只弹 message toast；失败响应的 data.warnings（规则库文件面
    // 三态判决/提交不确定的人工核对指引/软跳过清单）与冲突明细必须同框展示，
    // 与成功路径同口径。
    await showImportFailure(error, '配置导入失败', '导入失败')
  } finally {
    importing.value = false
  }
}

// 本卡读写的配置键（父级传入完整配置对象；此处只声明本卡可能访问的字段，
// 缺失键由下方 computed 归一默认值——键本身已在 GlobalConfigData 声明）。
interface BasicSettingsConfig {
  log_level: string
  task_log_size_mb: number
  audit_log_size_mb: number
  runtime_log_size_mb: number
  audit_retention_months: number
  // 威胁大屏本站坐标（v3；父级未下发时为 undefined，由下方 computed 归一为 0）
  server_map_lat?: number
  threat_screen_mode?: string
  security_events_retention_days?: number
  security_events_row_cap?: number
  threat_traffic_sample_n?: number
  server_map_lon?: number
  jwt_expire_minutes: number
  timezone: string
  mfa_write_guard: boolean
  mfa_lockout_enabled: boolean
  github_proxy_url?: string
  has_github_token?: boolean
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

interface AdminTlsForm {
  mode: string
  certFile: File | null
  keyFile: File | null
  certInfo: AdminTlsCertInfo | null
  inspecting: boolean
  // /admin-tls/inspect 失败原因：弹框内必须可见（原实现只靠瞬态 toast，
  // 弹框只剩文件名 + 灰掉的「确定」，解析中/解析失败/配对缺失无法区分）
  inspectError: string
}

const mfaScopeVisible = ref(false)
// MFA「受保护操作范围」清单单源在 utils/mfaScopeGroups（与 middleware.go 的
// admin/business 组写路由逐族对齐；新增写端点族必须同步入列）。

const settings = defineModel<BasicSettingsConfig>('settings', { required: true })
// 时区选项目录（常用项）——写侧接受任意 IANA 时区名（后端 time.LoadLocation
// 校验），因此「启用 ∪ 当前值」：API/备份写入的非枚举值以自定义项原值回显，
// 否则下拉空白、用户一改选就无法再改回该值。
const PRESET_TIMEZONES: readonly { label: string; value: string }[] = [
  { label: 'Asia/Shanghai (UTC+8)', value: 'Asia/Shanghai' },
  { label: 'Asia/Hong_Kong (UTC+8)', value: 'Asia/Hong_Kong' },
  { label: 'Asia/Tokyo (UTC+9)', value: 'Asia/Tokyo' },
  { label: 'Asia/Singapore (UTC+8)', value: 'Asia/Singapore' },
  { label: 'Asia/Seoul (UTC+9)', value: 'Asia/Seoul' },
  { label: 'Asia/Bangkok (UTC+7)', value: 'Asia/Bangkok' },
  { label: 'Asia/Kolkata (UTC+5:30)', value: 'Asia/Kolkata' },
  { label: 'Asia/Dubai (UTC+4)', value: 'Asia/Dubai' },
  { label: 'Europe/London (UTC+0，夏令时 UTC+1)', value: 'Europe/London' },
  { label: 'Europe/Paris (UTC+1，夏令时 UTC+2)', value: 'Europe/Paris' },
  { label: 'Europe/Berlin (UTC+1，夏令时 UTC+2)', value: 'Europe/Berlin' },
  { label: 'Europe/Moscow (UTC+3)', value: 'Europe/Moscow' },
  { label: 'America/New_York (UTC-5，夏令时 UTC-4)', value: 'America/New_York' },
  { label: 'America/Chicago (UTC-6，夏令时 UTC-5)', value: 'America/Chicago' },
  { label: 'America/Denver (UTC-7，夏令时 UTC-6)', value: 'America/Denver' },
  { label: 'America/Los_Angeles (UTC-8，夏令时 UTC-7)', value: 'America/Los_Angeles' },
  { label: 'America/Sao_Paulo (UTC-3)', value: 'America/Sao_Paulo' },
  { label: 'Australia/Sydney (UTC+10，夏令时 UTC+11)', value: 'Australia/Sydney' },
  { label: 'UTC', value: 'UTC' },
]
const timezoneOptions = computed(() => {
  const options = PRESET_TIMEZONES.map((item) => ({ ...item }))
  const current = settings.value.timezone
  if (current && !options.some((item) => item.value === current)) {
    options.push({ label: `${current}（自定义）`, value: current })
  }
  return options
})
// 时区前置校验：allow-create 允许任意输入，一次拼写错误会让整卡保存被后端
// （time.LoadLocation）400 拒绝，连带日志级别/保留策略/大屏坐标等无关项失败。
// 运行时 Intl 与 Go 共用 IANA 库，本地即可定位到字段。
const timezoneError = (value: string): string => {
  const tz = value.trim()
  if (!tz) return '时区不能为空'
  try {
    // 只借它做校验：构造即抛 RangeError 表示库中无此时区。
    new Intl.DateTimeFormat(undefined, { timeZone: tz })
    return ''
  } catch {
    return `无效的时区：${tz}`
  }
}
// 父级 /config 加载完成前禁止保存：表单此刻仍是默认值。
const props = defineProps<{ configLoaded: boolean }>()
const emit = defineEmits<{
  (e: 'save'): void
}>()

// 读取失败不得把默认值当可写值：原 getter 未加载时回退
// 默认代理、保存 payload 恒带该键——一次 /config 抖动 + 任一保存 = 把用户已选
// 的 AxisNow 静默改回默认。现以 githubProxyLoaded 门控编辑与提交。
// 加载态复用父级整包 /config（Settings.vue applyBasicKeys 已合并
// github_proxy_url / has_github_token）：卡片不再自拉第二份 /config，也不需
// 独立 seq 竞态守卫（父级已有 settingsRequestSeq 单一通道）。
const githubProxyLoaded = computed(() => props.configLoaded)
const githubProxyUrl = computed<string>({
  get: () => {
    if (!githubProxyLoaded.value) return ''
    return settings.value.github_proxy_url || DEFAULT_GITHUB_PROXY_URL
  },
  set: (value: string) => {
    settings.value.github_proxy_url = value
  },
})

// GitHub 令牌三态：省略=保持、显式空串（清除钮）=撤销、非空=覆盖；has_github_token 仅显隐占位
// 令牌输入与清除标记、安全事件 dirty、管理面板 HTTPS 暂存态统一由设置草稿
// （模块单例）持有——切分页重挂不丢（见 useSettingsDraft）。
const {
  githubTokenInput,
  githubTokenClearPending,
  securityEventsRetentionDirty,
  securityEventsRowCapDirty,
  adminTls,
  adminTlsSaved,
  adminTlsHasCert,
  adminTlsCertError,
  adminTlsUnavailable,
  stagedAdminTlsCert,
} = useSettingsDraft()
const clearGithubToken = () => {
  githubTokenInput.value = ''
  githubTokenClearPending.value = true
}

const saving = ref(false)
// 保存中冻结整卡表单：保存成功由父级重新取 /config 回填整卡，在途时的编辑
// 会被回填静默覆盖（且成功提示不披露被丢弃的字段）。
const formFrozen = computed(() => isReadOnly.value || saving.value)
// 大屏本站坐标：地点选择（中国城市/海外国家）→ 经纬度；替代按公网 IP
// 归属地自动检测（常落到省会/国家质心，无法精确到城市）。
const siteLocationKey = ref('')
const applySiteLocation = (key: string): void => {
  if (!key) {
    settings.value.server_map_lat = 0
    settings.value.server_map_lon = 0
    return
  }
  const coords = coordsForSiteLocation(key)
  if (!coords) {
    ElMessage.error('地点数据缺失，请重新选择')
    siteLocationKey.value = nearestSiteLocation(settings.value.server_map_lat ?? 0, settings.value.server_map_lon ?? 0)
    return
  }
  settings.value.server_map_lat = coords.lat
  settings.value.server_map_lon = coords.lon
}
watch(
  () => [settings.value.server_map_lat, settings.value.server_map_lon] as const,
  ([lat, lon]) => {
    const nearest = nearestSiteLocation(lat ?? 0, lon ?? 0)
    // 已有坐标回显最近地点；用户刚选择的地点坐标一致时不会被覆盖。
    if (nearest && siteLocationKey.value !== nearest && coordsForSiteLocation(siteLocationKey.value)?.lat !== lat) {
      siteLocationKey.value = nearest
    }
    if (!nearest) siteLocationKey.value = ''
  },
  { immediate: true },
)
// v2.3.8 威胁大屏中央视觉模式（map/globe）：直接写回父级共享模型——切分页
// 重挂不回退（原组件内 ref 卸载即复位），与同卡直绑 settings 的字段同口径。
// 展示归一由单源 helper 承担（库值非法时的回显口径不在此重复实现）。
const threatScreenMode = computed<'map' | 'globe'>({
  get: () => displayThreatScreenMode(settings.value.threat_screen_mode),
  set: (value) => {
    settings.value.threat_screen_mode = value
  },
})
// 安全事件滚动保留：展示归一 90 天 / 1,000,000 行；库值 0=自动 的哨兵保持不变。
// 编辑值写回父级共享模型（切分页不丢），dirty 标记只在用户实际编辑时置位，
// 保存载荷按 dirty 携带字段（见 utils/configValues securityEventsWritePayload），
// 避免把展示归一值物化进库。
const seRetentionDays = computed<number>({
  get: () => displaySecurityEventsRetentionDays(settings.value.security_events_retention_days),
  set: (value) => {
    settings.value.security_events_retention_days = value
    securityEventsRetentionDirty.value = true
  },
})
const seRowCap = computed<number>({
  get: () => displaySecurityEventsRowCap(settings.value.security_events_row_cap),
  set: (value) => {
    settings.value.security_events_row_cap = value
    securityEventsRowCapDirty.value = true
  },
})
const trafficSampleN = computed<number>({
  get: () => normalizeTrafficSampleN(settings.value.threat_traffic_sample_n),
  set: (value) => {
    settings.value.threat_traffic_sample_n = value
  },
})
// 证书弹框表单（文件选择/校验）是临时态：随弹框关闭销毁，不随分页切换保留；
// 已确认的暂存材料（stagedAdminTlsCert）在设置草稿里存活。
const adminTlsForm = ref<AdminTlsForm>({ mode: 'selfsigned', certFile: null, keyFile: null, certInfo: null, inspecting: false, inspectError: '' })
const adminTlsDialogVisible = ref(false)
// 隐藏文件选择器代理（弹框 destroy-on-close，input 置于弹框外）
const tlsCertFileInput = ref<HTMLInputElement | null>(null)
const tlsKeyFileInput = ref<HTMLInputElement | null>(null)
const pickTlsFile = (kind: 'cert' | 'key'): void => {
  ;(kind === 'cert' ? tlsCertFileInput.value : tlsKeyFileInput.value)?.click()
}

// 存量 upload 证书损坏（含带外改库/旧版本导入形态）：以已保存的 mode 判定，
// 不受弹框内未提交的切换影响。
const adminTlsCertBroken = computed(() => adminTlsSaved.value.mode === 'upload' && adminTlsCertError.value !== '')
// 确认门判据单源 utils/adminTlsGate：已保存的上传证书可沿用（后端在未携带
// cert_file/key_file 时保留库内材料），保存成功后 staged 证书清空不得导致
// 「关闭强制加密 → 再开启」必须重传文件。
const adminTlsStoredCertState = computed(() => ({
  savedMode: adminTlsSaved.value.mode,
  hasSavedCert: adminTlsHasCert.value,
  certError: adminTlsCertError.value,
}))
const adminTlsReuseSaved = computed(() => adminTlsReusesSavedCert(adminTlsStoredCertState.value, adminTlsForm.value))
// 只选了一半材料时给出可见原因：inspecting 只在两个文件齐备时启动，缺一个时
// 弹框原本只有文件名 + 灰掉的「确定」，用户无法区分「还没选全」与「解析失败」。
const adminTlsMissingPairHint = computed(() => {
  if (adminTlsForm.value.mode !== 'upload') return ''
  const hasCert = adminTlsForm.value.certFile !== null
  const hasKey = adminTlsForm.value.keyFile !== null
  if (hasCert === hasKey) return ''
  return hasCert ? '已选择证书文件，还需选择私钥文件才能解析证书' : '已选择私钥文件，还需选择证书文件才能解析证书'
})
const adminTlsConfirmBlocked = computed(() => adminTlsConfirmDisabled(adminTlsStoredCertState.value, adminTlsForm.value))
const adminTlsDirty = computed(() => {
  if (adminTls.value.enabled !== adminTlsSaved.value.enabled) return true
  if (!adminTls.value.enabled) return false
  return adminTls.value.mode !== adminTlsSaved.value.mode || stagedAdminTlsCert.value !== null
})

// /admin-tls 读取失败不再静默吞错——开关禁用直到加载成功，
// 避免长期以默认关闭态误导「HTTPS 已关闭」。
const adminTlsLoaded = ref(false)
// 读取失败必须显性化——原仅 console.warn，
// 开关永久灰置且页面不解释（用户只能整页刷新碰运气）。内联错误 + 重试入口。
const adminTlsLoadFailed = ref(false)
const loadAdminTls = async () => {
  adminTlsLoadFailed.value = false
  adminTlsUnavailable.value = false
  try {
    const res = await request.get('/admin-tls')
    if (res.data) {
      const saved = { enabled: res.data.enabled, mode: res.data.mode || 'selfsigned' }
      // 暂存判定必须在写入新 saved 之前取：写入后 adminTls 与 saved 的差异会把
      // 「服务端状态刚变化」误判成「用户暂存」（首次进入且服务端已启用时开关
      // 会错显关闭）。有暂存时保留用户的编辑与暂存证书，无暂存时以服务端为准
      // （暂存证书只在保存成功后清空）。
      const wasStaged = adminTlsDirty.value
      adminTlsSaved.value = saved
      if (!wasStaged) adminTls.value = { ...saved }
      // 后端降级读（config_unavailable）：enabled/mode 是「未启用/自签名」的
      // 降级值而非真实状态。此时不得视为加载成功（开关保持禁用），证书派生
      // 态也不据此刷新——降级载荷不含可信的证书信息。
      adminTlsUnavailable.value = res.data.config_unavailable === true
      adminTlsLoaded.value = !adminTlsUnavailable.value
      if (!adminTlsUnavailable.value) {
        adminTlsHasCert.value = res.data.cert_info != null || saved.mode === 'selfsigned'
        adminTlsCertError.value = res.data.cert_info_error || ''
      }
    }
  } catch {
    adminTlsLoadFailed.value = true
    console.warn('管理 TLS 配置读取失败，强制加密开关暂不可用')
  }
}
const retryLoadAdminTls = (): void => { void loadAdminTls() }

const openAdminTlsDialog = () => {
  // 上传/校验走 admin-tls/inspect（后端写语义端点，非只读豁免）
  if (isReadOnly.value) return
  adminTlsForm.value = {
    mode: adminTls.value.mode === 'upload' ? 'upload' : 'selfsigned',
    certFile: stagedAdminTlsCert.value?.certFile ?? null,
    keyFile: stagedAdminTlsCert.value?.keyFile ?? null,
    certInfo: stagedAdminTlsCert.value?.certInfo ?? null,
    inspecting: false,
    inspectError: '',
  }
  adminTlsDialogVisible.value = true
}

const onAdminTlsDialogClose = () => {
  tlsInspectSeq++
  adminTlsForm.value = { mode: 'selfsigned', certFile: null, keyFile: null, certInfo: null, inspecting: false, inspectError: '' }
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

// 组件卸载收尾引用上述 tls 态与 disposed，故置于声明之后
// （原位于 appLogTimer watch 附近、引用其后声明的 let——当前安全但形态脆弱）。
onUnmounted(() => {
  disposed = true
  autoBackupReadSession.invalidate()
  appLogTail.stop()
  // 卸载即取消在途的预览上传（组件销毁后响应无处落地）
  importPreviewSession?.dispose()
  importPreviewSession = null
  if (tlsProtocolFallbackTimer) clearTimeout(tlsProtocolFallbackTimer)
  tlsProtocolFallbackTimer = null
})

const onTlsFile = async (e: Event, kind: 'cert' | 'key') => {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  // 读完即复位（与导入选择器同口径）——否则再次选择同一路径/同名文件
  // 不触发 change，换盘内容或重试同一证书时弹框停在旧状态。
  input.value = ''
  if (!file) return
  if (kind === 'cert') adminTlsForm.value.certFile = file
  else adminTlsForm.value.keyFile = file
  adminTlsForm.value.certInfo = null
  adminTlsForm.value.inspectError = ''
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
        // 解析成功但无证书信息：同样要给出可见原因，避免「确定」无声变灰
        adminTlsForm.value.inspectError = adminTlsForm.value.certInfo ? '' : '未能从所选文件解析出证书信息，请确认文件内容完整'
      }
    } catch {
      if (seq === tlsInspectSeq) {
        adminTlsForm.value.certInfo = null
        // 具体原因（不匹配/损坏）由后端 message 经全局拦截器 toast 呈现；此处给出
        // 弹框内常驻解释 +「重新选择」动作，用户不必依赖一闪而过的 toast 试错。
        adminTlsForm.value.inspectError = '证书解析失败：证书与私钥可能不匹配，或文件已损坏／不是 PEM 格式；请重新选择两个文件'
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
  // 停留当前页，弹窗给出可点击的目标链接，由用户就绪后自行访问。
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
    // 实现明确「不盲跳」（见上），文案不得再承诺自动跳转
    if (!disposed) ElMessage.warning(`请手动访问新地址：${target}`)
  }, 15000)
}

// 弹窗「确定」仅暂存证书选择，不发请求；随底部「保存」统一提交
const confirmAdminTls = () => {
  if (adminTlsConfirmBlocked.value) return
  const { mode, certFile, keyFile, certInfo } = adminTlsForm.value
  tlsDialogFromToggle = false
  adminTls.value.mode = mode
  // 沿用库内证书时保持 null：保存载荷只发 enabled+mode，证书材料由后端保留
  stagedAdminTlsCert.value = mode === 'upload' && certFile && keyFile && certInfo
    ? { certFile, keyFile, certInfo }
    : null
  adminTlsDialogVisible.value = false
}

loadAdminTls()
const restarting = ref(false)

const handleRestart = async () => {
  if (isReadOnly.value || restarting.value) return
  restarting.value = true
  // 确认/重启/就绪轮询流程单源（utils/restart），与漂移恢复横幅同一实现
  const result = await restartServiceWithFeedback({
    confirmMessage: '重启期间服务短暂不可用，容器将自动拉起，就绪后自动刷新页面。确认重启？',
    confirmTitle: '重启服务',
    successMessage: '服务正在重启，就绪后自动刷新页面',
    isDisposed: () => disposed,
  })
  if (result !== 'reloaded') restarting.value = false
}

const handleSave = async () => {
  if (!props.configLoaded) {
    ElMessage.warning('配置尚未加载完成，暂不能保存')
    return
  }
  if (isReadOnly.value) return
  if (saving.value) return
  const tlsPending = adminTlsDirty.value
  if (tlsPending && adminTls.value.enabled && adminTls.value.mode === 'upload' && !stagedAdminTlsCert.value && !adminTlsHasCert.value) {
    ElMessage.warning('请先在「配置证书」中选择并校验上传证书')
    return
  }
  const tzError = timezoneError(settings.value.timezone)
  if (tzError) {
    ElMessage.warning(`${tzError}（请从列表选择，或输入 IANA 格式时区名，如 Asia/Shanghai）`)
    return
  }
  settings.value.timezone = settings.value.timezone.trim()
  saving.value = true
  try {
    const payload = {
      log_level: settings.value.log_level,
      task_log_size_mb: settings.value.task_log_size_mb,
      audit_log_size_mb: settings.value.audit_log_size_mb,
      runtime_log_size_mb: settings.value.runtime_log_size_mb,
      audit_retention_months: settings.value.audit_retention_months,
      jwt_expire_minutes: settings.value.jwt_expire_minutes,
      timezone: settings.value.timezone,
      server_map_lat: settings.value.server_map_lat ?? 0,
      server_map_lon: settings.value.server_map_lon ?? 0,
      threat_screen_mode: threatScreenMode.value,
      // 仅在用户实际编辑过时才提交保留/行数上限（未编辑省略键，
      // 后端 COALESCE 保持现值——库值 0=自动 不被展示归一值物化）。
      ...securityEventsWritePayload({
        retentionDays: seRetentionDays.value,
        retentionDirty: securityEventsRetentionDirty.value,
        rowCap: seRowCap.value,
        rowCapDirty: securityEventsRowCapDirty.value,
      }),
      threat_traffic_sample_n: trafficSampleN.value,
      mfa_write_guard: settings.value.mfa_write_guard,
      mfa_lockout_enabled: settings.value.mfa_lockout_enabled,
      // 未加载时省略该键（后端保持现值）——不得以默认值覆盖用户选择
      ...(githubProxyLoaded.value ? { github_proxy_url: githubProxyUrl.value } : {}),
      source: 'basic',
    }
    // 令牌三态：清除标记→显式空串撤销；有输入→覆盖；
    // 两者皆无→省略字段保持现值
    if (githubTokenClearPending.value) {
      ;(payload as Record<string, unknown>).github_token = ''
    } else if (githubTokenInput.value.trim() !== '') {
      ;(payload as Record<string, unknown>).github_token = githubTokenInput.value.trim()
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
    const saveResp = await request.put('/config', payload)
    // 保存成功后同步令牌显隐态：清除→has_github_token=false；覆盖→置 true 并清空输入框
    if (githubTokenClearPending.value) {
      settings.value.has_github_token = false
      githubTokenClearPending.value = false
    } else if (githubTokenInput.value.trim() !== '') {
      settings.value.has_github_token = true
      githubTokenInput.value = ''
    }
    // 保存成功后清除编辑标记——后续保存继续省略未再编辑的字段，
    // 避免一次编辑把值永久物化为每次提交的显式载荷。
    securityEventsRetentionDirty.value = false
    securityEventsRowCapDirty.value = false
    // 保存成功后立即刷新全局配置，让 timezone 在 authStore 中立竿见影（date.ts formatDate 展示侧即时生效）；
    // silent：保存已成功，随后的 GET /config 刷新失败不应再弹误导性错误 toast
    try {
      await authStore.fetchConfig(true)
    } catch (refreshError) {
      // 刷新失败不等于保存失败——/config 已落库
      console.error('Failed to refresh global config after save:', refreshError)
    }
    // 父级刷新先于 TLS 段：两段写无跨表事务，TLS 段失败不得让基础设置
    // 看起来整单未生效（用户只需重试 TLS 段）。
    emit('save')
    if (tlsPending) {
      try {
        const fd = formDataOf({ enabled: String(adminTls.value.enabled), mode: adminTls.value.mode })
        const staged = stagedAdminTlsCert.value
        if (adminTls.value.enabled && adminTls.value.mode === 'upload' && staged) {
          fd.append('cert_file', staged.certFile)
          fd.append('key_file', staged.keyFile)
        }
        // silent：失败文案由本段自报（全局「保存失败」会被读成整单未生效）
        await request.put('/admin-tls', fd, { silent: true })
        // 成功态以读路径回填（唯一真相）：后端新证书可解析时不再下发
        // cert_info_error，损坏横幅与「可复用已保存证书」确认门随之复位。
        // 手工补丁 saved/hasCert 会残留旧 error——修好证书后仍报「坏」，
        // 且确认门被旧 error 灰置到整页刷新。
        adminTlsSaved.value = { ...adminTls.value }
        stagedAdminTlsCert.value = null
        await loadAdminTls()
        notifyTlsRestarting(adminTls.value.enabled)
      } catch (tlsError) {
        // 部分成功必须显性披露：基础键已落库，证书与重启语义未生效
        console.error('Failed to save admin TLS config:', tlsError)
        const reason = tlsError instanceof Error && tlsError.message ? tlsError.message : '未知错误'
        ElMessage.error(`基础设置已保存；HTTPS 配置保存失败：${reason}。证书未变更，可再次保存以仅重试 HTTPS 段`)
      }
    } else {
      const message = (saveResp as unknown as { message?: string }).message ?? ''
      mfaAwareSuccess(message.includes('配置无变化') ? message : '保存成功')
    }
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
.compact-select { width: 240px; max-width: 100%; }
/* 旧式 el-text tip-inline/tip-block 已全量归一全局 form-tip-inline/
   form-tip-line（main.css 唯一事实源），scoped 重复定义删除 */
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
.log-viewer { height: 55vh; min-height: 320px; overflow: auto; padding: 12px 16px; background: #0f172a; border-radius: var(--radius-sm, 6px); }
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

/* →十七次：el-descriptions 的表格布局压不动 label 宽（仍折行）——
   改自绘行布局：标题列 flex 定宽 + nowrap，内容列自动换行。 */
.mfa-scope-list {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 8px;
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
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  background: #f9fafb;
  border-right: 1px solid var(--el-border-color-lighter);
}
.mfa-scope-items {
  flex: 1;
  padding: 8px 12px;
  font-size: 12px;
  color: #374151;
  line-height: 1.8;
}

/* 「支持的操作」链接与描述文字同色（info），保留可点击/hover 链接语义*/
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
/* 内容列只显范围标签，单行不换行（明细在 hover tooltip，2026-09-21 用户裁定） */
.auto-backup-scope-text { white-space: nowrap; }
.auto-backup-scope-text.is-warning { color: var(--el-color-warning); }
.auto-backup-list { border-top: 1px solid var(--el-border-color-lighter); padding-top: 10px; }

/* 自管标签行族已退役（2026-10-11 用户裁定：对齐统一走原生 el-form-item，
 * Firefox label-for 控制台告警为 EP 上游已知形态、非用户可见）——
 * .form-radio-row / -label / -content 死 CSS 一并删除。 */

/* HTTPS 证书配置弹框（2026-09-25 用户裁定重构）：正文 20px 水平留白；
   文件选择=按钮+文件名展示；证书信息=浅底卡片行布局 */
.tls-file-field { display: flex; align-items: center; gap: 10px; width: 100%; }
.tls-file-name { font-size: 12px; color: #374151; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tls-file-name.is-empty { color: #9ca3af; }
.tls-cert-info { display: flex; flex-direction: column; gap: 2px; width: 100%; border: 1px solid var(--el-border-color-lighter); border-radius: 8px; padding: 10px 12px; background: #fafafa; font-size: 12px; line-height: 1.8; }
.tls-cert-info-row { display: flex; gap: 8px; }
.tls-cert-info-label { flex: 0 0 60px; color: #6b7280; }
.tls-cert-info-row .is-expired { color: var(--el-color-danger); font-weight: 600; }
.import-waf-hint { display: block; }
</style>
