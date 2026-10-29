package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"lazy-balancer-v2/internal/db"
)

var certDir = "/app/certs"

// SetCertDirForTest 重定向证书物化目录，仅供测试隔离使用（返回还原函数）。
func SetCertDirForTest(dir string) func() {
	old := certDir
	certDir = dir
	return func() { certDir = old }
}

// certWriteMu 保护证书文件操作的层级互斥：读锁（RLock）覆盖按规则并行的
// 写/删/快照/物化，写锁（Lock）只留给「跨规则快照回滚」（RestoreCertFiles
// 全有全无，必须排斥一切并发文件操作）。全局互斥时代 /load 渲染 N 条
// ACME 规则在同一锁内串行 N 组 fsync（机械盘合计数百 ms～秒级），跨规则
// 部署/删除彼此阻塞，per-rule DeployLock 因此无实际收益。
var certWriteMu sync.RWMutex

// certRuleFileLocks 按 ruleID 串行化同一规则的 cert/key 文件操作
// （内容比对→tmp→rename 序列不得与同规则并发写交错产生撕裂组合）。
// 条目在最后一个持有者释放后回收（见 refCountedLockTable）——键空间是
// 「当前在途操作数」而非历史规则总数。
var certRuleFileLocks refCountedLockTable

// refCountedLockTable 是按 key 引用计数的互斥锁表。与「sync.Map + LoadOrStore
// 只增不删」的旧形态不同，最后一个持有者释放后条目即回收：规则可反复创建/删除
// （caddy_id 随机生成），只增不删的表会按历史规则总数线性增长。refs 在 acquire
// 内与「查找/创建条目」同一临界区自增（含阻塞等待者），只要有人持有或等待条目
// 就不会被回收——同 key 因此不会出现两把不同锁的并发窗口。查找与登记分属两处
// 是本表唯一需要防止的形态（见 acquire 注释）。
type refCountedLockTable struct {
	mu    sync.Mutex
	locks sync.Map // key -> *refCountedLock
}

type refCountedLock struct {
	table *refCountedLockTable
	key   string
	mu    sync.Mutex
	refs  int
}

// acquire 原子地取得 key 的锁条目：查找/创建与引用登记在同一个表级临界区内
// 完成，返回的锁尚未持有，调用方须再调用 Lock 阻塞获取。
//
// 两步必须在同一临界区：若先返回指针、稍后才登记引用，最后一个持有者可能在
// 其间把 refs 减到 0 并回收条目——迟到的获取者拿到的旧锁已不在表里，第三者
// 随即建出新锁，同 key 因此出现两把并存的锁（per-rule 互斥失效）。
func (t *refCountedLockTable) acquire(key string) *refCountedLock {
	t.mu.Lock()
	defer t.mu.Unlock()
	value, _ := t.locks.LoadOrStore(key, &refCountedLock{table: t, key: key})
	lock := value.(*refCountedLock)
	lock.refs++
	return lock
}

// Lock 只阻塞在条目自身的互斥量上：引用已在 acquire 时登记（覆盖持有 + 等待
// 全体），回收判定因此安全——本方法不再触碰表锁，也不存在锁序反转。
func (l *refCountedLock) Lock() {
	l.mu.Lock()
}

func (l *refCountedLock) Unlock() {
	l.mu.Unlock()
	l.table.mu.Lock()
	l.refs--
	if l.refs == 0 {
		l.table.locks.Delete(l.key)
	}
	l.table.mu.Unlock()
}

// lockCertRuleFile 返回单规则的 per-rule 文件锁。调用方必须先持
// certWriteMu.RLock（锁序：certWriteMu → per-rule，单向不逆）。
func lockCertRuleFile(ruleID string) *refCountedLock {
	return certRuleFileLocks.acquire(ruleID)
}

// lockCertRuleFiles 按序取多条规则的 per-rule 锁（排序+去重防死锁/自锁），
// 返回统一解锁函数。调用方必须先持 certWriteMu.RLock。
func lockCertRuleFiles(ruleIDs []string) func() {
	unique := make([]string, 0, len(ruleIDs))
	seen := make(map[string]struct{}, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if _, ok := seen[ruleID]; ok {
			continue
		}
		seen[ruleID] = struct{}{}
		unique = append(unique, ruleID)
	}
	sort.Strings(unique)
	locks := make([]*refCountedLock, 0, len(unique))
	for _, ruleID := range unique {
		lock := lockCertRuleFile(ruleID)
		lock.Lock()
		locks = append(locks, lock)
	}
	return func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Unlock()
		}
	}
}

var certificateDeployLocks refCountedLockTable

// DeployLock serializes the complete deployment and rollback transaction for
// one rule while allowing unrelated rules to deploy concurrently. 条目随最后
// 持有者释放回收（refCountedLockTable），与 certRuleFileLocks 同一实现。
func DeployLock(ruleID string) func() {
	lock := certificateDeployLocks.acquire(ruleID)
	lock.Lock()
	return lock.Unlock
}

type CertFileSnapshot struct {
	Data   []byte
	Mode   os.FileMode
	Exists bool
}

type CertPairSnapshot struct {
	Cert CertFileSnapshot
	Key  CertFileSnapshot
}

// certPairMatchesSnapshot 是「磁盘证书对是否已与期望一致」的唯一判据：内容逐
// 字节相等，且证书 0644、私钥 0600。三条链路共用同一判据——写侧
// writeCertPairFiles 据此跳过写盘、materializeCertPair 据此给出 changed（启动
// 恢复计数/审计只统计真正写过的对）、MaterializeCertPairs 据此确定差异集与
// 回滚快照范围。
//
// 判据单源是硬约束（守卫：certstore_zero_write_single_source_test.go）。历史上
// 三处各写一份，任一处漏掉权限比对就让「重复物化修复权限」的契约在该链路上
// 静默失效，而其余链路仍绿。内容与权限必须**同时**满足才零写：内容一致但权限
// 被外部改错时必须重写修复。
func certPairMatchesSnapshot(cert, key CertFileSnapshot, certPEM, keyPEM string) bool {
	return cert.Exists && cert.Mode == 0644 &&
		key.Exists && key.Mode == 0600 &&
		bytes.Equal(cert.Data, []byte(certPEM)) &&
		bytes.Equal(key.Data, []byte(keyPEM))
}

type CertFilesSnapshot map[string]CertPairSnapshot

type CertMaterial struct {
	RuleID  string
	CertPEM string
	KeyPEM  string
}

// safeRuleID rejects anything outside the generated caddy_id alphabet so a
// malicious or corrupted rule ID can never escape the cert directory.
func safeRuleID(ruleID string) bool {
	if ruleID == "" || len(ruleID) > 64 {
		return false
	}
	for _, r := range ruleID {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// ValidCertRuleID 报告 ruleID 是否满足证书文件路径字母表（非空、≤64、仅
// [a-z0-9_-]），与 safeRuleID 完全同源。导出供导入口等跨包调用方复用同一
// 字母表（v2 导入允许含 '.' 的 caddy_id，证书物化路径却拒绝——
// 必须在导入校验阶段 fail-fast 点名，而不是在证书阶段整体回滚）。
func ValidCertRuleID(ruleID string) bool {
	return safeRuleID(ruleID)
}

func CertFilePaths(ruleID string) (certPath, keyPath string) {
	if !safeRuleID(ruleID) {
		return "", ""
	}
	return filepath.Join(certDir, ruleID+".crt"), filepath.Join(certDir, ruleID+".key")
}

func WriteCertFiles(ruleID, certPEM, keyPEM string) error {
	_, err := writeCertFiles(ruleID, certPEM, keyPEM)
	return err
}

// writeCertFiles 是 WriteCertFiles 的带 changed 形态：changed=false 表示磁盘已是
// 期望的内容与权限（零写，见 certPairMatchesSnapshot）。调用方需要「是否真正
// 写盘」时（启动物化的恢复计数）走本函数，复位/部署等只关心错误的路径走
// WriteCertFiles。
func writeCertFiles(ruleID, certPEM, keyPEM string) (bool, error) {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	ruleLock := lockCertRuleFile(ruleID)
	ruleLock.Lock()
	defer ruleLock.Unlock()
	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return false, fmt.Errorf("非法的规则编号: %q", ruleID)
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return false, fmt.Errorf("创建证书目录: %w", err)
	}
	return writeCertPairFiles(certPath, keyPath, certPEM, keyPEM)
}

func writeCertPair(certPath, keyPath, certPEM, keyPEM string) error {
	_, err := writeCertPairFiles(certPath, keyPath, certPEM, keyPEM)
	return err
}

// writeCertPairFiles 落盘一对证书文件并返回是否真正写入。零写判据单源
// （certPairMatchesSnapshot），磁盘快照只读一次——此前先 ReadFile 比对内容、
// 再 Stat 比对权限、再 Stat 取回滚用权限，启动路径
// （materializeCertPair → WriteCertFiles → writeCertPair）因此对同一对文件
// 读两遍。快照同时提供回滚所需的原内容与原权限。
func writeCertPairFiles(certPath, keyPath, certPEM, keyPEM string) (bool, error) {
	cert, err := snapshotCertFile(certPath)
	if err != nil {
		return false, fmt.Errorf("读取原证书: %w", err)
	}
	key, err := snapshotCertFile(keyPath)
	if err != nil {
		// 私钥不可读（EACCES/IO）：无法判定零写，按「需要重写」继续——tmp+rename
		// 会用正确权限重建私钥，是修复路径而非失败（与既有口径一致：证书侧读失败
		// 仍上抛，私钥侧历史上是宽松读取）。
		key = CertFileSnapshot{}
	}
	previousCert := cert.Data
	certExisted := cert.Exists
	// 内容一致且权限正确才零写：跳过可免每次 apply 的 tmp+fsync+rename 写放大。
	// 权限被外部改错时仍重写（既有契约：重复物化修复权限，
	// TestMaterializeCertPairs_restores_permissions 钉住）。
	if certPairMatchesSnapshot(cert, key, certPEM, keyPEM) {
		return false, nil
	}
	previousMode := os.FileMode(0644)
	if certExisted {
		previousMode = cert.Mode
	}

	certTmp, keyTmp := certPath+".tmp", keyPath+".tmp"
	if err := writeSyncedFile(certTmp, []byte(certPEM), 0644); err != nil {
		return false, fmt.Errorf("写入证书: %w", err)
	}
	if err := writeSyncedFile(keyTmp, []byte(keyPEM), 0600); err != nil {
		return false, errors.Join(fmt.Errorf("写入私钥: %w", err), removeTemporaryCertFile(certTmp))
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		return false, errors.Join(fmt.Errorf("部署证书: %w", err), removeTemporaryCertFile(certTmp), removeTemporaryCertFile(keyTmp))
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		deployErr := fmt.Errorf("部署私钥: %w", err)
		cleanupErr := removeTemporaryCertFile(keyTmp)
		if certExisted {
			if restoreErr := writeSyncedFile(certPath, previousCert, previousMode); restoreErr != nil {
				return false, errors.Join(deployErr, cleanupErr, fmt.Errorf("恢复原证书: %w", restoreErr))
			}
		} else if removeErr := os.Remove(certPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return false, errors.Join(deployErr, cleanupErr, fmt.Errorf("删除新证书: %w", removeErr))
		}
		return false, errors.Join(deployErr, cleanupErr)
	}
	if err := syncParentDir(certPath); err != nil {
		return false, fmt.Errorf("同步证书目录: %w", err)
	}
	return true, nil
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	return file.Close()
}

func syncParentDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return errors.Join(err, dir.Close())
	}
	return dir.Close()
}

func removeTemporaryCertFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清理临时文件 %s: %w", path, err)
	}
	return nil
}

func RemoveCertFiles(ruleID string) error {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	ruleLock := lockCertRuleFile(ruleID)
	ruleLock.Lock()
	defer ruleLock.Unlock()

	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return fmt.Errorf("非法的规则编号: %q", ruleID)
	}
	var certErr, keyErr error
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		certErr = fmt.Errorf("删除证书: %w", err)
	}
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		keyErr = fmt.Errorf("删除私钥: %w", err)
	}
	return errors.Join(certErr, keyErr)
}

func SnapshotCertFiles(ruleIDs []string) (CertFilesSnapshot, error) {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	unlock := lockCertRuleFiles(ruleIDs)
	defer unlock()
	return snapshotCertFilesLocked(ruleIDs)
}

func snapshotCertFilesLocked(ruleIDs []string) (CertFilesSnapshot, error) {
	snapshot := make(CertFilesSnapshot, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if _, exists := snapshot[ruleID]; exists {
			continue
		}
		certPath, keyPath := CertFilePaths(ruleID)
		if certPath == "" {
			return nil, fmt.Errorf("非法的规则编号: %q", ruleID)
		}
		cert, err := snapshotCertFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("快照证书 %s: %w", ruleID, err)
		}
		key, err := snapshotCertFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("快照私钥 %s: %w", ruleID, err)
		}
		snapshot[ruleID] = CertPairSnapshot{Cert: cert, Key: key}
	}
	return snapshot, nil
}

// RestoreCertFiles 恢复整份快照（任一失败→全部回滚）。跨规则回滚必须全局
// 互斥：写锁排斥一切并发文件操作（其余路径均持 RLock + per-rule 锁）。
func RestoreCertFiles(snapshot CertFilesSnapshot) error {
	certWriteMu.Lock()
	defer certWriteMu.Unlock()
	return restoreCertFilesLocked(snapshot)
}

func restoreCertFilesLocked(snapshot CertFilesSnapshot) error {
	ruleIDs := make([]string, 0, len(snapshot))
	for ruleID := range snapshot {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	current, err := snapshotCertFilesLocked(ruleIDs)
	if err != nil {
		return fmt.Errorf("快照恢复前证书文件: %w", err)
	}

	for _, ruleID := range ruleIDs {
		pair := snapshot[ruleID]
		certPath, keyPath := CertFilePaths(ruleID)
		certErr := restoreCertFile(certPath, pair.Cert)
		var keyErr error
		if certErr == nil {
			keyErr = restoreCertFile(keyPath, pair.Key)
		}
		if certErr != nil || keyErr != nil {
			rollbackErr := restoreCertFilesBestEffortLocked(current)
			restoreErr := fmt.Errorf("恢复证书对 %s: %w", ruleID, errors.Join(certErr, keyErr))
			if rollbackErr != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("回滚全部证书文件: %w", rollbackErr))
			}
			return restoreErr
		}
	}
	return nil
}

func restoreCertFilesBestEffortLocked(snapshot CertFilesSnapshot) error {
	var restoreErrors []error
	for ruleID, pair := range snapshot {
		certPath, keyPath := CertFilePaths(ruleID)
		restoreErrors = append(restoreErrors,
			restoreCertFile(certPath, pair.Cert),
			restoreCertFile(keyPath, pair.Key),
		)
	}
	return errors.Join(restoreErrors...)
}

func MaterializeCertPairs(materials []CertMaterial) (CertFilesSnapshot, error) {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	materialRuleIDs := make([]string, 0, len(materials))
	for _, material := range materials {
		materialRuleIDs = append(materialRuleIDs, material.RuleID)
	}
	unlock := lockCertRuleFiles(materialRuleIDs)
	defer unlock()

	lastMaterialByRule := make(map[string]int, len(materials))
	for i, material := range materials {
		if _, err := tls.X509KeyPair([]byte(material.CertPEM), []byte(material.KeyPEM)); err != nil {
			return nil, fmt.Errorf("证书与私钥不匹配 %s: %w", material.RuleID, err)
		}
		if certPath, _ := CertFilePaths(material.RuleID); certPath == "" {
			return nil, fmt.Errorf("非法的规则编号: %q", material.RuleID)
		}
		lastMaterialByRule[material.RuleID] = i
	}

	changedMaterials := make([]CertMaterial, 0, len(lastMaterialByRule))
	snapshot := make(CertFilesSnapshot, len(lastMaterialByRule))
	for i, material := range materials {
		if lastMaterialByRule[material.RuleID] != i {
			continue
		}
		certPath, keyPath := CertFilePaths(material.RuleID)
		cert, err := snapshotCertFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("快照证书 %s: %w", material.RuleID, err)
		}
		key, err := snapshotCertFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("快照私钥 %s: %w", material.RuleID, err)
		}
		// 零写判据与写侧/启动物化同源（certPairMatchesSnapshot）：内容与权限都
		// 一致的对不进差异集，也就不占快照/回滚面。
		if certPairMatchesSnapshot(cert, key, material.CertPEM, material.KeyPEM) {
			continue
		}
		snapshot[material.RuleID] = CertPairSnapshot{Cert: cert, Key: key}
		changedMaterials = append(changedMaterials, material)
	}
	if len(changedMaterials) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return nil, fmt.Errorf("创建证书目录: %w", err)
	}
	for _, material := range changedMaterials {
		certPath, keyPath := CertFilePaths(material.RuleID)
		if err := writeCertPair(certPath, keyPath, material.CertPEM, material.KeyPEM); err != nil {
			return nil, errors.Join(fmt.Errorf("物化证书 %s: %w", material.RuleID, err), restoreCertFilesLocked(snapshot))
		}
	}
	return snapshot, nil
}

func snapshotCertFile(path string) (CertFileSnapshot, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return CertFileSnapshot{}, nil
	}
	if err != nil {
		return CertFileSnapshot{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return CertFileSnapshot{}, err
	}
	return CertFileSnapshot{Data: data, Mode: info.Mode().Perm(), Exists: true}, nil
}

func restoreCertFile(path string, snapshot CertFileSnapshot) error {
	if !snapshot.Exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	temporaryPath := path + ".restore"
	if err := writeSyncedFile(temporaryPath, snapshot.Data, snapshot.Mode); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		removeErr := os.Remove(temporaryPath)
		return errors.Join(err, removeErr)
	}
	return syncParentDir(path)
}

func MaterializeAllCertsFromDB() {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		Logf("error", "certstore: create cert dir failed: %v", err)
		return
	}
	manualRecovered := 0
	acmeRecovered := 0

	rows, err := db.DB.Query(`SELECT caddy_id, tls_cert, tls_key FROM lb_rules WHERE enable_tls=1 AND tls_source='manual' AND COALESCE(tls_cert,'')!='' AND COALESCE(tls_key,'')!=''`)
	if err != nil {
		Logf("error", "certstore: query manual certs failed: %v", err)
		RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), "类型：手动证书", AuditResultPart("query_failed")), "")
	} else {
		for rows.Next() {
			var ruleID, certPEM, keyPEM string
			if err := rows.Scan(&ruleID, &certPEM, &keyPEM); err != nil {
				Logf("error", "certstore: scan manual cert failed: %v", err)
				continue
			}
			changed, materializeErr := materializeCertPair(ruleID, certPEM, keyPEM)
			if materializeErr != nil {
				Logf("error", "certstore: write manual cert %s failed: %v", ruleID, materializeErr)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(ruleID), "类型：手动证书", AuditResultPart("io_error")), "")
			} else if changed {
				manualRecovered++
			}
		}
		if err := rows.Err(); err != nil {
			Logf("error", "certstore: iterate manual certs failed: %v", err)
		}
		rows.Close()
	}

	// 每规则取「最新且域名适用」的一行（同 rule_id 多 cert_jobs 行）——选择与
	// 6h 文件对账同源（latestApplicableACMECertMaterials）：物化内容不取决于
	// 扫描顺序，也不会重建旧域证书。
	materials, _, selectErr := latestApplicableACMECertMaterials(context.Background(), db.DB, "certstore")
	if selectErr != nil {
		Logf("error", "certstore: query ACME certs failed: %v", selectErr)
		RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), "类型：ACME证书", AuditResultPart("query_failed")), "")
	} else {
		for _, material := range materials {
			changed, materializeErr := materializeCertPair(material.RuleID, material.CertPEM, material.KeyPEM)
			if materializeErr != nil {
				Logf("error", "certstore: write ACME cert %s failed: %v", material.RuleID, materializeErr)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(material.RuleID), "类型：ACME证书", AuditResultPart("io_error")), "")
			} else if changed {
				acmeRecovered++
			}
		}
	}
	if manualRecovered > 0 || acmeRecovered > 0 {
		RecordAuditLog("system", "恢复", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), fmt.Sprintf("手动证书 %d 个", manualRecovered), fmt.Sprintf("ACME证书 %d 个", acmeRecovered)), "")
	}
	TaskLogf("startup:config-load", "certs", "证书物化完成：手动证书 %d 个、ACME 证书 %d 个落盘", manualRecovered, acmeRecovered)
}

// materializeCertPair 把库内证书对物化到磁盘，返回是否真正发生了写入。
// 内容与权限已一致时零写（返回 changed=false）——调用方的恢复计数
// 与审计/任务日志必须只统计 changed，否则每次启动都报「恢复 N 个」，稀释真正
// 的恢复事件（运维无法区分「真恢复」与「本来就在」）。
//
// changed 由写侧同源给出（writeCertFiles → certPairMatchesSnapshot）：本函数只
// 做材料自校验，不再自己读一遍磁盘内容/权限、再交给写侧读第二遍——启动路径对
// 同一对文件的重复读在千规则规模下是成倍的 syscall 与整文件读取。
func materializeCertPair(ruleID, certPEM, keyPEM string) (bool, error) {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return false, fmt.Errorf("证书与私钥不匹配: %w", err)
	}
	// 非法规则编号由 writeCertFiles 统一拒绝（与 WriteCertFiles 同错误文案）。
	return writeCertFiles(ruleID, certPEM, keyPEM)
}
