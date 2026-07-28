package services

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"lazy-balancer-v2/internal/db"
)

const certDir = "/app/certs"

// 序列化证书对写盘：避免并发写同一规则产生撕裂的 cert/key 组合
var certWriteMu sync.Mutex

type CertFileSnapshot struct {
	Data   []byte
	Mode   os.FileMode
	Exists bool
}

type CertPairSnapshot struct {
	Cert CertFileSnapshot
	Key  CertFileSnapshot
}

type CertFilesSnapshot map[string]CertPairSnapshot

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

func CertFilePaths(ruleID string) (certPath, keyPath string) {
	if !safeRuleID(ruleID) {
		return "", ""
	}
	return filepath.Join(certDir, ruleID+".crt"), filepath.Join(certDir, ruleID+".key")
}

func WriteCertFiles(ruleID, certPEM, keyPEM string) error {
	certWriteMu.Lock()
	defer certWriteMu.Unlock()
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录: %w", err)
	}
	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return fmt.Errorf("非法的规则编号: %q", ruleID)
	}
	return writeCertPair(certPath, keyPath, certPEM, keyPEM)
}

func writeCertPair(certPath, keyPath, certPEM, keyPEM string) error {
	previousCert, err := os.ReadFile(certPath)
	certExisted := err == nil
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("读取原证书: %w", err)
	}
	previousMode := os.FileMode(0644)
	if certExisted {
		info, statErr := os.Stat(certPath)
		if statErr != nil {
			return fmt.Errorf("读取原证书权限: %w", statErr)
		}
		previousMode = info.Mode().Perm()
	}

	certTmp, keyTmp := certPath+".tmp", keyPath+".tmp"
	if err := os.WriteFile(certTmp, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("写入证书: %w", err)
	}
	if err := os.WriteFile(keyTmp, []byte(keyPEM), 0600); err != nil {
		return errors.Join(fmt.Errorf("写入私钥: %w", err), removeTemporaryCertFile(certTmp))
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		return errors.Join(fmt.Errorf("部署证书: %w", err), removeTemporaryCertFile(certTmp), removeTemporaryCertFile(keyTmp))
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		deployErr := fmt.Errorf("部署私钥: %w", err)
		cleanupErr := removeTemporaryCertFile(keyTmp)
		if certExisted {
			if restoreErr := os.WriteFile(certPath, previousCert, previousMode); restoreErr != nil {
				return errors.Join(deployErr, cleanupErr, fmt.Errorf("恢复原证书: %w", restoreErr))
			}
		} else if removeErr := os.Remove(certPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return errors.Join(deployErr, cleanupErr, fmt.Errorf("删除新证书: %w", removeErr))
		}
		return errors.Join(deployErr, cleanupErr)
	}
	return nil
}

func removeTemporaryCertFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清理临时文件 %s: %w", path, err)
	}
	return nil
}

func RemoveCertFiles(ruleID string) {
	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return
	}
	os.Remove(certPath)
	os.Remove(keyPath)
}

func SnapshotCertFiles(ruleIDs []string) (CertFilesSnapshot, error) {
	certWriteMu.Lock()
	defer certWriteMu.Unlock()

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

func RestoreCertFiles(snapshot CertFilesSnapshot) error {
	certWriteMu.Lock()
	defer certWriteMu.Unlock()

	var restoreErrors []error
	for ruleID, pair := range snapshot {
		certPath, keyPath := CertFilePaths(ruleID)
		if certPath == "" {
			restoreErrors = append(restoreErrors, fmt.Errorf("非法的规则编号: %q", ruleID))
			continue
		}
		if err := restoreCertFile(certPath, pair.Cert); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("恢复证书 %s: %w", ruleID, err))
		}
		if err := restoreCertFile(keyPath, pair.Key); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("恢复私钥 %s: %w", ruleID, err))
		}
	}
	return errors.Join(restoreErrors...)
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
	if err := os.WriteFile(temporaryPath, snapshot.Data, snapshot.Mode); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		removeErr := os.Remove(temporaryPath)
		return errors.Join(err, removeErr)
	}
	return nil
}

func MaterializeAllCertsFromDB() {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Printf("certstore: create cert dir failed: %v", err)
		return
	}
	manualRecovered := 0
	acmeRecovered := 0

	rows, err := db.DB.Query(`SELECT caddy_id, tls_cert, tls_key FROM lb_rules WHERE enable_tls=1 AND tls_source='manual' AND COALESCE(tls_cert,'')!='' AND COALESCE(tls_key,'')!=''`)
	if err != nil {
		log.Printf("certstore: query manual certs failed: %v", err)
		RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), "类型：手动证书", AuditResultPart("query_failed")), "")
	} else {
		for rows.Next() {
			var ruleID, certPEM, keyPEM string
			if err := rows.Scan(&ruleID, &certPEM, &keyPEM); err != nil {
				log.Printf("certstore: scan manual cert failed: %v", err)
				continue
			}
			if err := WriteCertFiles(ruleID, certPEM, keyPEM); err != nil {
				log.Printf("certstore: write manual cert %s failed: %v", ruleID, err)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(ruleID), "类型：手动证书", AuditResultPart("io_error")), "")
			} else {
				manualRecovered++
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("certstore: iterate manual certs failed: %v", err)
		}
		rows.Close()
	}

	rows2, err := db.DB.Query(`SELECT rule_id, cert_pem, key_pem FROM cert_jobs WHERE status='issued' AND COALESCE(cert_pem,'')!='' AND COALESCE(key_pem,'')!=''`)
	if err != nil {
		log.Printf("certstore: query ACME certs failed: %v", err)
		RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), "类型：ACME证书", AuditResultPart("query_failed")), "")
	} else {
		for rows2.Next() {
			var ruleID, certPEM, keyPEM string
			if err := rows2.Scan(&ruleID, &certPEM, &keyPEM); err != nil {
				log.Printf("certstore: scan ACME cert failed: %v", err)
				continue
			}
			if err := WriteCertFiles(ruleID, certPEM, keyPEM); err != nil {
				log.Printf("certstore: write ACME cert %s failed: %v", ruleID, err)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(ruleID), "类型：ACME证书", AuditResultPart("io_error")), "")
			} else {
				acmeRecovered++
			}
		}
		if err := rows2.Err(); err != nil {
			log.Printf("certstore: iterate ACME certs failed: %v", err)
		}
		rows2.Close()
	}
	if manualRecovered > 0 || acmeRecovered > 0 {
		RecordAuditLog("system", "恢复", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), fmt.Sprintf("手动证书 %d 个", manualRecovered), fmt.Sprintf("ACME证书 %d 个", acmeRecovered)), "")
	}
}
