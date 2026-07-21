package services

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"lazy-balancer-v2/internal/db"
)

const certDir = "/app/certs"

func CertFilePaths(ruleID string) (certPath, keyPath string) {
	return filepath.Join(certDir, ruleID+".crt"), filepath.Join(certDir, ruleID+".key")
}

func WriteCertFiles(ruleID, certPEM, keyPEM string) error {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录: %w", err)
	}
	certPath, keyPath := CertFilePaths(ruleID)
	certTmp, keyTmp := certPath+".tmp", keyPath+".tmp"
	if err := os.WriteFile(certTmp, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("写入证书: %w", err)
	}
	if err := os.WriteFile(keyTmp, []byte(keyPEM), 0600); err != nil {
		_ = os.Remove(certTmp)
		return fmt.Errorf("写入私钥: %w", err)
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		_ = os.Remove(certTmp)
		_ = os.Remove(keyTmp)
		return fmt.Errorf("部署证书: %w", err)
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		_ = os.Remove(keyTmp)
		return fmt.Errorf("部署私钥: %w", err)
	}
	return nil
}

func RemoveCertFiles(ruleID string) {
	certPath, keyPath := CertFilePaths(ruleID)
	os.Remove(certPath)
	os.Remove(keyPath)
}

func CertFileExists(ruleID string) bool {
	certPath, _ := CertFilePaths(ruleID)
	_, err := os.Stat(certPath)
	return err == nil
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
