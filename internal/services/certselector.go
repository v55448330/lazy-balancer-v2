package services

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"
)

type CertificateCandidate struct {
	ID        int64
	Domain    string
	Status    string
	CertPEM   string
	KeyPEM    string
	UpdatedAt float64
}

type CertificateSelection struct {
	Candidate   CertificateCandidate
	Certificate *x509.Certificate
}

func SelectCertificate(candidates []CertificateCandidate, ruleDomains string, now time.Time) (CertificateSelection, bool) {
	canonicalDomains, err := CanonicalACMEDomains(ruleDomains)
	if err != nil {
		return CertificateSelection{}, false
	}
	domains := strings.Split(canonicalDomains, ",")
	var selected CertificateSelection
	found := false
	for _, candidate := range candidates {
		if candidate.Status == "disabled" {
			continue
		}
		pair, err := tls.X509KeyPair([]byte(candidate.CertPEM), []byte(candidate.KeyPEM))
		if err != nil || len(pair.Certificate) == 0 {
			continue
		}
		certificate := pair.Leaf
		if certificate == nil {
			certificate, err = x509.ParseCertificate(pair.Certificate[0])
		}
		if err != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			continue
		}
		coversDomains := true
		for _, domain := range domains {
			if certificate.VerifyHostname(domain) != nil {
				coversDomains = false
				break
			}
		}
		if !coversDomains {
			continue
		}
		if !found || candidate.UpdatedAt > selected.Candidate.UpdatedAt || candidate.UpdatedAt == selected.Candidate.UpdatedAt && candidate.ID > selected.Candidate.ID {
			selected = CertificateSelection{Candidate: candidate, Certificate: certificate}
			found = true
		}
	}
	return selected, found
}
