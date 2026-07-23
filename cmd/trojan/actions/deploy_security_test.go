package actions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCertificatePEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}

func TestCertificateNeedsRenewal(t *testing.T) {
	certificatePath := filepath.Join(t.TempDir(), "certificate.pem")
	now := time.Now()
	if err := os.WriteFile(certificatePath, testCertificatePEM(t, now.Add(90*24*time.Hour)), 0644); err != nil {
		t.Fatalf("write long-lived certificate: %v", err)
	}
	needsRenewal, err := certificateNeedsRenewal(certificatePath, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("inspect long-lived certificate: %v", err)
	}
	if needsRenewal {
		t.Fatal("certificate outside renewal window must not renew")
	}

	if err := os.WriteFile(certificatePath, testCertificatePEM(t, now.Add(7*24*time.Hour)), 0644); err != nil {
		t.Fatalf("write soon-expiring certificate: %v", err)
	}
	needsRenewal, err = certificateNeedsRenewal(certificatePath, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("inspect soon-expiring certificate: %v", err)
	}
	if !needsRenewal {
		t.Fatal("certificate inside renewal window must renew")
	}
}

func TestCertificateRenewalConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme-renewal.conf")
	want := certificateRenewalConfig{
		Domain:          "example.com",
		Email:           "ops@example.com",
		CAURL:           "https://acme.example/directory",
		CertificatePath: "/etc/trojan-go/tls/example.com/example.com.crt",
		PrivateKeyPath:  "/etc/trojan-go/tls/example.com/example.com.key",
		ReloadHysteria:  true,
	}
	if err := writeCertificateRenewalConfig(path, want); err != nil {
		t.Fatalf("write renewal config: %v", err)
	}
	got, err := readCertificateRenewalConfig(path)
	if err != nil {
		t.Fatalf("read renewal config: %v", err)
	}
	if got != want {
		t.Fatalf("renewal config mismatch: got %+v, want %+v", got, want)
	}
}

func TestVerifySHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("verified content"), 0644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	const expected = "034311adcf7e54dc9c9d35f583590b4c865b4b7ffa132b2acf9812c5a509f779"
	if err := verifySHA256(path, expected); err != nil {
		t.Fatalf("verify known checksum: %v", err)
	}
	if err := verifySHA256(path, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("mismatched checksum must fail")
	}
}
