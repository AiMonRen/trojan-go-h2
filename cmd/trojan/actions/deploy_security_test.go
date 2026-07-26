package actions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/internal/certmonitor"
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
	needsRenewal, err := certmonitor.CertificateNeedsRenewal(certificatePath, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("inspect long-lived certificate: %v", err)
	}
	if needsRenewal {
		t.Fatal("certificate outside renewal window must not renew")
	}

	if err := os.WriteFile(certificatePath, testCertificatePEM(t, now.Add(7*24*time.Hour)), 0644); err != nil {
		t.Fatalf("write soon-expiring certificate: %v", err)
	}
	needsRenewal, err = certmonitor.CertificateNeedsRenewal(certificatePath, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("inspect soon-expiring certificate: %v", err)
	}
	if !needsRenewal {
		t.Fatal("certificate inside renewal window must renew")
	}
}

func TestCertificateRenewalConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme-renewal.conf")
	want := certmonitor.CertificateRenewalConfig{
		Domain:          "example.com",
		Email:           "ops@example.com",
		CAURL:           "https://acme.example/directory",
		CertificatePath: "/etc/trojan-go/tls/example.com/example.com.crt",
		PrivateKeyPath:  "/etc/trojan-go/tls/example.com/example.com.key",
		ReloadHysteria:  true,
	}
	if err := certmonitor.WriteCertificateRenewalConfig(path, want); err != nil {
		t.Fatalf("write renewal config: %v", err)
	}
	got, err := certmonitor.ReadCertificateRenewalConfig(path)
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

// testCertKeyPair returns a matching self-signed certificate and its private
// key, both PEM-encoded, so writeCertificateFiles' pair validation passes.
func testCertKeyPair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestWriteCertificateFilesAtomicSwitch(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com.crt")
	keyPath := filepath.Join(dir, "example.com.key")

	cert1, key1 := testCertKeyPair(t, "example.com")
	if err := certmonitor.WriteCertificateFiles(certPath, keyPath, cert1, key1); err != nil {
		t.Fatalf("initial install: %v", err)
	}

	// The public paths must resolve (through symlinks) to the exact PEM we wrote
	// and must always form a valid pair.
	assertCertPairMatches(t, certPath, keyPath, cert1, key1)

	// A renewal writes a new pair; after the switch the paths must reflect the
	// new material and still be a matching pair (no mixed old/new).
	cert2, key2 := testCertKeyPair(t, "example.com")
	if err := certmonitor.WriteCertificateFiles(certPath, keyPath, cert2, key2); err != nil {
		t.Fatalf("renewal install: %v", err)
	}
	assertCertPairMatches(t, certPath, keyPath, cert2, key2)

	// Only one live version should remain after pruning (current + at most the
	// just-written one). Never a mismatched pair.
	store := filepath.Join(dir, ".certstore")
	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	versions := 0
	for _, e := range entries {
		if e.IsDir() {
			versions++
		}
	}
	if versions != 1 {
		t.Fatalf("expected exactly 1 retained version directory after prune, got %d", versions)
	}
}

func assertCertPairMatches(t *testing.T, certPath, keyPath string, wantCert, wantKey []byte) {
	t.Helper()
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert via path: %v", err)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key via path: %v", err)
	}
	if string(gotCert) != string(wantCert) {
		t.Fatal("certificate content does not match what was written")
	}
	if string(gotKey) != string(wantKey) {
		t.Fatal("key content does not match what was written")
	}
	if _, err := tls.X509KeyPair(gotCert, gotKey); err != nil {
		t.Fatalf("live cert/key are not a valid pair: %v", err)
	}
}
