package tlscert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	// The logger keeps its log file open, so it must live outside the
	// auto-cleaned temp dir to avoid Windows cleanup failures.
	logDir, err := os.MkdirTemp("", "zoraxy-tlscert-logs")
	if err != nil {
		t.Fatalf("create log dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(logDir) })
	lg, err := logger.NewLogger("test", logDir)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	return &Manager{CertStore: dir, Logger: lg}
}

func TestGenerateSelfSignedAllKeyTypes(t *testing.T) {
	m := newTestManager(t)
	dir := m.CertStore

	for _, kt := range SupportedTlsKeyTypes {
		certFile := "test-" + kt.String() + ".pem"
		keyFile := "test-" + kt.String() + ".key"
		if err := m.GenerateSelfSignedCertificate("example.com", []string{"example.com"}, certFile, keyFile, kt); err != nil {
			t.Fatalf("%s: generate failed: %v", kt, err)
		}

		certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
		if err != nil {
			t.Fatalf("%s: read cert: %v", kt, err)
		}
		keyPEM, err := os.ReadFile(filepath.Join(dir, keyFile))
		if err != nil {
			t.Fatalf("%s: read key: %v", kt, err)
		}

		// The pair must load as a usable TLS certificate
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
			t.Fatalf("%s: X509KeyPair failed: %v", kt, err)
		}

		block, _ := pem.Decode(keyPEM)
		if block == nil {
			t.Fatalf("%s: key PEM decode failed", kt)
		}

		switch {
		case len(kt.String()) > 3 && kt.String()[:3] == "rsa":
			if block.Type != "RSA PRIVATE KEY" {
				t.Fatalf("%s: unexpected PEM type %q", kt, block.Type)
			}
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("%s: parse PKCS1: %v", kt, err)
			}
			want := map[string]int{"rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096}[kt.String()]
			if k.N.BitLen() != want {
				t.Fatalf("%s: got %d bit key, want %d", kt, k.N.BitLen(), want)
			}
		default:
			if block.Type != "EC PRIVATE KEY" {
				t.Fatalf("%s: unexpected PEM type %q", kt, block.Type)
			}
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("%s: parse EC: %v", kt, err)
			}
			want := map[string]int{"ecdsa-p256": 256, "ecdsa-p384": 384, "ecdsa-p521": 521}[kt.String()]
			if k.Curve.Params().BitSize != want {
				t.Fatalf("%s: got %d bit curve, want %d", kt, k.Curve.Params().BitSize, want)
			}
		}
	}
}

func TestGenerateSelfSignedInvalidKeyType(t *testing.T) {
	m := newTestManager(t)
	if err := m.GenerateSelfSignedCertificate("example.com", nil, "a.pem", "a.key", TlsKeyType("bogus")); err == nil {
		t.Fatal("expected error for invalid key type")
	}
}

func TestGenerateSelfSignedEmptyKeyTypeDefaults(t *testing.T) {
	m := newTestManager(t)
	if err := m.GenerateSelfSignedCertificate("example.com", nil, "a.pem", "a.key", ""); err != nil {
		t.Fatalf("empty key type should default: %v", err)
	}
}

// The certificate store must be able to reload RSA keys, not just ECDSA ones.
func TestUpdateLoadedCertListWithRSA(t *testing.T) {
	m := newTestManager(t)
	if err := m.GenerateSelfSignedCertificate("rsa.example.com", []string{"rsa.example.com"}, "rsa.example.com.pem", "rsa.example.com.key", TlsKeyTypeRSA2048); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := m.UpdateLoadedCertList(); err != nil {
		t.Fatalf("update loaded cert list: %v", err)
	}
	if len(m.LoadedCerts) != 1 {
		t.Fatalf("expected 1 loaded cert, got %d", len(m.LoadedCerts))
	}
	if m.LoadedCerts[0].Cert.PublicKeyAlgorithm != x509.RSA {
		t.Fatalf("expected RSA public key, got %v", m.LoadedCerts[0].Cert.PublicKeyAlgorithm)
	}
}
