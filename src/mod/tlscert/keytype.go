package tlscert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// TlsKeyType defines the algorithm and key size used when generating
// self-signed certificates.
type TlsKeyType string

const (
	TlsKeyTypeECDSAP256 TlsKeyType = "ecdsa-p256"
	TlsKeyTypeECDSAP384 TlsKeyType = "ecdsa-p384"
	TlsKeyTypeECDSAP521 TlsKeyType = "ecdsa-p521"
	TlsKeyTypeRSA2048   TlsKeyType = "rsa-2048"
	TlsKeyTypeRSA3072   TlsKeyType = "rsa-3072"
	TlsKeyTypeRSA4096   TlsKeyType = "rsa-4096"

	// DefaultTlsKeyType keeps the historical behaviour (ECDSA P-256)
	DefaultTlsKeyType = TlsKeyTypeECDSAP256
)

// SupportedTlsKeyTypes lists all key types in ascending order of strength
var SupportedTlsKeyTypes = []TlsKeyType{
	TlsKeyTypeECDSAP256,
	TlsKeyTypeECDSAP384,
	TlsKeyTypeECDSAP521,
	TlsKeyTypeRSA2048,
	TlsKeyTypeRSA3072,
	TlsKeyTypeRSA4096,
}

// IsValid reports whether the key type is one of the supported values
func (k TlsKeyType) IsValid() bool {
	for _, supported := range SupportedTlsKeyTypes {
		if k == supported {
			return true
		}
	}
	return false
}

func (k TlsKeyType) String() string {
	return string(k)
}

// generatePrivateKey creates a new private key matching this key type
func (k TlsKeyType) generatePrivateKey() (crypto.Signer, error) {
	switch k {
	case TlsKeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case TlsKeyTypeRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case TlsKeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case TlsKeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case TlsKeyTypeECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case TlsKeyTypeECDSAP256, "":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("unsupported key type %q", string(k))
}

// marshalPrivateKeyPEM encodes a private key into its conventional PEM form
func marshalPrivateKeyPEM(key crypto.Signer) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}, nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", key)
}
