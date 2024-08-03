package sshutils_test

import (
	"crypto/rand"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	//nolint:depguard
	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

func TestGenerateHostKey(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name          string
		keyType       sshutils.KeyType
		keyTypeString string
		publicKeyType string
		err           string
	}{
		{
			"rsa",
			sshutils.RSA,
			"rsa",
			"ssh-rsa",
			"",
		},
		{
			"ecdsa",
			sshutils.ECDSA,
			"ecdsa",
			"ecdsa-sha2-nistp256",
			"",
		},
		{
			"ed25519",
			sshutils.Ed25519,
			"ed25519",
			"ssh-ed25519",
			"",
		},
		{
			"unknown",
			sshutils.KeyType(42),
			"unknown type (42)",
			"",
			"unsupported key type: unknown type (42)",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.keyType.String() != tt.keyTypeString {
				t.Errorf("expected key type string %v, got %v", tt.keyTypeString, tt.keyType.String())
			}
			key, err := sshutils.GenerateHostKey(rand.Reader, tt.keyType)
			if err != nil || tt.err != "" {
				if (err != nil && (tt.err == "" || !strings.HasPrefix(err.Error(), tt.err))) || (err == nil && tt.err != "") {
					t.Errorf("GenerateHostKey() error = %v, want %q", err, tt.err)
				}
				return
			}
			if key.PublicKey().Type() != tt.publicKeyType {
				t.Errorf("GenerateHostKey() type = %v, want %v", key.PublicKey().Type(), tt.publicKeyType)
			}
			expectedFingerprintPrefix := "SHA256:"
			if !strings.HasPrefix(key.String(), expectedFingerprintPrefix) {
				t.Errorf("GenerateHostKey() fingerprint = %v, want %v", key.String(), expectedFingerprintPrefix)
			}
			if key.String() != ssh.FingerprintSHA256(key.PublicKey()) {
				t.Errorf("GenerateHostKey() fingerprint = %v, want %v", key.String(), ssh.FingerprintSHA256(key.PublicKey()))
			}
			keyFile := path.Join(t.TempDir(), tt.name)
			if err := key.Save(keyFile); err != nil {
				t.Errorf("Save() error = %v", err)
			}
			key2, err := sshutils.LoadHostKey(keyFile)
			if err != nil {
				t.Errorf("LoadHostKey() error = %v", err)
			}
			if key.String() != key2.String() {
				t.Errorf("LoadHostKey() fingerprint = %v, want %v", key2.String(), key.String())
			}
		})
	}
}

func TestGenerateHostKey_Error(t *testing.T) {
	t.Parallel()
	_, err := sshutils.GenerateHostKey(&fakeRandReader{true}, sshutils.RSA)
	if expectedError := "invalid key: fake error"; err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Response() error = %v, want %v", err, expectedError)
	}
}

func TestLoadHostKey_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := sshutils.LoadHostKey("missing")
	expectedError := "invalid key file: open missing"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("LoadHostKey() error = %v, want %v", err, expectedError)
	}
}

func TestLoadHostKey_InvalidKey(t *testing.T) {
	t.Parallel()
	keyFile := path.Join(t.TempDir(), "invalid")
	if err := os.WriteFile(keyFile, []byte("invalid"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := sshutils.LoadHostKey(keyFile)
	expectedError := "invalid key file: ssh: no key found"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("LoadHostKey() error = %v, want %v", err, expectedError)
	}
}

func TestLoadHostKey_UnsupportedKey(t *testing.T) {
	t.Parallel()
	keyFile := path.Join(t.TempDir(), "unsupported")
	if err := os.WriteFile(keyFile, []byte(`-----BEGIN DSA PRIVATE KEY-----
MIH4AgEAAkEA/xHcnZwDuXk9xo1J7rBYQWXztGW7uOZ6DOAeJGBed2KUJlo3q2ld
+k37ETPH3hy9uLEmnSQJOl9BRarNKvLIgQIVANab841m1OON+WIJR9b0GPWn1A8n
AkAilkYpzVX7Xnm+iXsxRRRuMzdPmkKuED+drzYv44cKV7OfeE9mB1Em0FoAUUSE
Rn9NGYrCV2oCIplAQJtFseZNAkEAjUtS8B8IKksHv3Y8cmfoLfWgNKyPNov5R+0U
f64EsZ7vJrIacpDPVXi1llIjQpWFZPo7nRpJ0SA2C5YouNJzygIUQdjs5FHSqHm+
MykJo7li7Fc1OeQ=
-----END DSA PRIVATE KEY-----`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := sshutils.LoadHostKey(keyFile)
	expectedError := "invalid key: ssh: unsupported DSA key size 512"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("LoadHostKey() error = %v, want %v", err, expectedError)
	}
}

func TestSave_InvalidFile(t *testing.T) {
	t.Parallel()
	key, err := sshutils.GenerateHostKey(rand.Reader, sshutils.RSA)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	keyFile := t.TempDir()
	expectedError := fmt.Sprintf("invalid key file: open %v", keyFile)
	if err := key.Save(keyFile); err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Save() error = %v, want %v", err, expectedError)
	}
}

func TestSave_InvalidKey(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	keyFile := path.Join(tempDir, "invalid")
	if err := os.WriteFile(keyFile, []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCVoARJpctxbLuBogHVoSTbL6E5cEemlqm8t5Wdp8yqi1vJSEnj
+U0dPEgLW/k6vV7XLA5Aus6lY67zc70U7RBy+GiYjihtZwLZcV1XDuFvWwme70xS
6LfohTcOY/HyHMfEMDVfUn+l0jUTsHPFyESxEBbGLnOs2/KcXYFfKWndAwIVAJG6
uD3Yi9y/xvJLRQlK8Z3qyOBZAoGACkRxWQzwPG/K9iY+3aEGTyjP+JGXsyvsH3bZ
pglIT0/wlyLQFmpggGN64dw0sj3MlQYkZrKBiU8gQ0VPDw5XEgzzRg0/w5ogIjQc
SmOOQWrJx1ksk/Bve/rLqySizlWTr6HcAjowV3HLIyd2AkdVlER0fcZ0+Ktm/K0j
Y5PP6jACgYEAk3O45B8rzmsM3NaaGS2lJKMn1iPxdbAdS783kR2Dgh0BYYq4/qFV
/07jSrNUmf9CQqgLkvQkkPeIKI1pMdrC7d4ZMucSP0/GPoOAJayqfewo9tQUm6/i
KO7YddFBgX0A8RD8Ta0PQqB9zP6RWnSAJwJWqfpjP5J9E1NJ930DihcCFBsjAkOk
1KFY3BSoV0jtyTfwcSh5
-----END DSA PRIVATE KEY-----`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	key, err := sshutils.LoadHostKey(keyFile)
	if err != nil {
		t.Fatalf("LoadHostKey() error = %v", err)
	}
	expectedError := "invalid key: x509: unknown key type"
	if err := key.Save(path.Join(tempDir, "key")); err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Save() error = %v, want %v", err, expectedError)
	}
}
