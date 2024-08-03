package sshutils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
)

const (
	rsaKeyBitSize    = 2048
	hostKeyFilePerms = 0o600
)

type InvalidKeyError struct {
	err error
}

func (e InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid key: %v", e.err)
}

type InvalidKeyFileError struct {
	err error
}

func (e InvalidKeyFileError) Error() string {
	return fmt.Sprintf("invalid key file: %v", e.err)
}

type UnsupportedKeyTypeError struct {
	t KeyType
}

func (e UnsupportedKeyTypeError) Error() string {
	return fmt.Sprintf("unsupported key type: %v", e.t)
}

type KeyType int

const (
	RSA = iota
	ECDSA
	Ed25519
)

func (t KeyType) String() string {
	switch t {
	case RSA:
		return "rsa"
	case ECDSA:
		return "ecdsa"
	case Ed25519:
		return "ed25519"
	default:
		return fmt.Sprintf("unknown type (%d)", t)
	}
}

type HostKey struct {
	ssh.Signer
	key interface{}
}

func (key *HostKey) String() string {
	return ssh.FingerprintSHA256(key.PublicKey())
}

func hostKeyFromKey(key interface{}) (*HostKey, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, InvalidKeyError{err}
	}
	return &HostKey{
		Signer: signer,
		key:    key,
	}, nil
}

func GenerateHostKey(rand io.Reader, t KeyType) (*HostKey, error) {
	var key interface{}
	var err error
	switch t {
	case RSA:
		key, err = rsa.GenerateKey(rand, rsaKeyBitSize)
	case ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand)
	case Ed25519:
		_, key, err = ed25519.GenerateKey(rand)
	default:
		return nil, UnsupportedKeyTypeError{t}
	}
	if err != nil {
		return nil, InvalidKeyError{err}
	}
	return hostKeyFromKey(key)
}

func LoadHostKey(fileName string) (*HostKey, error) {
	keyBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, InvalidKeyFileError{err}
	}
	key, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, InvalidKeyFileError{err}
	}
	return hostKeyFromKey(key)
}

func (key *HostKey) Save(fileName string) error {
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, hostKeyFilePerms) //nolint:nosnakecase
	if err != nil {
		return InvalidKeyFileError{err}
	}
	defer file.Close()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key.key)
	if err != nil {
		return InvalidKeyError{err}
	}
	if _, err = file.Write(pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   keyBytes,
	})); err != nil {
		return InvalidKeyFileError{err}
	}
	return nil
}
