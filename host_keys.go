package sshutils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

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
		return "unknown"
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
		return nil, fmt.Errorf("Failed to create signer: %w", err)
	}
	return &HostKey{
		Signer: signer,
		key:    key,
	}, nil
}

var UnsupportedKeyType = errors.New("unsupported key type")

func GenerateHostKey(t KeyType) (*HostKey, error) {
	var key interface{}
	err := UnsupportedKeyType
	switch t {
	case RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to generate key: %w", err)
	}
	return hostKeyFromKey(key)
}

func LoadHostKey(fileName string) (*HostKey, error) {
	keyBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("Failed to read key file: %w", err)
	}
	key, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse key: %w", err)
	}
	return hostKeyFromKey(key)
}

func (key *HostKey) Save(fileName string) error {
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("Failed to open key file: %w", err)
	}
	defer file.Close()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key.key)
	if err != nil {
		return fmt.Errorf("Failed to marshal key: %w", err)
	}
	if _, err = file.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})); err != nil {
		return fmt.Errorf("Failed to write key file: %w", err)
	}
	return nil
}
