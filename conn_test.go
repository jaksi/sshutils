package sshutils_test

import (
	"bytes"
	"testing"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

func TestConn(t *testing.T) {
	serverConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	hostKey, err := sshutils.GenerateHostKey(sshutils.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig.AddHostKey(hostKey)

	serverConnections, err := sshutils.Listen("127.0.0.1:2022", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	clientConnection, err := sshutils.Dial("127.0.0.1:2022", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	serverConnection := <-serverConnections
	defer serverConnection.Close()

	clientC2SChan := make(chan *sshutils.Channel)
	go func() {
		clientC2S, err := clientConnection.OpenChannel("c2s", []byte{0x42})
		if err != nil {
			t.Error(err)
		}
		clientC2SChan <- clientC2S
	}()
	newServerC2S := <-serverConnection.NewChannels
	if newServerC2S.ChannelType() != "c2s" {
		t.Fatalf("serverC2S.ChannelType() = %v, want %v", newServerC2S.ChannelType(), "c2s")
	}
	if !bytes.Equal(newServerC2S.ExtraData(), []byte{0x42}) {
		t.Fatalf("serverC2S.ExtraData() = %v, want %v", newServerC2S.ExtraData(), []byte{0x42})
	}
	serverC2S, err := newServerC2S.Accept()
	if err != nil {
		t.Fatal(err)
	}
	clientC2S := <-clientC2SChan
	if clientC2S.ChannelID() != serverC2S.ChannelID() {
		t.Fatalf("clientC2S.ChannelID() = %v, want %v", clientC2S.ChannelID(), serverC2S.ChannelID())
	}

	go func() {
		if _, err := clientConnection.OpenChannel("c2s_fail", []byte{0x43}); err == nil {
			t.Error("OpenChannel(c2s_fail) should fail")
		}
	}()
	newServerC2SFail := <-serverConnection.NewChannels
	if newServerC2SFail.ChannelType() != "c2s_fail" {
		t.Fatalf("serverC2SFail.ChannelType() = %v, want %v", newServerC2SFail.ChannelType(), "c2s_fail")
	}
	if !bytes.Equal(newServerC2SFail.ExtraData(), []byte{0x43}) {
		t.Fatalf("serverC2SFail.ExtraData() = %v, want %v", newServerC2SFail.ExtraData(), []byte{0x43})
	}
	if err := newServerC2SFail.Reject(ssh.Prohibited, ""); err != nil {
		t.Fatal(err)
	}

	serverS2CChan := make(chan *sshutils.Channel)
	go func() {
		serverS2C, err := serverConnection.OpenChannel("s2c", []byte{0x44})
		if err != nil {
			t.Error(err)
		}
		serverS2CChan <- serverS2C
	}()
	newClientS2C := <-clientConnection.NewChannels
	if newClientS2C.ChannelType() != "s2c" {
		t.Fatalf("clientS2C.ChannelType() = %v, want %v", newClientS2C.ChannelType(), "s2c")
	}
	if !bytes.Equal(newClientS2C.ExtraData(), []byte{0x44}) {
		t.Fatalf("clientS2C.ExtraData() = %v, want %v", newClientS2C.ExtraData(), []byte{0x44})
	}
	clientS2C, err := newClientS2C.Accept()
	if err != nil {
		t.Fatal(err)
	}
	serverS2C := <-serverS2CChan
	if serverS2C.ChannelID() != clientS2C.ChannelID() {
		t.Fatalf("serverS2C.ChannelID() = %v, want %v", serverS2C.ChannelID(), clientS2C.ChannelID())
	}

	go func() {
		if _, err := serverConnection.OpenChannel("s2c_fail", []byte{0x45}); err == nil {
			t.Error("OpenChannel(s2c_fail) should fail")
		}
	}()
	newClientS2CFail := <-clientConnection.NewChannels
	if newClientS2CFail.ChannelType() != "s2c_fail" {
		t.Fatalf("clientS2CFail.ChannelType() = %v, want %v", newClientS2CFail.ChannelType(), "s2c_fail")
	}
	if !bytes.Equal(newClientS2CFail.ExtraData(), []byte{0x45}) {
		t.Fatalf("clientS2CFail.ExtraData() = %v, want %v", newClientS2CFail.ExtraData(), []byte{0x45})
	}
	if err := newClientS2CFail.Reject(ssh.Prohibited, ""); err != nil {
		t.Fatal(err)
	}

	if _, err := sshutils.Listen("test.invalid:2022", serverConfig); err == nil {
		t.Error("Listen(test.invalid:2022) should fail")
	}

	if _, err := sshutils.Dial("test.invalid:2022", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}); err == nil {
		t.Error("Dial(test.invalid:2022) should fail")
	}

	if _, err := sshutils.Dial("127.0.0.1:2022", &ssh.ClientConfig{}); err == nil {
		t.Error("Dial() should fail")
	}
}
