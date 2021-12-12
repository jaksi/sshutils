package sshutils_test

import (
	"bytes"
	"encoding/base64"
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

	listener, err := sshutils.Listen("127.0.0.1:2022", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	var serverConnection *sshutils.Conn
	var serverConnectionErr error
	go func() {
		serverConnection, serverConnectionErr = listener.Accept()
	}()
	clientConnection, err := sshutils.Dial("127.0.0.1:2022", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()

	expectedString := base64.StdEncoding.EncodeToString(clientConnection.SessionID())
	if clientConnection.String() != expectedString {
		t.Errorf("clientConnection.String() = %v, want %v", clientConnection.String(), expectedString)
	}

	if serverConnectionErr != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()

	expectedString = base64.StdEncoding.EncodeToString(serverConnection.SessionID())
	if serverConnection.String() != expectedString {
		t.Errorf("serverConnection.String() = %v, want %v", serverConnection.String(), expectedString)
	}

	clientC2SChan := make(chan *sshutils.Channel)
	go func() {
		clientC2S, err := clientConnection.NewChannel("c2s", []byte{0x42})
		if err != nil {
			t.Error(err)
		}
		clientC2SChan <- clientC2S
	}()
	newServerC2S := <-serverConnection.NewChannels
	if newServerC2S.ChannelType() != "c2s" {
		t.Errorf("serverC2S.ChannelType() = %v, want %v", newServerC2S.ChannelType(), "c2s")
	}
	if !bytes.Equal(newServerC2S.ExtraData(), []byte{0x42}) {
		t.Errorf("serverC2S.ExtraData() = %v, want %v", newServerC2S.ExtraData(), []byte{0x42})
	}
	if newServerC2S.String() != "c2s" {
		t.Errorf("serverC2S.String() = %v, want %v", newServerC2S.String(), "c2s")
	}
	if !bytes.Equal(newServerC2S.ConnMetadata().SessionID(), clientConnection.SessionID()) {
		t.Errorf("serverC2S.ConnMetadata().SessionID() = %v, want %v", newServerC2S.ConnMetadata().SessionID(), clientConnection.SessionID())
	}
	serverC2S, err := newServerC2S.AcceptChannel()
	if err != nil {
		t.Fatal(err)
	}
	if serverC2S.String() != "0" {
		t.Errorf("serverC2S.String() = %v, want %v", serverC2S.String(), "0")
	}
	if serverC2S.ChannelType() != "c2s" {
		t.Errorf("serverC2S.ChannelType() = %v, want %v", serverC2S.ChannelType(), "c2s")
	}
	if !bytes.Equal(serverC2S.ConnMetadata().SessionID(), serverConnection.SessionID()) {
		t.Errorf("serverC2S.ConnMetadata().SessionID() = %v, want %v", serverC2S.ConnMetadata().SessionID(), serverConnection.SessionID())
	}
	clientC2S := <-clientC2SChan
	if clientC2S.String() != "0" {
		t.Errorf("clientC2S.String() = %v, want %v", clientC2S.String(), "0")
	}
	if clientC2S.ChannelID() != serverC2S.ChannelID() {
		t.Errorf("clientC2S.ChannelID() = %v, want %v", clientC2S.ChannelID(), serverC2S.ChannelID())
	}
	if clientC2S.ChannelType() != "c2s" {
		t.Errorf("clientC2S.ChannelType() = %v, want %v", clientC2S.ChannelType(), "c2s")
	}
	if !bytes.Equal(clientC2S.ConnMetadata().SessionID(), clientConnection.SessionID()) {
		t.Errorf("clientC2S.ConnMetadata().SessionID() = %v, want %v", clientC2S.ConnMetadata().SessionID(), clientConnection.SessionID())
	}

	go func() {
		if _, err := clientConnection.NewChannel("c2s_fail", []byte{0x43}); err == nil {
			t.Error("OpenChannel(c2s_fail) should fail")
		}
	}()
	newServerC2SFail := <-serverConnection.NewChannels
	if newServerC2SFail.ChannelType() != "c2s_fail" {
		t.Errorf("serverC2SFail.ChannelType() = %v, want %v", newServerC2SFail.ChannelType(), "c2s_fail")
	}
	if !bytes.Equal(newServerC2SFail.ExtraData(), []byte{0x43}) {
		t.Errorf("serverC2SFail.ExtraData() = %v, want %v", newServerC2SFail.ExtraData(), []byte{0x43})
	}
	if err := newServerC2SFail.Reject(ssh.Prohibited, ""); err != nil {
		t.Fatal(err)
	}

	serverS2CChan := make(chan *sshutils.Channel)
	go func() {
		serverS2C, err := serverConnection.NewChannel("s2c", []byte{0x44})
		if err != nil {
			t.Error(err)
		}
		serverS2CChan <- serverS2C
	}()
	newClientS2C := <-clientConnection.NewChannels
	if newClientS2C.ChannelType() != "s2c" {
		t.Errorf("clientS2C.ChannelType() = %v, want %v", newClientS2C.ChannelType(), "s2c")
	}
	if !bytes.Equal(newClientS2C.ExtraData(), []byte{0x44}) {
		t.Errorf("clientS2C.ExtraData() = %v, want %v", newClientS2C.ExtraData(), []byte{0x44})
	}
	if newClientS2C.String() != "s2c" {
		t.Errorf("clientS2C.String() = %v, want %v", newClientS2C.String(), "s2c")
	}
	if !bytes.Equal(newClientS2C.ConnMetadata().SessionID(), serverConnection.SessionID()) {
		t.Errorf("clientS2C.ConnMetadata().SessionID() = %v, want %v", newClientS2C.ConnMetadata().SessionID(), serverConnection.SessionID())
	}
	clientS2C, err := newClientS2C.AcceptChannel()
	if err != nil {
		t.Fatal(err)
	}
	if clientS2C.String() != "1" {
		t.Errorf("clientS2C.String() = %v, want %v", clientS2C.String(), "1")
	}
	if clientS2C.ChannelType() != "s2c" {
		t.Errorf("clientS2C.ChannelType() = %v, want %v", clientS2C.ChannelType(), "s2c")
	}
	if !bytes.Equal(clientS2C.ConnMetadata().SessionID(), clientConnection.SessionID()) {
		t.Errorf("clientS2C.ConnMetadata().SessionID() = %v, want %v", clientS2C.ConnMetadata().SessionID(), clientConnection.SessionID())
	}
	serverS2C := <-serverS2CChan
	if serverS2C.String() != "1" {
		t.Errorf("serverS2C.String() = %v, want %v", serverS2C.String(), "1")
	}
	if serverS2C.ChannelID() != clientS2C.ChannelID() {
		t.Errorf("serverS2C.ChannelID() = %v, want %v", serverS2C.ChannelID(), clientS2C.ChannelID())
	}
	if serverS2C.ChannelType() != "s2c" {
		t.Errorf("serverS2C.ChannelType() = %v, want %v", serverS2C.ChannelType(), "s2c")
	}
	if !bytes.Equal(serverS2C.ConnMetadata().SessionID(), clientConnection.SessionID()) {
		t.Errorf("serverS2C.ConnMetadata().SessionID() = %v, want %v", serverS2C.ConnMetadata().SessionID(), clientConnection.SessionID())
	}

	go func() {
		if _, err := serverConnection.NewChannel("s2c_fail", []byte{0x45}); err == nil {
			t.Error("OpenChannel(s2c_fail) should fail")
		}
	}()
	newClientS2CFail := <-clientConnection.NewChannels
	if newClientS2CFail.ChannelType() != "s2c_fail" {
		t.Errorf("clientS2CFail.ChannelType() = %v, want %v", newClientS2CFail.ChannelType(), "s2c_fail")
	}
	if !bytes.Equal(newClientS2CFail.ExtraData(), []byte{0x45}) {
		t.Errorf("clientS2CFail.ExtraData() = %v, want %v", newClientS2CFail.ExtraData(), []byte{0x45})
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
	listener.Close()

	listener, err = sshutils.Listen("127.0.0.1:2022", &ssh.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		serverConnection, serverConnectionErr = listener.Accept()
	}()
	if _, err := sshutils.Dial("127.0.0.1:2022", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}); err == nil {
		t.Error("Dial() should fail")
	}
	if serverConnectionErr == nil {
		t.Error("listener.Accept() should fail")
	}
}
