package sshutils_test

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

func TestListen_InUse(t *testing.T) {
	t.Parallel()
	//nolint:exhaustivestruct,exhaustruct
	serverConfig := &ssh.ServerConfig{}
	listener1, err := sshutils.Listen("localhost:0", serverConfig)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener1.Close()
	listener2, err := sshutils.Listen(listener1.Addr().String(), serverConfig)
	if expectedError := "failed to listen: listen tcp"; err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Listen() error = %v, want %q", err, expectedError)
	}
	if listener2 != nil {
		defer listener2.Close()
	}
}

func TestAcceptDial_FailedToEstablish(t *testing.T) {
	t.Parallel()
	//nolint:exhaustivestruct,exhaustruct
	serverConfig := &ssh.ServerConfig{}
	listener, err := sshutils.Listen("localhost:0", serverConfig)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	//nolint:exhaustivestruct,exhaustruct
	clientConfig := &ssh.ClientConfig{}
	errChan := make(chan error)
	go func() {
		conn, err := sshutils.Dial(listener.Addr().String(), clientConfig)
		if conn != nil {
			conn.Close()
		}
		errChan <- err
	}()
	conn, err := listener.Accept()
	if conn != nil {
		defer conn.Close()
	}
	expectedError := "failed to establish SSH connection: ssh: server has no host keys"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Accept() error = %v, want %q", err, expectedError)
	}
	expectedError = "failed to establish SSH connection: ssh: must specify HostKeyCallback"
	if err = <-errChan; err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Dial() error = %v, want %q", err, expectedError)
	}
}

func TestDial_Error(t *testing.T) {
	t.Parallel()
	//nolint:exhaustivestruct,exhaustruct
	clientConfig := &ssh.ClientConfig{}
	conn, err := sshutils.Dial("localhost:0", clientConfig)
	if conn != nil {
		defer conn.Close()
	}
	expectedError := "failed to dial: dial tcp"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Dial() error = %v, want %q", err, expectedError)
	}
}

func TestConn(t *testing.T) {
	t.Parallel()

	//nolint:exhaustivestruct,exhaustruct
	serverConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	key, err := sshutils.GenerateHostKey(nil, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	serverConfig.AddHostKey(key)

	//nolint:exhaustivestruct,exhaustruct
	clientConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	listener, err := sshutils.Listen("localhost:0", serverConfig)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	clientConnChan := make(chan *sshutils.Conn)
	go func() {
		clientConn, err := sshutils.Dial(listener.Addr().String(), clientConfig)
		if err != nil {
			t.Errorf("Dial() error = %v", err)
		}
		clientConnChan <- clientConn
	}()

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer serverConn.Close()

	clientConn := <-clientConnChan
	if clientConn == nil {
		t.Fatal("Dial() = nil")
	}

	expectedString := hex.EncodeToString(clientConn.SessionID())
	if clientConn.String() != expectedString {
		t.Errorf("String() = %v, want %v", clientConn.String(), expectedString)
	}
	if serverConn.String() != expectedString {
		t.Errorf("String() = %v, want %v", serverConn.String(), expectedString)
	}

	_, _, err = clientConn.Request("tcpip-forward", false, &sshutils.TcpipForwardRequestPayload{"foo", 42})
	if err != nil {
		t.Errorf("Request() error = %v", err)
	}
	request := <-serverConn.Requests
	expectedString = "tcpip-forward: foo:42"
	if payload, err := request.UnmarshalPayload(); err != nil {
		t.Errorf("UnmarshalPayload() error = %v", err)
	} else if payload.String() != expectedString {
		t.Errorf("String() = %v, want %v", payload.String(), expectedString)
	}
	expectedVersion := "SSH-2.0-Go"
	if string(request.ConnMetadata().ClientVersion()) != expectedVersion {
		t.Errorf("ClientVersion() = %v, want %v", string(request.ConnMetadata().ClientVersion()), expectedVersion)
	}
	expectedString = "tcpip-forward"
	if request.String() != expectedString {
		t.Errorf("String() = %v, want %v", request.String(), expectedString)
	}
	channels := make(chan *sshutils.Channel)
	go func() {
		newChannel := <-clientConn.NewChannels
		if err := newChannel.Reject(ssh.Prohibited, "foo"); err != nil {
			t.Errorf("Reject() error = %v", err)
			channels <- nil
			return
		}
		newChannel = <-clientConn.NewChannels
		expectedString := "tun: ethernet, interface: 0"
		if payload, err := newChannel.UnmarshalPayload(); err != nil {
			t.Errorf("UnmarshalPayload() error = %v", err)
		} else if payload.String() != expectedString {
			t.Errorf("String() = %v, want %v", payload.String(), expectedString)
		}
		if string(newChannel.ConnMetadata().ClientVersion()) != expectedVersion {
			t.Errorf("ClientVersion() = %v, want %v", string(newChannel.ConnMetadata().ClientVersion()), expectedVersion)
		}
		expectedString = "tun@openssh.com"
		if newChannel.String() != expectedString {
			t.Errorf("String() = %v, want %v", newChannel.String(), expectedString)
		}
		channel, err := newChannel.AcceptChannel()
		if err != nil {
			t.Errorf("AcceptChannel() error = %v", err)
			channels <- nil
			return
		}
		channels <- channel
	}()
	_, err = serverConn.Channel("foo", nil)
	expectedError := "failed to open channel: ssh: rejected: administratively prohibited (foo)"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Channel() error = %v, want %v", err, expectedError)
	}
	serverChannel, err := serverConn.Channel("tun@openssh.com",
		&sshutils.TunChannelPayload{sshutils.TunChannelModeEthernet, 0})
	if err != nil {
		t.Errorf("Channel() error = %v", err)
	}
	clientChannel := <-channels
	if clientChannel == nil {
		t.Fatal("AcceptChannel() = nil")
	}
	if serverChannel != nil && clientChannel != nil {
		expectedChannelID := "0"
		if serverChannel.ChannelID() != expectedChannelID {
			t.Errorf("ChannelID() = %v, want %v", serverChannel.ChannelID(), expectedChannelID)
		}
		if clientChannel.ChannelID() != expectedChannelID {
			t.Errorf("ChannelID() = %v, want %v", clientChannel.ChannelID(), expectedChannelID)
		}
		expectedType := "tun@openssh.com"
		if serverChannel.ChannelType() != expectedType {
			t.Errorf("ChannelType() = %v, want %v", serverChannel.ChannelType(), expectedType)
		}
		if clientChannel.ChannelType() != expectedType {
			t.Errorf("ChannelType() = %v, want %v", clientChannel.ChannelType(), expectedType)
		}
		if string(serverChannel.ConnMetadata().ClientVersion()) != expectedVersion {
			t.Errorf("ClientVersion() = %v, want %v", string(serverChannel.ConnMetadata().ClientVersion()), expectedVersion)
		}
		if string(clientChannel.ConnMetadata().ClientVersion()) != expectedVersion {
			t.Errorf("ClientVersion() = %v, want %v", string(clientChannel.ConnMetadata().ClientVersion()), expectedVersion)
		}
		expectedString = "0"
		if serverChannel.String() != expectedString {
			t.Errorf("String() = %v, want %v", serverChannel.String(), expectedString)
		}
		if clientChannel.String() != expectedString {
			t.Errorf("String() = %v, want %v", clientChannel.String(), expectedString)
		}

		_, err = serverChannel.Request("env", false, &sshutils.EnvRequestPayload{"foo", "bar"})
		if err != nil {
			t.Errorf("Request() error = %v", err)
		}
		channelRequest := <-clientChannel.Requests
		expectedString = "env: foo=bar"
		if payload, err := channelRequest.UnmarshalPayload(); err != nil {
			t.Errorf("UnmarshalPayload() error = %v", err)
		} else if payload.String() != expectedString {
			t.Errorf("String() = %v, want %v", payload.String(), expectedString)
		}
		if channelRequest.Channel().ChannelID() != expectedChannelID {
			t.Errorf("ChannelID() = %v, want %v", channelRequest.Channel().ChannelID(), expectedChannelID)
		}
		if string(channelRequest.ConnMetadata().ClientVersion()) != expectedVersion {
			t.Errorf("ClientVersion() = %v, want %v", string(channelRequest.ConnMetadata().ClientVersion()), expectedVersion)
		}
		expectedString = "env"
		if channelRequest.String() != expectedString {
			t.Errorf("String() = %v, want %v", channelRequest.String(), expectedString)
		}

		serverChannel.Close()
		_, err = clientChannel.Request("foo", true, nil)
		expectedError := "failed to send request: EOF"
		if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
			t.Errorf("Request() error = %v, want %v", err, expectedError)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		newChannel := <-clientConn.NewChannels
		clientConn.Close()
		_, err = newChannel.AcceptChannel()
		expectedError = "failed to open channel"
		if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
			t.Errorf("AcceptChannel() error = %v, want %v", err, expectedError)
		}
	}()
	_, err = serverConn.Channel("closing", nil)
	expectedError = "failed to open channel: ssh:"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Channel() error = %v, want %v", err, expectedError)
	}
	wg.Wait()

	_, _, err = serverConn.Request("foo", true, nil)
	expectedError = "failed to send request: EOF"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Request() error = %v, want %q", err, expectedError)
	}
	_, err = clientConn.Channel("bar", nil)
	expectedError = "failed to open channel: read tcp"
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Channel() error = %v, want %q", err, expectedError)
	}
}
