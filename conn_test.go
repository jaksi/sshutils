package sshutils_test

import (
	"testing"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

func TestDialFail(t *testing.T) {
	t.Parallel()
	_, err := sshutils.Dial("localhost:0", &ssh.ClientConfig{})
	if err == nil {
		t.Fatal("dial should fail")
	}
}

func TestListenFail(t *testing.T) {
	t.Parallel()
	_, err := sshutils.Listen("example.org:0", &ssh.ServerConfig{})
	if err == nil {
		t.Fatal("listen should fail")
	}
}

func TestConnFail(t *testing.T) {
	t.Parallel()
	hostKey, err := sshutils.GenerateHostKey(sshutils.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	serverConfig.AddHostKey(hostKey)
	listener, err := sshutils.Listen("localhost:0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		serverConn, err := listener.Accept()
		if err == nil {
			serverConn.Close()
			t.Error("accept should fail")
		}
	}()
	if clientConn, err := sshutils.Dial(listener.Addr().String(),
		&ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()}); err == nil {
		clientConn.Close()
		t.Fatal("dial should fail")
	}
}

func getConnPair(t *testing.T) (*sshutils.Conn, *sshutils.Conn) {
	t.Helper()
	hostKey, err := sshutils.GenerateHostKey(sshutils.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostKey)
	listener, err := sshutils.Listen("localhost:0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverConnChan := make(chan *sshutils.Conn)
	go func() {
		serverConn, err := listener.Accept()
		if err != nil {
			t.Error(err)
			serverConnChan <- nil
			return
		}
		serverConnChan <- serverConn
	}()
	clientConn, err := sshutils.Dial(listener.Addr().String(),
		&ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	serverConn := <-serverConnChan
	return clientConn, serverConn
}

func TestConn(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := getConnPair(t)
	if clientConn == nil {
		t.Fatal("client connection is nil")
	}
	if serverConn == nil {
		t.Fatal("server connection is nil")
	}
	defer clientConn.Close()
	defer serverConn.Close()
	if clientConn.String() != serverConn.String() {
		t.Error("client and server connection strings are not equal")
	}
}

func TestGlobalRequest(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := getConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()
	payload := &sshutils.TcpipForwardRequestPayload{
		Address: "localhost",
		Port:    80,
	}
	_, _, err := clientConn.Request("tcpip-forward", false, payload)
	if err != nil {
		t.Fatal(err)
	}
	serverRequest := <-serverConn.Requests
	if serverRequest.Type != "tcpip-forward" {
		t.Error("wrong request type")
	}
	if serverRequest.WantReply != false {
		t.Error("want reply is not false")
	}
	serverPayload, err := sshutils.UnmarshalGlobalRequestPayload(serverRequest)
	if err != nil {
		t.Fatal(err)
	}
	concreteServerPayload, ok := serverPayload.(*sshutils.TcpipForwardRequestPayload)
	if !ok {
		t.Fatal("wrong payload type")
	}
	if *concreteServerPayload != *payload {
		t.Error("wrong payload")
	}
}

func TestChannelFail(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := getConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()
	go func() {
		newChannel := <-serverConn.NewChannels
		if err := newChannel.Reject(ssh.Prohibited, "test"); err != nil {
			t.Error(err)
		}
	}()
	if clientChannel, err := clientConn.Channel("test", nil); err == nil {
		clientChannel.Close()
		t.Error("new channel should fail")
	}
}

func getChannelPair(t *testing.T, clientConn, serverConn *sshutils.Conn) (*sshutils.Channel, *sshutils.Channel) {
	t.Helper()
	name := "direct-tcpip"
	payload := &sshutils.DirectTcpipChannelPayload{
		Address:           "localhost",
		Port:              80,
		OriginatorAddress: "localhost",
		OriginatorPort:    8080,
	}
	serverChannelChan := make(chan *sshutils.Channel)
	go func() {
		newChannel := <-serverConn.NewChannels
		if newChannel.String() != name {
			t.Error("wrong channel name")
		}
		if newChannel.ConnMetadata() != serverConn {
			t.Error("wrong connection metadata")
		}
		serverPayload, err := newChannel.Payload()
		if err != nil {
			t.Error(err)
		}
		concreteServerPayload, ok := serverPayload.(*sshutils.DirectTcpipChannelPayload)
		if !ok {
			t.Error("wrong payload type")
		}
		if *concreteServerPayload != *payload {
			t.Error("wrong payload")
		}
		serverChannel, err := newChannel.AcceptChannel()
		if err != nil {
			t.Error(err)
			serverChannelChan <- nil
			return
		}
		serverChannelChan <- serverChannel
	}()
	clientChannel, err := clientConn.Channel(name, payload)
	if err != nil {
		t.Fatal(err)
	}
	serverChannel := <-serverChannelChan
	return clientChannel, serverChannel
}

func testChannel(t *testing.T, conn1, conn2 *sshutils.Conn) {
	t.Helper()
	channel1, channel2 := getChannelPair(t, conn1, conn2)
	if channel1 == nil {
		t.Fatal("channel1 is nil")
	}
	if channel2 == nil {
		t.Fatal("channel2 is nil")
	}
	if channel1.String() != channel2.String() {
		t.Error("channel strings are not equal")
	}
	if channel1.ChannelID() != channel2.ChannelID() {
		t.Error("channel ids are not equal")
	}
	if channel1.ChannelType() != channel2.ChannelType() {
		t.Error("channel types are not equal")
	}
	if channel1.ConnMetadata() != conn1 {
		t.Error("connection metadata for channel1 is not conn1")
	}
	if channel2.ConnMetadata() != conn2 {
		t.Error("connection metadata for channel2 is not conn2")
	}
}

func TestChannelC2S(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := getConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()
	testChannel(t, clientConn, serverConn)
}

func TestChannelS2C(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := getConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()
	testChannel(t, serverConn, clientConn)
}

func TestChannelRequest(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := getConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()
	clientChannel, serverChannel := getChannelPair(t, clientConn, serverConn)
	payload := &sshutils.ExecRequestPayload{"/usr/bin/whoami"}
	_, err := clientChannel.Request("exec", false, payload)
	if err != nil {
		t.Fatal(err)
	}
	serverRequest := <-serverChannel.Requests
	if serverRequest.Type != "exec" {
		t.Error("wrong request type")
	}
	if serverRequest.WantReply != false {
		t.Error("want reply is not false")
	}
	serverPayload, err := sshutils.UnmarshalChannelRequestPayload(serverRequest)
	if err != nil {
		t.Fatal(err)
	}
	concreteServerPayload, ok := serverPayload.(*sshutils.ExecRequestPayload)
	if !ok {
		t.Fatal("wrong payload type")
	}
	if *concreteServerPayload != *payload {
		t.Error("wrong payload")
	}
}
