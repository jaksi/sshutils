package sshutils

import (
	"encoding/base64"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

type Conn struct {
	ssh.Conn
	NewChannels   <-chan *NewChannel
	Requests      <-chan *ssh.Request
	nextChannelID int
}

func (conn *Conn) NewChannel(name string, data []byte) (*Channel, error) {
	sshChannel, requests, err := conn.Conn.OpenChannel(name, data)
	if err != nil {
		return nil, fmt.Errorf("Failed to open channel: %w", err)
	}
	channel := &Channel{sshChannel, requests, fmt.Sprint(conn.nextChannelID), name, conn}
	conn.nextChannelID++
	return channel, nil
}

func (conn *Conn) String() string {
	return base64.StdEncoding.EncodeToString(conn.SessionID())
}

func (conn *Conn) Request(name string, wantReply bool, payload Payload) (bool, []byte, error) {
	accepted, reply, err := conn.SendRequest(name, wantReply, payload.Marshal())
	if err != nil {
		return false, nil, fmt.Errorf("Failed to send request: %w", err)
	}
	return accepted, reply, nil
}

type NewChannel struct {
	ssh.NewChannel
	conn *Conn
}

func (newChannel *NewChannel) AcceptChannel() (*Channel, error) {
	sshChannel, requests, err := newChannel.NewChannel.Accept()
	if err != nil {
		return nil, fmt.Errorf("Failed to accept channel: %w", err)
	}
	channel := &Channel{
		sshChannel, requests,
		fmt.Sprint(newChannel.conn.nextChannelID), newChannel.ChannelType(), newChannel.conn,
	}
	newChannel.conn.nextChannelID++
	return channel, nil
}

func (newChannel *NewChannel) String() string {
	return newChannel.ChannelType()
}

func (newChannel *NewChannel) Payload() (Payload, error) {
	return UnmarshalNewChannelPayload(newChannel)
}

func (newChannel *NewChannel) ConnMetadata() ssh.ConnMetadata {
	return newChannel.conn
}

type Channel struct {
	ssh.Channel
	Requests    <-chan *ssh.Request
	channelID   string
	channelType string
	conn        *Conn
}

func (channel *Channel) ChannelID() string {
	return channel.channelID
}

func (channel *Channel) ChannelType() string {
	return channel.channelType
}

func (channel *Channel) String() string {
	return channel.channelID
}

func (channel *Channel) ConnMetadata() ssh.ConnMetadata {
	return channel.conn
}

func (channel *Channel) Request(name string, wantReply bool, payload Payload) (bool, error) {
	accepted, err := channel.SendRequest(name, wantReply, payload.Marshal())
	if err != nil {
		return false, fmt.Errorf("Failed to send request: %w", err)
	}
	return accepted, nil
}

func Dial(address string, config *ssh.ClientConfig) (*Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("Failed to dial: %w", err)
	}
	sshConn, sshNewChannels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("Failed to establish SSH client connection: %w", err)
	}
	newChannels := make(chan *NewChannel)
	connection := &Conn{
		Conn:        sshConn,
		NewChannels: newChannels,
		Requests:    requests,
	}
	go func() {
		defer close(newChannels)
		for sshNewChannel := range sshNewChannels {
			newChannels <- &NewChannel{sshNewChannel, connection}
		}
	}()
	return connection, nil
}

type Listener struct {
	net.Listener
	config ssh.ServerConfig
}

func (listener *Listener) Accept() (*Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("Failed to accept connection: %w", err)
	}
	sshConn, sshNewChannels, requests, err := ssh.NewServerConn(conn, &listener.config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("Failed to establish SSH server connection: %w", err)
	}
	newChannels := make(chan *NewChannel)
	connection := &Conn{
		Conn:        sshConn,
		NewChannels: newChannels,
		Requests:    requests,
	}
	go func() {
		defer close(newChannels)
		for sshNewChannel := range sshNewChannels {
			newChannels <- &NewChannel{sshNewChannel, connection}
		}
	}()
	return connection, nil
}

func Listen(address string, config *ssh.ServerConfig) (*Listener, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("Failed to listen: %w", err)
	}
	return &Listener{l, *config}, nil
}
