package sshutils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

var (
	ErrEstablishSSH = errors.New("failed to establish SSH connection")
	ErrSendRequest  = errors.New("failed to send request")
	ErrChannelOpen  = errors.New("failed to open channel")
)

type Listener struct {
	net.Listener
	config ssh.ServerConfig
}

func (listener *Listener) Accept() (*Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}
	sshConn, sshNewChannels, sshRequests, err := ssh.NewServerConn(conn, &listener.config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrEstablishSSH, err)
	}
	return handleConn(sshConn, sshNewChannels, sshRequests), nil
}

func Listen(address string, config *ssh.ServerConfig) (*Listener, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	return &Listener{l, *config}, nil
}

type Conn struct {
	ssh.Conn
	NewChannels   <-chan *NewChannel
	Requests      <-chan *GlobalRequest
	nextChannelID int
}

func (conn *Conn) RawChannel(name string, payload []byte) (*Channel, error) {
	sshChannel, sshRequests, err := conn.Conn.OpenChannel(name, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChannelOpen, err)
	}
	return handleChannel(sshChannel, sshRequests, conn, name), nil
}

func (conn *Conn) Channel(name string, payload Payload) (*Channel, error) {
	var data []byte
	if payload != nil {
		data = payload.Marshal()
	}
	return conn.RawChannel(name, data)
}

func (conn *Conn) RawRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	accepted, reply, err := conn.SendRequest(name, wantReply, payload)
	if err != nil {
		return false, nil, fmt.Errorf("%w: %v", ErrSendRequest, err)
	}
	return accepted, reply, nil
}

func (conn *Conn) Request(name string, wantReply bool, payload Payload) (bool, []byte, error) {
	var data []byte
	if payload != nil {
		data = payload.Marshal()
	}
	return conn.RawRequest(name, wantReply, data)
}

func (conn *Conn) String() string {
	return hex.EncodeToString(conn.SessionID())
}

func Dial(address string, config *ssh.ClientConfig) (*Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	sshConn, sshNewChannels, sshRequests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrEstablishSSH, err)
	}
	return handleConn(sshConn, sshNewChannels, sshRequests), nil
}

func handleConn(sshConn ssh.Conn, sshNewChannels <-chan ssh.NewChannel, sshRequests <-chan *ssh.Request) *Conn {
	newChannels := make(chan *NewChannel)
	requests := make(chan *GlobalRequest)
	connection := &Conn{
		Conn:          sshConn,
		NewChannels:   newChannels,
		Requests:      requests,
		nextChannelID: 0,
	}
	go func() {
		for sshNewChannels != nil || sshRequests != nil {
			select {
			case newChannel, ok := <-sshNewChannels:
				if !ok {
					close(newChannels)
					sshNewChannels = nil
					continue
				}
				newChannels <- &NewChannel{newChannel, connection}
			case request, ok := <-sshRequests:
				if !ok {
					close(requests)
					sshRequests = nil
					continue
				}
				requests <- &GlobalRequest{request, connection}
			}
		}
	}()
	return connection
}

type NewChannel struct {
	ssh.NewChannel
	conn *Conn
}

func (newChannel *NewChannel) AcceptChannel() (*Channel, error) {
	sshChannel, sshRequests, err := newChannel.Accept()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChannelOpen, err)
	}
	return handleChannel(sshChannel, sshRequests, newChannel.conn, newChannel.ChannelType()), nil
}

func (newChannel *NewChannel) UnmarshalPayload() (Payload, error) {
	return UnmarshalNewChannelPayload(newChannel)
}

func (newChannel *NewChannel) ConnMetadata() ssh.ConnMetadata {
	return newChannel.conn
}

func (newChannel *NewChannel) String() string {
	return newChannel.ChannelType()
}

type Channel struct {
	ssh.Channel
	Requests    <-chan *ChannelRequest
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

func (channel *Channel) ConnMetadata() ssh.ConnMetadata {
	return channel.conn
}

func (channel *Channel) RawRequest(name string, wantReply bool, payload []byte) (bool, error) {
	accepted, err := channel.SendRequest(name, wantReply, payload)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrSendRequest, err)
	}
	return accepted, nil
}

func (channel *Channel) Request(name string, wantReply bool, payload Payload) (bool, error) {
	var data []byte
	if payload != nil {
		data = payload.Marshal()
	}
	return channel.RawRequest(name, wantReply, data)
}

func (channel *Channel) String() string {
	return channel.channelID
}

func handleChannel(sshChannel ssh.Channel, sshRequests <-chan *ssh.Request, conn *Conn, name string) *Channel {
	requests := make(chan *ChannelRequest)
	channel := &Channel{sshChannel, requests, fmt.Sprint(conn.nextChannelID), name, conn}
	go func() {
		for request := range sshRequests {
			requests <- &ChannelRequest{request, channel}
		}
		close(requests)
	}()
	conn.nextChannelID++
	return channel
}

type GlobalRequest struct {
	*ssh.Request
	conn *Conn
}

func (request *GlobalRequest) UnmarshalPayload() (Payload, error) {
	return UnmarshalGlobalRequestPayload(request.Request)
}

func (request *GlobalRequest) ConnMetadata() ssh.ConnMetadata {
	return request.conn
}

func (request *GlobalRequest) String() string {
	return request.Request.Type
}

type ChannelRequest struct {
	*ssh.Request
	channel *Channel
}

func (request *ChannelRequest) UnmarshalPayload() (Payload, error) {
	return UnmarshalChannelRequestPayload(request.Request)
}

func (request *ChannelRequest) Channel() *Channel {
	return request.channel
}

func (request *ChannelRequest) ConnMetadata() ssh.ConnMetadata {
	return request.channel.conn
}

func (request *ChannelRequest) String() string {
	return request.Request.Type
}
