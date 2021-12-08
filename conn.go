package sshutils

import (
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

type side int

const (
	client side = iota
	server
)

func (s side) String() string {
	switch s {
	case client:
		return "client"
	case server:
		return "server"
	default:
		return "unknown"
	}
}

type Conn struct {
	ssh.Conn
	s             side
	NewChannels   <-chan *NewChannel
	Requests      <-chan *ssh.Request
	nextChannelID int
}

func (conn *Conn) NewChannel(name string, data []byte) (*Channel, error) {
	sshChannel, requests, err := conn.Conn.OpenChannel(name, data)
	if err != nil {
		return nil, err
	}
	channel := &Channel{sshChannel, requests, fmt.Sprint(conn.nextChannelID)}
	conn.nextChannelID++
	return channel, nil
}

func (conn *Conn) String() string {
	return fmt.Sprintf("%s %s - %s", conn.s, conn.LocalAddr(), conn.RemoteAddr())
}

type NewChannel struct {
	ssh.NewChannel
	conn *Conn
}

func (newChannel *NewChannel) AcceptChannel() (*Channel, error) {
	sshChannel, requests, err := newChannel.NewChannel.Accept()
	if err != nil {
		return nil, err
	}
	channel := &Channel{sshChannel, requests, fmt.Sprint(newChannel.conn.nextChannelID)}
	newChannel.conn.nextChannelID++
	return channel, nil
}

func (newChannel *NewChannel) String() string {
	return newChannel.ChannelType()
}

func (newChannel *NewChannel) Payload() (Payload, error) {
	return UnmarshalNewChannelPayload(newChannel)
}

type Channel struct {
	ssh.Channel
	Requests  <-chan *ssh.Request
	channelID string
}

func (channel *Channel) ChannelID() string {
	return channel.channelID
}

func (channel *Channel) String() string {
	return channel.channelID
}

func Dial(address string, config *ssh.ClientConfig) (*Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	sshConn, sshNewChannels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	newChannels := make(chan *NewChannel)
	connection := &Conn{
		Conn:        sshConn,
		s:           client,
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

func Listen(address string, config *ssh.ServerConfig) (<-chan *Conn, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	connections := make(chan *Conn)
	go func() {
		defer close(connections)
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			sshConn, sshNewChannels, requests, err := ssh.NewServerConn(conn, config)
			if err != nil {
				conn.Close()
				continue
			}
			newChannels := make(chan *NewChannel)
			connection := &Conn{
				Conn:        sshConn,
				s:           server,
				NewChannels: newChannels,
				Requests:    requests,
			}
			go func() {
				defer close(newChannels)
				for sshNewChannel := range sshNewChannels {
					newChannels <- &NewChannel{sshNewChannel, connection}
				}
			}()
			connections <- connection
		}
	}()
	return connections, nil
}
