package sshutils

import (
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

func (conn *Conn) OpenChannel(name string, data []byte) (*Channel, error) {
	sshChannel, requests, err := conn.Conn.OpenChannel(name, data)
	if err != nil {
		return nil, err
	}
	channel := &Channel{sshChannel, requests, fmt.Sprint(conn.nextChannelID)}
	conn.nextChannelID++
	return channel, nil
}

type NewChannel struct {
	ssh.NewChannel
	conn *Conn
}

func (newChannel *NewChannel) Accept() (*Channel, error) {
	sshChannel, requests, err := newChannel.NewChannel.Accept()
	if err != nil {
		return nil, err
	}
	channel := &Channel{sshChannel, requests, fmt.Sprint(newChannel.conn.nextChannelID)}
	newChannel.conn.nextChannelID++
	return channel, nil
}

type Channel struct {
	ssh.Channel
	Requests  <-chan *ssh.Request
	channelID string
}

func (channel *Channel) ChannelID() string {
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
		NewChannels: newChannels,
		Requests:    requests,
	}
	go func() {
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
				NewChannels: newChannels,
				Requests:    requests,
			}
			go func() {
				for sshNewChannel := range sshNewChannels {
					newChannels <- &NewChannel{sshNewChannel, connection}
				}
			}()
			connections <- connection
		}
	}()
	return connections, nil
}
