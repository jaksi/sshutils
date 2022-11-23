package sshutils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	ErrEstablishSSH = errors.New("failed to establish SSH connection")
	ErrSendRequest  = errors.New("failed to send request")
	ErrChannelOpen  = errors.New("failed to open channel")
)

type ConnectHandler func(conn *Conn)

type NewChannelHandler func(newChannel *NewChannel)

type GlobalRequestHandler func(request *GlobalRequest)

type ChannelRequestHandler func(request *ChannelRequest)

type ChannelCloseHandler func(channelMetadata ChannelMetadata)

type CloseHandler func(connMetadata ssh.ConnMetadata)

type Server struct {
	Addr          string
	Connect       ConnectHandler
	NewChannel    NewChannelHandler
	GlobalRequest GlobalRequestHandler
	Close         CloseHandler
	ErrorLog      *log.Logger
	SSHConfig     *ssh.ServerConfig
}

func (s *Server) ListenAndServe() error {
	if s.ErrorLog == nil {
		s.ErrorLog = log.Default()
	}

	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			s.ErrorLog.Printf("failed to accept connection: %v", err)
			continue
		}

		sshConn, ssewChannels, sshRequests, err := ssh.NewServerConn(c, s.SSHConfig)
	}
}

func Serve(
	address string, config *ssh.ServerConfig,
	connectHandler ConnectHandler,
	newChannelHandler NewChannelHandler, globalRequestHandler GlobalRequestHandler,
	closeHandler CloseHandler,
) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}
		sshConn, sshNewChannels, sshRequests, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			tcpConn.Close()
			log.Printf("%v: %v", ErrEstablishSSH, err)
			continue
		}
		conn := handleConn(sshConn, sshNewChannels, sshRequests, newChannelHandler, globalRequestHandler, closeHandler)
		connectHandler(conn)
	}
}

func Dial(
	address string, config *ssh.ClientConfig,
	newChannelHandler NewChannelHandler, globalRequestHandler GlobalRequestHandler, closeHandler CloseHandler,
) (*Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	sshConn, sshNewChannels, sshRequests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrEstablishSSH, err)
	}
	return handleConn(sshConn, sshNewChannels, sshRequests, newChannelHandler, globalRequestHandler, closeHandler), nil
}

func handleConn(
	sshConn ssh.Conn, sshNewChannels <-chan ssh.NewChannel, sshRequests <-chan *ssh.Request,
	newChannelHandler NewChannelHandler, globalRequestHandler GlobalRequestHandler, closeHandler CloseHandler,
) *Conn {
	conn := &Conn{
		sshConn,
		0,
		[]reflect.SelectCase{
			{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sshNewChannels)},
			{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sshRequests)},
		},
		[]*Channel{},
		sync.Mutex{},
	}
	go func() {
		for len(conn.selectCases) > 2 || sshNewChannels != nil || sshRequests != nil {
			conn.mutex.Lock()
			chosen, value, ok := reflect.Select(conn.selectCases)
			var channel *Channel
			if chosen > 1 {
				channel = conn.channels[chosen-2]
				if !ok {
					conn.selectCases = append(conn.selectCases[:chosen], conn.selectCases[chosen+1:]...)
					conn.channels = append(conn.channels[:chosen-2], conn.channels[chosen-1:]...)
				}
			}
			conn.mutex.Unlock()
			if !ok {
				if channel == nil {
					if chosen == 0 {
						sshNewChannels = nil
					} else {
						sshRequests = nil
					}
					closeHandler(conn.conn)
				} else {
					channel.channelCloseHandler(channel)
				}
				continue
			}
			switch chosen {
			case 0:
				//nolint:forcetypeassert
				newChannel := value.Interface().(ssh.NewChannel)
				newChannelHandler(&NewChannel{newChannel, conn})
			case 1:
				//nolint:forcetypeassert
				request := value.Interface().(*ssh.Request)
				globalRequestHandler(&GlobalRequest{request, conn})
			default:
				//nolint:forcetypeassert
				request := value.Interface().(*ssh.Request)
				channel.channelRequestHandler(&ChannelRequest{request, channel})
			}
		}
	}()
	return conn
}

type Conn struct {
	conn          ssh.Conn
	nextChannelID int
	selectCases   []reflect.SelectCase
	channels      []*Channel
	mutex         sync.Mutex
}

func (conn *Conn) OpenChannel(
	name string, payload Payload,
	channelRequestHandler ChannelRequestHandler, channelCloseHandler ChannelCloseHandler,
) (*Channel, error) {
	var data []byte
	if payload != nil {
		data = payload.Marshal()
	}
	sshChannel, sshRequests, err := conn.conn.OpenChannel(name, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChannelOpen, err)
	}
	channel := &Channel{sshChannel, conn, fmt.Sprint(conn.nextChannelID), name, channelRequestHandler, channelCloseHandler}
	conn.mutex.Lock()
	conn.nextChannelID++
	conn.selectCases = append(conn.selectCases,
		reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sshRequests), Send: reflect.ValueOf(nil)})
	conn.channels = append(conn.channels, channel)
	conn.mutex.Unlock()
	return channel, nil
}

func (conn *Conn) SendRequest(name string, wantReply bool, payload Payload) (bool, []byte, error) {
	var data []byte
	if payload != nil {
		data = payload.Marshal()
	}
	accepted, reply, err := conn.conn.SendRequest(name, wantReply, data)
	if err != nil {
		return false, nil, fmt.Errorf("%w: %v", ErrSendRequest, err)
	}
	return accepted, reply, nil
}

func (conn *Conn) String() string {
	return hex.EncodeToString(conn.conn.SessionID())
}

type NewChannel struct {
	newChannel ssh.NewChannel
	conn       *Conn
}

func (newChannel *NewChannel) Accept(
	channelRequestHandler ChannelRequestHandler, channelCloseHandler ChannelCloseHandler,
) (*Channel, error) {
	sshChannel, sshRequests, err := newChannel.newChannel.Accept()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChannelOpen, err)
	}
	channel := &Channel{
		sshChannel,
		newChannel.conn,
		fmt.Sprint(newChannel.conn.nextChannelID),
		newChannel.newChannel.ChannelType(),
		channelRequestHandler, channelCloseHandler,
	}
	newChannel.conn.mutex.Lock()
	newChannel.conn.nextChannelID++
	newChannel.conn.selectCases = append(newChannel.conn.selectCases,
		reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sshRequests), Send: reflect.ValueOf(nil)})
	newChannel.conn.channels = append(newChannel.conn.channels, channel)
	newChannel.conn.mutex.Unlock()
	return channel, nil
}

func (newChannel *NewChannel) Payload() (Payload, error) {
	return UnmarshalNewChannelPayload(newChannel.newChannel)
}

func (newChannel *NewChannel) ConnMetadata() ssh.ConnMetadata {
	return newChannel.conn.conn
}

func (newChannel *NewChannel) String() string {
	return newChannel.newChannel.ChannelType()
}

type Channel struct {
	channel               ssh.Channel
	conn                  *Conn
	channelID             string
	channelType           string
	channelRequestHandler ChannelRequestHandler
	channelCloseHandler   ChannelCloseHandler
}

type ChannelMetadata interface {
	ConnMetadata() ssh.ConnMetadata
	ChannelID() string
	ChannelType() string
}

func (channel *Channel) ConnMetadata() ssh.ConnMetadata {
	return channel.conn.conn
}

func (channel *Channel) ChannelID() string {
	return channel.channelID
}

func (channel *Channel) ChannelType() string {
	return channel.channelType
}

func (channel *Channel) RawRequest(name string, wantReply bool, payload []byte) (bool, error) {
	accepted, err := channel.channel.SendRequest(name, wantReply, payload)
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

type GlobalRequest struct {
	*ssh.Request
	conn *Conn
}

func (request *GlobalRequest) UnmarshalPayload() (Payload, error) {
	return UnmarshalGlobalRequestPayload(request.Request)
}

func (request *GlobalRequest) ConnMetadata() ssh.ConnMetadata {
	return request.conn.conn
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
	return request.channel.conn.conn
}

func (request *ChannelRequest) String() string {
	return request.Request.Type
}
