package sshutils

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

var errInvalidPayload = errors.New("invalid payload")

type Payload interface {
	fmt.Stringer
	Unmarshal(data []byte) error
	Marshal() []byte
}

type RawPayload []byte

func (p *RawPayload) String() string {
	return hex.EncodeToString(*p)
}

func (p *RawPayload) Unmarshal(data []byte) error {
	*p = data
	return nil
}

func (p *RawPayload) Marshal() []byte {
	return *p
}

type UnknownPayload struct {
	RawPayload
	RequestType string
}

func (payload *UnknownPayload) String() string {
	return fmt.Sprintf("unknown type (%v), payload: %v", payload.RequestType, payload.RawPayload.String())
}

/*
Channel open payloads
*/

/*
	session
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.1
*/

type SessionChannelPayload struct{}

func (payload *SessionChannelPayload) String() string {
	return "session"
}

func (payload *SessionChannelPayload) Unmarshal(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("%w: non-empty payload", errInvalidPayload)
	}
	return nil
}

func (payload *SessionChannelPayload) Marshal() []byte {
	return nil
}

/*
	x11
	https://www.rfc-editor.org/rfc/rfc4254#section-6.3.2
*/

type X11ChannelPayload struct {
	OriginatorAddress string
	OriginatorPort    uint32
}

func (payload *X11ChannelPayload) String() string {
	return fmt.Sprintf("x11: %v",
		net.JoinHostPort(payload.OriginatorAddress, fmt.Sprintf("%v", payload.OriginatorPort)))
}

func (payload *X11ChannelPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *X11ChannelPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	forwarded-tcpip
	https://www.rfc-editor.org/rfc/rfc4254.html#section-7.2
*/

type ForwardedTcpipChannelPayload struct {
	Address           string
	Port              uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

func (payload *ForwardedTcpipChannelPayload) String() string {
	return fmt.Sprintf("forwarded-tcpip: %v -> %v",
		net.JoinHostPort(payload.OriginatorAddress, fmt.Sprintf("%v", payload.OriginatorPort)),
		net.JoinHostPort(payload.Address, fmt.Sprintf("%v", payload.Port)))
}

func (payload *ForwardedTcpipChannelPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *ForwardedTcpipChannelPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	direct-tcpip
	https://www.rfc-editor.org/rfc/rfc4254.html#section-7.2
*/

type DirectTcpipChannelPayload struct {
	Address           string
	Port              uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

func (payload *DirectTcpipChannelPayload) String() string {
	return fmt.Sprintf("direct-tcpip: %v -> %v",
		net.JoinHostPort(payload.OriginatorAddress, fmt.Sprintf("%v", payload.OriginatorPort)),
		net.JoinHostPort(payload.Address, fmt.Sprintf("%v", payload.Port)))
}

func (payload *DirectTcpipChannelPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *DirectTcpipChannelPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	tun@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.3
*/

type TunChannelMode uint32

const (
	TunChannelModePointToPoint TunChannelMode = 1
	TunChannelModeEthernet     TunChannelMode = 2
)

func (mode TunChannelMode) String() string {
	switch mode {
	case TunChannelModePointToPoint:
		return "point-to-point"
	case TunChannelModeEthernet:
		return "ethernet"
	}
	return fmt.Sprintf("unknown mode (%v)", uint32(mode))
}

type TunChannelPayload struct {
	TunnelMode TunChannelMode
	Interface  uint32
}

func (payload *TunChannelPayload) String() string {
	return fmt.Sprintf("tun: %v, interface: %v", payload.TunnelMode, payload.Interface)
}

func (payload *TunChannelPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *TunChannelPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	direct-streamlocal@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.4
*/

type DirectStreamlocalChannelPayload struct {
	Path      string
	Reserved1 string
	Reserved2 uint32
}

func (payload *DirectStreamlocalChannelPayload) String() string {
	return fmt.Sprintf("direct-streamlocal: %v", payload.Path)
}

func (payload *DirectStreamlocalChannelPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *DirectStreamlocalChannelPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	forwarded-streamlocal@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.4
*/

type ForwardedStreamlocalChannelPayload struct {
	Path     string
	Reserved string
}

func (payload *ForwardedStreamlocalChannelPayload) String() string {
	return fmt.Sprintf("forwarded-streamlocal: %v", payload.Path)
}

func (payload *ForwardedStreamlocalChannelPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *ForwardedStreamlocalChannelPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

func UnmarshalNewChannelPayload(newChannel ssh.NewChannel) (Payload, error) {
	var payload Payload
	switch newChannel.ChannelType() {
	case "session":
		payload = new(SessionChannelPayload)
	case "x11":
		payload = new(X11ChannelPayload)
	case "forwarded-tcpip":
		payload = new(ForwardedTcpipChannelPayload)
	case "direct-tcpip":
		payload = new(DirectTcpipChannelPayload)
	case "tun@openssh.com":
		payload = new(TunChannelPayload)
	case "direct-streamlocal@openssh.com":
		payload = new(DirectStreamlocalChannelPayload)
	case "forwarded-streamlocal@openssh.com":
		payload = new(ForwardedStreamlocalChannelPayload)
	default:
		payload = &UnknownPayload{nil, newChannel.ChannelType()}
	}
	if err := payload.Unmarshal(newChannel.ExtraData()); err != nil {
		return nil, fmt.Errorf("failed to unmarshal new channel payload: %w", err)
	}
	return payload, nil
}

/*
Global request payloads
*/

/*
	tcpip-forward
	https://www.rfc-editor.org/rfc/rfc4254.html#section-7.1
*/

type tcpipRequestPayload struct {
	Address string
	Port    uint32
}

type TcpipForwardRequestPayload tcpipRequestPayload

func (payload *TcpipForwardRequestPayload) String() string {
	return fmt.Sprintf("tcpip-forward: %v", net.JoinHostPort(payload.Address, fmt.Sprint(payload.Port)))
}

func (payload *TcpipForwardRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *TcpipForwardRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

func (payload *TcpipForwardRequestPayload) Response(port uint32) []byte {
	return ssh.Marshal(struct{ uint32 }{port})
}

/*
	cancel-tcpip-forward
	https://www.rfc-editor.org/rfc/rfc4254.html#section-7.1
*/

type CancelTcpipForwardRequestPayload tcpipRequestPayload

func (payload *CancelTcpipForwardRequestPayload) String() string {
	return fmt.Sprintf("cancel-tcpip-forward: %v", net.JoinHostPort(payload.Address, fmt.Sprint(payload.Port)))
}

func (payload *CancelTcpipForwardRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *CancelTcpipForwardRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	no-more-sessions@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.2
*/

type NoMoreSessionsRequestPayload struct{}

func (payload *NoMoreSessionsRequestPayload) String() string {
	return "no-more-sessions"
}

func (payload *NoMoreSessionsRequestPayload) Unmarshal(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("%w: non-empty payload", errInvalidPayload)
	}
	return nil
}

func (payload *NoMoreSessionsRequestPayload) Marshal() []byte {
	return nil
}

/*
	streamlocal-forward@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.4
*/

type streamlocalForwardRequestPayload struct {
	Path string
}

type StreamlocalForwardRequestPayload streamlocalForwardRequestPayload

func (payload *StreamlocalForwardRequestPayload) String() string {
	return fmt.Sprintf("streamlocal-forward: %v", payload.Path)
}

func (payload *StreamlocalForwardRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *StreamlocalForwardRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	cancel-streamlocal-forward@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.4
*/

type CancelStreamlocalForwardRequestPayload streamlocalForwardRequestPayload

func (payload *CancelStreamlocalForwardRequestPayload) String() string {
	return fmt.Sprintf("cancel-streamlocal-forward: %v", payload.Path)
}

func (payload *CancelStreamlocalForwardRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *CancelStreamlocalForwardRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	hostkeys-00@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.5
*/

type PublicKeys []ssh.PublicKey

func (publicKeys PublicKeys) String() string {
	fingerprints := make([]string, len(publicKeys))
	for i, publicKey := range publicKeys {
		fingerprints[i] = ssh.FingerprintSHA256(publicKey)
	}
	return fmt.Sprintf("[%v]", strings.Join(fingerprints, ", "))
}

func unmarshalBytes(data []byte) ([][]byte, error) {
	var result [][]byte
	for len(data) > 0 {
		var b struct {
			Bytes string
			Rest  []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(data, &b); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bytes: %w", err)
		}
		result = append(result, []byte(b.Bytes))
		data = b.Rest
	}
	return result, nil
}

func unmarshalPublicKeys(data []byte) (PublicKeys, error) {
	publicKeyBytes, err := unmarshalBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public keys: %w", err)
	}
	publicKeys := make(PublicKeys, len(publicKeyBytes))
	for i, b := range publicKeyBytes {
		publicKeys[i], err = ssh.ParsePublicKey(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
	}
	return publicKeys, nil
}

func marshalBytes(payload [][]byte) []byte {
	var result []byte
	for _, b := range payload {
		result = append(result, ssh.Marshal(struct{ string }{string(b)})...)
	}
	return result
}

func marshalPublicKeys(publicKeys PublicKeys) []byte {
	publicKeyBytes := make([][]byte, len(publicKeys))
	for i, publicKey := range publicKeys {
		publicKeyBytes[i] = publicKey.Marshal()
	}
	return marshalBytes(publicKeyBytes)
}

type hostkeysRequestPayload struct {
	Hostkeys PublicKeys
}

type HostkeysRequestPayload hostkeysRequestPayload

func (payload *HostkeysRequestPayload) String() string {
	return fmt.Sprintf("hostkeys: %v", payload.Hostkeys)
}

func (payload *HostkeysRequestPayload) Unmarshal(data []byte) error {
	publicKeys, err := unmarshalPublicKeys(data)
	if err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	payload.Hostkeys = publicKeys
	return nil
}

func (payload *HostkeysRequestPayload) Marshal() []byte {
	return marshalPublicKeys(payload.Hostkeys)
}

/*
	hostkeys-prove-00@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.5
*/

type HostkeysProveRequestPayload hostkeysRequestPayload

func (payload *HostkeysProveRequestPayload) String() string {
	return fmt.Sprintf("hostkeys-prove: %v", payload.Hostkeys)
}

func (payload *HostkeysProveRequestPayload) Unmarshal(data []byte) error {
	publicKeys, err := unmarshalPublicKeys(data)
	if err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	payload.Hostkeys = publicKeys
	return nil
}

func (payload *HostkeysProveRequestPayload) Marshal() []byte {
	return marshalPublicKeys(payload.Hostkeys)
}

func hostkeySignatureData(hostkey ssh.PublicKey, sessionID []byte) []byte {
	return ssh.Marshal(struct {
		requestType, sessionID, hostkey string
	}{
		"hostkeys-prove-00@openssh.com",
		string(sessionID),
		string(hostkey.Marshal()),
	})
}

func (payload *HostkeysProveRequestPayload) Response(
	rand io.Reader, hostKeys []*HostKey, sessionID []byte,
) ([]byte, error) {
	responseBytes := make([][]byte, len(payload.Hostkeys))
	for i, requestKey := range payload.Hostkeys {
		var signature *ssh.Signature
		var err error
		for _, hostKey := range hostKeys {
			if bytes.Equal(requestKey.Marshal(), hostKey.PublicKey().Marshal()) {
				signature, err = hostKey.Sign(rand, hostkeySignatureData(hostKey.PublicKey(), sessionID))
				if err != nil {
					return nil, fmt.Errorf("failed to sign data: %w", err)
				}
				break
			}
		}
		if signature == nil {
			return nil, fmt.Errorf("%w: no matching host key", errInvalidPayload)
		}
		responseBytes[i] = ssh.Marshal(signature)
	}
	return marshalBytes(responseBytes), nil
}

func (payload *HostkeysProveRequestPayload) VerifyResponse(response []byte, sessionID []byte) error {
	signatureBytes, err := unmarshalBytes(response)
	if err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	if len(signatureBytes) != len(payload.Hostkeys) {
		return fmt.Errorf("%w: invalid number of signatures", errInvalidPayload)
	}
	for i, b := range signatureBytes {
		signature := new(ssh.Signature)
		if err := ssh.Unmarshal(b, signature); err != nil {
			return fmt.Errorf("%w: %v", errInvalidPayload, err)
		}
		if err := payload.Hostkeys[i].Verify(hostkeySignatureData(payload.Hostkeys[i], sessionID), signature); err != nil {
			return fmt.Errorf("%w: %v", errInvalidPayload, err)
		}
	}
	return nil
}

func UnmarshalGlobalRequestPayload(request *ssh.Request) (Payload, error) {
	var payload Payload
	switch request.Type {
	case "tcpip-forward":
		payload = new(TcpipForwardRequestPayload)
	case "cancel-tcpip-forward":
		payload = new(CancelTcpipForwardRequestPayload)
	case "no-more-sessions@openssh.com":
		payload = new(NoMoreSessionsRequestPayload)
	case "streamlocal-forward@openssh.com":
		payload = new(StreamlocalForwardRequestPayload)
	case "cancel-streamlocal-forward@openssh.com":
		payload = new(CancelStreamlocalForwardRequestPayload)
	case "hostkeys-00@openssh.com":
		payload = new(HostkeysRequestPayload)
	case "hostkeys-prove-00@openssh.com":
		payload = new(HostkeysProveRequestPayload)
	default:
		payload = &UnknownPayload{nil, request.Type}
	}
	if err := payload.Unmarshal(request.Payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal global request payload: %w", err)
	}
	return payload, nil
}

/*
Global request payloads
*/

/*
	pty-req
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.2
*/

type PtyRequestPayload struct {
	Term          string
	Width         uint32
	Height        uint32
	WidthPx       uint32
	HeightPx      uint32
	TerminalModes ssh.TerminalModes
}

func (payload *PtyRequestPayload) String() string {
	return fmt.Sprintf("pty-req: %v, %vx%v", payload.Term, payload.Width, payload.Height)
}

type rawPtyRequestPayload struct {
	Term          string
	Width         uint32
	Height        uint32
	WidthPx       uint32
	HeightPx      uint32
	TerminalModes string
}

func (payload *PtyRequestPayload) Unmarshal(data []byte) error {
	var raw rawPtyRequestPayload
	if err := ssh.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	rawTerminalModes := []byte(raw.TerminalModes)
	terminalModes := ssh.TerminalModes{}
	for len(rawTerminalModes) > 0 {
		var opcode struct {
			Opcode byte
			Rest   []byte `ssh:"rest"`
		}
		_ = ssh.Unmarshal(rawTerminalModes, &opcode)
		if !(opcode.Opcode > 0 && opcode.Opcode < 160) {
			break
		}
		var argument struct {
			Argument uint32
			Rest     []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(opcode.Rest, &argument); err != nil {
			return fmt.Errorf("%w: %v", errInvalidPayload, err)
		}
		terminalModes[opcode.Opcode] = argument.Argument
		rawTerminalModes = argument.Rest
	}
	payload.Term = raw.Term
	payload.Width = raw.Width
	payload.Height = raw.Height
	payload.WidthPx = raw.WidthPx
	payload.HeightPx = raw.HeightPx
	payload.TerminalModes = terminalModes
	return nil
}

func (payload *PtyRequestPayload) Marshal() []byte {
	var raw rawPtyRequestPayload
	raw.Term = payload.Term
	raw.Width = payload.Width
	raw.Height = payload.Height
	raw.WidthPx = payload.WidthPx
	raw.HeightPx = payload.HeightPx
	terminalModes := []byte{}
	opcodes := make([]int, 0, len(payload.TerminalModes))
	for opcode := range payload.TerminalModes {
		opcodes = append(opcodes, int(opcode))
	}
	sort.Ints(opcodes)
	for _, opcode := range opcodes {
		terminalModes = append(terminalModes, ssh.Marshal(struct {
			byte
			uint32
		}{byte(opcode), payload.TerminalModes[uint8(opcode)]})...)
	}
	terminalModes = append(terminalModes, ssh.Marshal(struct{ byte }{0})...)
	raw.TerminalModes = string(terminalModes)
	return ssh.Marshal(&raw)
}

/*
	x11-req
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.3.1
*/

type X11RequestPayload struct {
	SingleConnection       bool
	AuthenticationProtocol string
	AuthenticationCookie   string
	ScreenNumber           uint32
}

func (payload *X11RequestPayload) String() string {
	return fmt.Sprintf("x11-req: %v", payload.ScreenNumber)
}

func (payload *X11RequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *X11RequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	env
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.4
*/

type EnvRequestPayload struct {
	Name  string
	Value string
}

func (payload *EnvRequestPayload) String() string {
	return fmt.Sprintf("env: %v=%v", payload.Name, payload.Value)
}

func (payload *EnvRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *EnvRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	shell
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.5
*/

type ShellRequestPayload struct{}

func (payload *ShellRequestPayload) String() string {
	return "shell"
}

func (payload *ShellRequestPayload) Unmarshal(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("%w: non-empty payload", errInvalidPayload)
	}
	return nil
}

func (payload *ShellRequestPayload) Marshal() []byte {
	return nil
}

/*
	exec
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.5
*/

type ExecRequestPayload struct {
	Command string
}

func (payload *ExecRequestPayload) String() string {
	return fmt.Sprintf("exec: %v", payload.Command)
}

func (payload *ExecRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *ExecRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	subsystem
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.5
*/

type SubsystemRequestPayload struct {
	Subsystem string
}

func (payload *SubsystemRequestPayload) String() string {
	return fmt.Sprintf("subsystem: %v", payload.Subsystem)
}

func (payload *SubsystemRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *SubsystemRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	window-change
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.7
*/

type WindowChangeRequestPayload struct {
	Width    uint32
	Height   uint32
	WidthPx  uint32
	HeightPx uint32
}

func (payload *WindowChangeRequestPayload) String() string {
	return fmt.Sprintf("window-change: %vx%v", payload.Width, payload.Height)
}

func (payload *WindowChangeRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *WindowChangeRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	xon-xoff
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.8
*/

type XonXoffRequestPayload struct {
	ClientCanDo bool
}

func (payload *XonXoffRequestPayload) String() string {
	return fmt.Sprintf("xon-xoff: %v", payload.ClientCanDo)
}

func (payload *XonXoffRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *XonXoffRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	signal
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.9
*/

type SignalRequestPayload struct {
	Name string
}

func (payload *SignalRequestPayload) String() string {
	return fmt.Sprintf("signal: %v", payload.Name)
}

func (payload *SignalRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *SignalRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	exit-status
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.10
*/

type ExitStatusRequestPayload struct {
	ExitStatus uint32
}

func (payload *ExitStatusRequestPayload) String() string {
	return fmt.Sprintf("exit-status: %v", payload.ExitStatus)
}

func (payload *ExitStatusRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *ExitStatusRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	exit-signal
	https://www.rfc-editor.org/rfc/rfc4254.html#section-6.10
*/

type ExitSignalRequestPayload struct {
	Name       string
	CoreDumped bool
	Message    string
	Language   string
}

func (payload *ExitSignalRequestPayload) String() string {
	return fmt.Sprintf("exit-signal: %v", payload.Name)
}

func (payload *ExitSignalRequestPayload) Unmarshal(data []byte) error {
	if err := ssh.Unmarshal(data, payload); err != nil {
		return fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	return nil
}

func (payload *ExitSignalRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

/*
	eow@openssh.com
	https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?rev=HEAD section 2.1
*/

type EowRequestPayload struct{}

func (payload *EowRequestPayload) String() string {
	return "eow"
}

func (payload *EowRequestPayload) Unmarshal(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("%w: non-empty payload", errInvalidPayload)
	}
	return nil
}

func (payload *EowRequestPayload) Marshal() []byte {
	return nil
}

//nolint:cyclop
func UnmarshalChannelRequestPayload(request *ssh.Request) (Payload, error) {
	var payload Payload
	switch request.Type {
	case "pty-req":
		payload = new(PtyRequestPayload)
	case "x11-req":
		payload = new(X11RequestPayload)
	case "env":
		payload = new(EnvRequestPayload)
	case "shell":
		payload = new(ShellRequestPayload)
	case "exec":
		payload = new(ExecRequestPayload)
	case "subsystem":
		payload = new(SubsystemRequestPayload)
	case "window-change":
		payload = new(WindowChangeRequestPayload)
	case "xon-xoff":
		payload = new(XonXoffRequestPayload)
	case "signal":
		payload = new(SignalRequestPayload)
	case "exit-status":
		payload = new(ExitStatusRequestPayload)
	case "exit-signal":
		payload = new(ExitSignalRequestPayload)
	case "eow@openssh.com":
		payload = new(EowRequestPayload)
	default:
		payload = &UnknownPayload{nil, request.Type}
	}
	if err := payload.Unmarshal(request.Payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal channel request payload: %w", err)
	}
	return payload, nil
}
