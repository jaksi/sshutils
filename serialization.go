package sshutils

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	InvalidPayload         = errors.New("invalid payload")
	UnsupportedPayloadType = errors.New("unsupported type")
	HostKeyNotFound        = errors.New("host key not found")
	MissingSignature       = errors.New("missing signature")
)

type Payload interface {
	fmt.Stringer
	Unmarshal(data []byte) error
	Marshal() []byte
}

type SessionChannelPayload struct{}

func (payload *SessionChannelPayload) String() string {
	return "session"
}

func (payload *SessionChannelPayload) Unmarshal(data []byte) error {
	if len(data) != 0 {
		return InvalidPayload
	}
	return nil
}

func (payload *SessionChannelPayload) Marshal() []byte {
	return nil
}

type DirectTcpipChannelPayload struct {
	Address           string
	Port              uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

func (payload *DirectTcpipChannelPayload) String() string {
	return fmt.Sprintf("direct-tcpip: %v -> %v", net.JoinHostPort(payload.OriginatorAddress, fmt.Sprintf("%v", payload.OriginatorPort)), net.JoinHostPort(payload.Address, fmt.Sprintf("%v", payload.Port)))
}

func (payload *DirectTcpipChannelPayload) Unmarshal(data []byte) error {
	return ssh.Unmarshal(data, payload)
}

func (payload *DirectTcpipChannelPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

func UnmarshalNewChannelPayload(newChannel ssh.NewChannel) (Payload, error) {
	var payload Payload
	switch newChannel.ChannelType() {
	case "session":
		payload = &SessionChannelPayload{}
	case "direct-tcpip":
		payload = &DirectTcpipChannelPayload{}
	default:
		return nil, UnsupportedPayloadType
	}
	if err := payload.Unmarshal(newChannel.ExtraData()); err != nil {
		return nil, err
	}
	return payload, nil
}

func unmarshalBytes(data []byte) ([][]byte, error) {
	var result [][]byte
	for len(data) > 0 {
		var b struct {
			Bytes string
			Rest  []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(data, &b); err != nil {
			return nil, err
		}
		result = append(result, []byte(b.Bytes))
		data = b.Rest
	}
	return result, nil
}

func marshalBytes(payload [][]byte) []byte {
	var result []byte
	for _, b := range payload {
		result = append(result, ssh.Marshal(struct{ string }{string(b)})...)
	}
	return result
}

type PublicKeys []ssh.PublicKey

func (publicKeys PublicKeys) String() string {
	fingerprints := make([]string, len(publicKeys))
	for i, publicKey := range publicKeys {
		fingerprints[i] = ssh.FingerprintSHA256(publicKey)
	}
	return fmt.Sprintf("[%v]", strings.Join(fingerprints, ", "))
}

func unmarshalPublicKeys(data []byte) (PublicKeys, error) {
	publicKeyBytes, err := unmarshalBytes(data)
	if err != nil {
		return nil, err
	}
	publicKeys := make(PublicKeys, len(publicKeyBytes))
	for i, b := range publicKeyBytes {
		publicKeys[i], err = ssh.ParsePublicKey(b)
		if err != nil {
			return nil, err
		}
	}
	return publicKeys, nil
}

func marshalPublicKeys(publicKeys PublicKeys) []byte {
	publicKeyBytes := make([][]byte, len(publicKeys))
	for i, publicKey := range publicKeys {
		publicKeyBytes[i] = publicKey.Marshal()
	}
	return marshalBytes(publicKeyBytes)
}

type HostkeysRequestPayload struct {
	Hostkeys PublicKeys
}

func (payload *HostkeysRequestPayload) String() string {
	return fmt.Sprintf("hostkeys: %v", payload.Hostkeys)
}

func (payload *HostkeysRequestPayload) Unmarshal(data []byte) error {
	publicKeys, err := unmarshalPublicKeys(data)
	if err != nil {
		return err
	}
	payload.Hostkeys = publicKeys
	return nil
}

func (payload *HostkeysRequestPayload) Marshal() []byte {
	return marshalPublicKeys(payload.Hostkeys)
}

type HostkeysProveRequestPayload struct {
	Hostkeys PublicKeys
}

func (payload *HostkeysProveRequestPayload) String() string {
	return fmt.Sprintf("hostkeys_prove: %v", payload.Hostkeys)
}

func (payload *HostkeysProveRequestPayload) Unmarshal(data []byte) error {
	publicKeys, err := unmarshalPublicKeys(data)
	if err != nil {
		return err
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

func (payload *HostkeysProveRequestPayload) Response(hostKeys []*HostKey, sessionID []byte) ([]byte, error) {
	responseBytes := make([][]byte, len(payload.Hostkeys))
	for i, requestKey := range payload.Hostkeys {
		var signature *ssh.Signature
		err := HostKeyNotFound
		for _, hostKey := range hostKeys {
			if bytes.Equal(requestKey.Marshal(), hostKey.PublicKey().Marshal()) {
				signature, err = hostKey.Sign(rand.Reader, hostkeySignatureData(hostKey.PublicKey(), sessionID))
				break
			}
		}
		if err != nil {
			return nil, err
		}
		responseBytes[i] = ssh.Marshal(signature)
	}
	return marshalBytes(responseBytes), nil
}

func (payload *HostkeysProveRequestPayload) VerifyResponse(response []byte, sessionID []byte) error {
	signatureBytes, err := unmarshalBytes(response)
	if err != nil {
		return err
	}
	if len(signatureBytes) != len(payload.Hostkeys) {
		return MissingSignature
	}
	for i, b := range signatureBytes {
		signature := new(ssh.Signature)
		if err := ssh.Unmarshal(b, signature); err != nil {
			return err
		}
		if err := payload.Hostkeys[i].Verify(hostkeySignatureData(payload.Hostkeys[i], sessionID), signature); err != nil {
			return err
		}
	}
	return nil
}

type tcpipRequestPayload struct {
	Address string
	Port    uint32
}

type TcpipForwardRequestPayload tcpipRequestPayload

func (payload *TcpipForwardRequestPayload) String() string {
	return fmt.Sprintf("tcpip-forward: %v", net.JoinHostPort(payload.Address, fmt.Sprint(payload.Port)))
}

func (payload *TcpipForwardRequestPayload) Unmarshal(data []byte) error {
	return ssh.Unmarshal(data, payload)
}

func (payload *TcpipForwardRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

func (payload *TcpipForwardRequestPayload) Response(port uint32) []byte {
	return ssh.Marshal(struct{ uint32 }{port})
}

type CancelTcpipForwardRequestPayload tcpipRequestPayload

func (payload *CancelTcpipForwardRequestPayload) String() string {
	return fmt.Sprintf("cancel-tcpip-forward: %v", net.JoinHostPort(payload.Address, fmt.Sprint(payload.Port)))
}

func (payload *CancelTcpipForwardRequestPayload) Unmarshal(data []byte) error {
	return ssh.Unmarshal(data, payload)
}

func (payload *CancelTcpipForwardRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

type NoMoreSessionsRequestPayload struct{}

func (payload *NoMoreSessionsRequestPayload) String() string {
	return "no-more-sessions"
}

func (payload *NoMoreSessionsRequestPayload) Unmarshal(data []byte) error {
	if len(data) != 0 {
		return InvalidPayload
	}
	return nil
}

func (payload *NoMoreSessionsRequestPayload) Marshal() []byte {
	return nil
}

func UnmarshalGlobalRequestPayload(request *ssh.Request) (Payload, error) {
	var payload Payload
	switch request.Type {
	case "tcpip-forward":
		payload = &TcpipForwardRequestPayload{}
	case "cancel-tcpip-forward":
		payload = &CancelTcpipForwardRequestPayload{}
	case "no-more-sessions@openssh.com":
		payload = &NoMoreSessionsRequestPayload{}
	case "hostkeys-00@openssh.com":
		payload = &HostkeysRequestPayload{}
	case "hostkeys-prove-00@openssh.com":
		payload = &HostkeysProveRequestPayload{}
	default:
		return nil, UnsupportedPayloadType
	}
	if err := payload.Unmarshal(request.Payload); err != nil {
		return nil, err
	}
	return payload, nil
}

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
	return ssh.Unmarshal(data, payload)
}

func (payload *X11RequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

type rawPtyRequestPayload struct {
	Term          string
	Width         uint32
	Height        uint32
	WidthPx       uint32
	HeightPx      uint32
	TerminalModes string
}

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

func (payload *PtyRequestPayload) Unmarshal(data []byte) error {
	var raw rawPtyRequestPayload
	if err := ssh.Unmarshal(data, &raw); err != nil {
		return err
	}
	rawTerminalModes := []byte(raw.TerminalModes)
	terminalModes := ssh.TerminalModes{}
	for len(rawTerminalModes) > 0 {
		var opcode struct {
			Opcode byte
			Rest   []byte `ssh:"rest"`
		}
		_ = ssh.Unmarshal(rawTerminalModes, &opcode)
		if !(opcode.Opcode > 1 && opcode.Opcode < 160) {
			break
		}
		var argument struct {
			Argument uint32
			Rest     []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(opcode.Rest, &argument); err != nil {
			return err
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

type EnvRequestPayload struct {
	Name  string
	Value string
}

func (payload *EnvRequestPayload) String() string {
	return fmt.Sprintf("env: %v=%v", payload.Name, payload.Value)
}

func (payload *EnvRequestPayload) Unmarshal(data []byte) error {
	return ssh.Unmarshal(data, payload)
}

func (payload *EnvRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

type ShellRequestPayload struct{}

func (payload *ShellRequestPayload) String() string {
	return "shell"
}

func (payload *ShellRequestPayload) Unmarshal(data []byte) error {
	if len(data) != 0 {
		return InvalidPayload
	}
	return nil
}

func (payload *ShellRequestPayload) Marshal() []byte {
	return nil
}

type ExecRequestPayload struct {
	Command string
}

func (payload *ExecRequestPayload) String() string {
	return fmt.Sprintf("exec: %v", payload.Command)
}

func (payload *ExecRequestPayload) Unmarshal(data []byte) error {
	return ssh.Unmarshal(data, payload)
}

func (payload *ExecRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

type SubsystemRequestPayload struct {
	Subsystem string
}

func (payload *SubsystemRequestPayload) String() string {
	return fmt.Sprintf("subsystem: %v", payload.Subsystem)
}

func (payload *SubsystemRequestPayload) Unmarshal(data []byte) error {
	return ssh.Unmarshal(data, payload)
}

func (payload *SubsystemRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

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
	return ssh.Unmarshal(data, payload)
}

func (payload *WindowChangeRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

type ExitStatusRequestPayload struct {
	ExitStatus uint32
}

func (payload *ExitStatusRequestPayload) String() string {
	return fmt.Sprintf("exit-status: %v", payload.ExitStatus)
}

func (payload *ExitStatusRequestPayload) Unmarshal(data []byte) error {
	return ssh.Unmarshal(data, payload)
}

func (payload *ExitStatusRequestPayload) Marshal() []byte {
	return ssh.Marshal(payload)
}

func UnmarshalChannelRequestPayload(request *ssh.Request) (Payload, error) {
	var payload Payload
	switch request.Type {
	case "x11-req":
		payload = &X11RequestPayload{}
	case "pty-req":
		payload = &PtyRequestPayload{}
	case "env":
		payload = &EnvRequestPayload{}
	case "shell":
		payload = &ShellRequestPayload{}
	case "exec":
		payload = &ExecRequestPayload{}
	case "subsystem":
		payload = &SubsystemRequestPayload{}
	case "window-change":
		payload = &WindowChangeRequestPayload{}
	case "exit-status":
		payload = &ExitStatusRequestPayload{}
	default:
		return nil, InvalidPayload
	}
	if err := payload.Unmarshal(request.Payload); err != nil {
		return nil, err
	}
	return payload, nil
}
