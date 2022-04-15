package sshutils_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

var (
	sessionID = []byte{0x42}

	directTcpipChannelPayloadBytes = []byte{
		0x00, 0x00, 0x00, 0x09, '1', '2', '7', '.', '0', '.', '0', '.', '1',
		0x00, 0x00, 0x16, 0x2e,
		0x00, 0x00, 0x00, 0x09, '1', '2', '7', '.', '0', '.', '0', '.', '1',
		0x00, 0x00, 0xf4, 0x27,
	}
	directTcpipChannelPayload = &sshutils.DirectTcpipChannelPayload{
		Address:           "127.0.0.1",
		Port:              5678,
		OriginatorAddress: "127.0.0.1",
		OriginatorPort:    62503,
	}

	tcpipForwardRequestPayloadBytes = []byte{
		0x00, 0x00, 0x00, 0xb, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g',
		0x00, 0x00, 0x01, 0xbb,
	}
	tcpipForwardRequestPayload = &sshutils.TcpipForwardRequestPayload{
		Address: "example.org",
		Port:    443,
	}
	cancelTcpipForwardRequestPayload = &sshutils.CancelTcpipForwardRequestPayload{
		Address: "example.org",
		Port:    443,
	}

	x11RequestPayloadBytes = []byte{
		0x01,
		0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o',
		0x00, 0x00, 0x00, 0x02, '4', '2',
		0x00, 0x00, 0x00, 0x00,
	}
	x11RequestPayload = &sshutils.X11RequestPayload{
		SingleConnection:       true,
		AuthenticationProtocol: "foo",
		AuthenticationCookie:   "42",
		ScreenNumber:           0,
	}

	ptyRequestPayloadBytes = []byte{
		0x00, 0x00, 0x00, 0x05, 'x', 't', 'e', 'r', 'm',
		0x00, 0x00, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x18,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	terminalModesBytes = []byte{
		ssh.ECHO,
		0x00, 0x00, 0x00, 0x01,
		ssh.TTY_OP_ISPEED,
		0x00, 0x00, 0x38, 0x40,
		ssh.TTY_OP_OSPEED,
		0x00, 0x00, 0x38, 0x40,
	}
	ptyRequestPayload = &sshutils.PtyRequestPayload{
		Term:     "xterm",
		Width:    80,
		Height:   24,
		WidthPx:  0,
		HeightPx: 0,
		TerminalModes: ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		},
	}

	envRequestPayloadBytes = []byte{
		0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o',
		0x00, 0x00, 0x00, 0x03, 'b', 'a', 'r',
	}
	envRequestPayload = &sshutils.EnvRequestPayload{
		Name:  "foo",
		Value: "bar",
	}

	execRequestPayloadBytes = []byte{0x00, 0x00, 0x00, 0x07, '/', 'b', 'i', 'n', '/', 's', 'h'}
	execRequestPayload      = &sshutils.ExecRequestPayload{
		Command: "/bin/sh",
	}

	subsystemRequestPayloadBytes = []byte{0x00, 0x00, 0x00, 0x04, 's', 'f', 't', 'p'}
	subsystemRequestPayload      = &sshutils.SubsystemRequestPayload{
		Subsystem: "sftp",
	}

	windowChangeRequestPayloadBytes = []byte{
		0x00, 0x00, 0x00, 0x78,
		0x00, 0x00, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	windowChangeRequestPayload = &sshutils.WindowChangeRequestPayload{
		Width:    120,
		Height:   80,
		WidthPx:  0,
		HeightPx: 0,
	}

	exitStatusRequestPayloadBytes = []byte{0x00, 0x00, 0x00, 0x01}
	exitStatusRequestPayload      = &sshutils.ExitStatusRequestPayload{
		ExitStatus: 1,
	}
)

type mockNewChannel struct {
	channelType string
	extraData   []byte
	canAccept   bool
}

func (newChannel *mockNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	if !newChannel.canAccept {
		return nil, nil, fmt.Errorf("mockNewChannel: cannot accept") //nolint:goerr113
	}
	return nil, nil, nil
}

func (newChannel *mockNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	panic("not implemented")
}

func (newChannel *mockNewChannel) ChannelType() string {
	return newChannel.channelType
}

func (newChannel *mockNewChannel) ExtraData() []byte {
	return newChannel.extraData
}

func (newChannel *mockNewChannel) String() string {
	return fmt.Sprintf("NewChannel: %v(%v)", newChannel.channelType, newChannel.extraData)
}

func TestUnmarshalSessionChannelPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.SessionChannelPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, &sshutils.SessionChannelPayload{}, "session", false},
		{[]byte{}, &sshutils.SessionChannelPayload{}, "session", false},
		{[]byte{42}, nil, "", true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.SessionChannelPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalSessionChannelPayload(t *testing.T) {
	payload := &sshutils.SessionChannelPayload{}
	output := payload.Marshal()
	expectedOutput := []byte{}
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Marshal() = %v, want %v", output, expectedOutput)
	}
}

func TestUnmarshalDirectTcpipChannelPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.DirectTcpipChannelPayload
		expectedString  string
		expectedError   bool
	}{
		{directTcpipChannelPayloadBytes, directTcpipChannelPayload, "direct-tcpip: 127.0.0.1:62503 -> 127.0.0.1:5678", false},
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{42}, nil, "", true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.DirectTcpipChannelPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal() = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalDirectTcpipChannelPayload(t *testing.T) {
	output := directTcpipChannelPayload.Marshal()
	if !bytes.Equal(output, directTcpipChannelPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, directTcpipChannelPayloadBytes)
	}
}

func TestUnmarshalNewChannelPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           ssh.NewChannel
		expectedPayload sshutils.Payload
		expectedError   bool
	}{
		{&mockNewChannel{"session", nil, true}, &sshutils.SessionChannelPayload{}, false},
		{&mockNewChannel{"session", []byte{42}, true}, nil, true},
		{&mockNewChannel{"direct-tcpip", directTcpipChannelPayloadBytes, true}, directTcpipChannelPayload, false},
		{&mockNewChannel{"direct-tcpip", nil, true}, nil, true},
		{&mockNewChannel{"test", nil, true}, nil, true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload, err := sshutils.UnmarshalNewChannelPayload(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("UnmarshalNewChannelPayload(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("UnmarshalNewChannelPayload(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("UnmarshalNewChannelPayload(...) = %v, want %v", payload, testCase.expectedPayload)
				}
			}
		})
	}
}

func TestUnmarshalHostkeysRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.HostkeysRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, &sshutils.HostkeysRequestPayload{sshutils.PublicKeys{}}, "hostkeys: []", false},
		{[]byte{}, &sshutils.HostkeysRequestPayload{sshutils.PublicKeys{}}, "hostkeys: []", false},
		{rsaHostkeyRequestPayloadBytes, &sshutils.HostkeysRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, fmt.Sprintf("hostkeys: [%v]", ssh.FingerprintSHA256(rsaHostKey.PublicKey())), false},
		{append(rsaHostkeyRequestPayloadBytes, ecdsaHostkeyRequestPayloadBytes...), &sshutils.HostkeysRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey(), ecdsaHostKey.PublicKey()}}, fmt.Sprintf("hostkeys: [%v, %v]", ssh.FingerprintSHA256(rsaHostKey.PublicKey()), ssh.FingerprintSHA256(ecdsaHostKey.PublicKey())), false},
		{[]byte{0x42}, nil, "", true},
		{[]byte{0x00, 0x00, 0x00, 0x42}, nil, "", true},
		{[]byte{0x00, 0x00, 0x00, 0x01, 0x42}, nil, "", true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var payload sshutils.HostkeysRequestPayload
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal() = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal() = %v, want nil", err)
				}
				if !reflect.DeepEqual(&payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal() = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalHostkeysRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input          *sshutils.HostkeysRequestPayload
		expectedOutput []byte
	}{
		{&sshutils.HostkeysRequestPayload{sshutils.PublicKeys{}}, []byte{}},
		{&sshutils.HostkeysRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, rsaHostkeyRequestPayloadBytes},
		{&sshutils.HostkeysRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey(), ecdsaHostKey.PublicKey()}}, append(rsaHostkeyRequestPayloadBytes, ecdsaHostkeyRequestPayloadBytes...)},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			output := testCase.input.Marshal()
			if !bytes.Equal(output, testCase.expectedOutput) {
				t.Errorf("Marshal() = %v, want %v", output, testCase.expectedOutput)
			}
		})
	}
}

func TestUnmarshalHostkeysProveRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.HostkeysProveRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{}}, "hostkeys_prove: []", false},
		{[]byte{}, &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{}}, "hostkeys_prove: []", false},
		{rsaHostkeyRequestPayloadBytes, &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, fmt.Sprintf("hostkeys_prove: [%v]", ssh.FingerprintSHA256(rsaHostKey.PublicKey())), false},
		{append(rsaHostkeyRequestPayloadBytes, ecdsaHostkeyRequestPayloadBytes...), &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey(), ecdsaHostKey.PublicKey()}}, fmt.Sprintf("hostkeys_prove: [%v, %v]", ssh.FingerprintSHA256(rsaHostKey.PublicKey()), ssh.FingerprintSHA256(ecdsaHostKey.PublicKey())), false},
		{[]byte{0x42}, nil, "", true},
		{[]byte{0x00, 0x00, 0x00, 0x42}, nil, "", true},
		{[]byte{0x00, 0x00, 0x00, 0x01, 0x42}, nil, "", true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var payload sshutils.HostkeysProveRequestPayload
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal() = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal() = %v, want nil", err)
				}
				if !reflect.DeepEqual(&payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal() = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalHostkeysProveRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input          *sshutils.HostkeysProveRequestPayload
		expectedOutput []byte
	}{
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{}}, []byte{}},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, rsaHostkeyRequestPayloadBytes},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey(), ecdsaHostKey.PublicKey()}}, append(rsaHostkeyRequestPayloadBytes, ecdsaHostkeyRequestPayloadBytes...)},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			output := testCase.input.Marshal()
			if !bytes.Equal(output, testCase.expectedOutput) {
				t.Errorf("Marshal() = %v, want %v", output, testCase.expectedOutput)
			}
		})
	}
}

func TestHostkeysProveRequestPayloadResponse(t *testing.T) {
	for i, testCase := range []struct {
		request       *sshutils.HostkeysProveRequestPayload
		hostKeys      []*sshutils.HostKey
		expectedError bool
	}{
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{}}, []*sshutils.HostKey{rsaHostKey, ecdsaHostKey}, false},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, []*sshutils.HostKey{rsaHostKey, ecdsaHostKey}, false},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey(), ecdsaHostKey.PublicKey()}}, []*sshutils.HostKey{rsaHostKey, ecdsaHostKey}, false},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, []*sshutils.HostKey{}, true},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{ed25519HostKey.PublicKey()}}, []*sshutils.HostKey{rsaHostKey, ecdsaHostKey}, true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			response, err := testCase.request.Response(testCase.hostKeys, sessionID)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("%v.Response(...) = %v, want non-nil", testCase.request, err)
				}
			} else {
				if err != nil {
					t.Fatalf("%v.Response(...) = %v, want nil", testCase.request, err)
				}
				if len(testCase.request.Hostkeys) == 0 {
					if len(response) != 0 {
						t.Errorf("%v.Response(...) = %v, want empty", testCase.request, response)
					}
				} else {
					if len(response) == 0 {
						t.Errorf("%v.Response(...) = %v, want non-empty", testCase.request, response)
					}
				}
			}
		})
	}
}

func TestHostkeysProveRequestPayloadVerifyResponse(t *testing.T) {
	for i, testCase := range []struct {
		request  *sshutils.HostkeysProveRequestPayload
		hostKeys []*sshutils.HostKey
	}{
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{}}, []*sshutils.HostKey{rsaHostKey, ecdsaHostKey}},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, []*sshutils.HostKey{rsaHostKey, ecdsaHostKey}},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey(), ecdsaHostKey.PublicKey()}}, []*sshutils.HostKey{rsaHostKey, ecdsaHostKey}},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			response, err := testCase.request.Response(testCase.hostKeys, sessionID)
			if err != nil {
				t.Fatalf("%v.Response(...) = %v, want nil", testCase.request, err)
			}
			err = testCase.request.VerifyResponse(response, sessionID)
			if err != nil {
				t.Errorf("%v.VerifyResponse(...) = %v, want nil", testCase.request, err)
			}
		})
	}
}

func TestHostkeysProveRequestPayloadVerifyResponseErr(t *testing.T) {
	for i, testCase := range []struct {
		request  *sshutils.HostkeysProveRequestPayload
		response []byte
	}{
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{}}, []byte{0x42}},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, []byte{}},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, []byte{0x00, 0x00, 0x00, 0x00}},
		{&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, ssh.Marshal(struct{ string }{string(ssh.Marshal(ssh.Signature{}))})},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			err := testCase.request.VerifyResponse(testCase.response, sessionID)
			if err == nil {
				t.Errorf("%v.VerifyResponse(...) = %v, want non-nil", testCase.request, err)
			}
		})
	}
}

func TestUnmarshalTcpipForwardRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.TcpipForwardRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{tcpipForwardRequestPayloadBytes, tcpipForwardRequestPayload, "tcpip-forward: example.org:443", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.TcpipForwardRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalTcpipForwardRequestPayload(t *testing.T) {
	output := tcpipForwardRequestPayload.Marshal()
	if !bytes.Equal(output, tcpipForwardRequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, tcpipForwardRequestPayloadBytes)
	}
}

func TestTcpipForwardRequestPayloadResponse(t *testing.T) {
	response := tcpipForwardRequestPayload.Response(42)
	expectedResponse := []byte{0x00, 0x00, 0x00, 0x2a}
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Response(...) = %v, want %v", response, expectedResponse)
	}
}

func TestUnmarshalCancelTcpipForwardRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.CancelTcpipForwardRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{tcpipForwardRequestPayloadBytes, cancelTcpipForwardRequestPayload, "cancel-tcpip-forward: example.org:443", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.CancelTcpipForwardRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalCancelTcpipForwardRequestPayload(t *testing.T) {
	output := cancelTcpipForwardRequestPayload.Marshal()
	if !bytes.Equal(output, tcpipForwardRequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, tcpipForwardRequestPayloadBytes)
	}
}

func TestUnmarshalNoMoreSessionsRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.NoMoreSessionsRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, &sshutils.NoMoreSessionsRequestPayload{}, "no-more-sessions", false},
		{[]byte{}, &sshutils.NoMoreSessionsRequestPayload{}, "no-more-sessions", false},
		{[]byte{0x42}, nil, "", true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.NoMoreSessionsRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalNoMoreSessionsRequestPayload(t *testing.T) {
	payload := &sshutils.NoMoreSessionsRequestPayload{}
	output := payload.Marshal()
	expectedOutput := []byte{}
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Marshal() = %v, want %v", output, expectedOutput)
	}
}

func TestUnmarshalGlobalRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           *ssh.Request
		expectedPayload sshutils.Payload
		expectedError   bool
	}{
		{&ssh.Request{Type: "tcpip-forward"}, nil, true},
		{&ssh.Request{Type: "tcpip-forward", Payload: tcpipForwardRequestPayloadBytes}, tcpipForwardRequestPayload, false},
		{&ssh.Request{Type: "cancel-tcpip-forward"}, nil, true},
		{&ssh.Request{Type: "cancel-tcpip-forward", Payload: tcpipForwardRequestPayloadBytes}, cancelTcpipForwardRequestPayload, false},
		{&ssh.Request{Type: "no-more-sessions@openssh.com", Payload: []byte{0x42}}, nil, true},
		{&ssh.Request{Type: "no-more-sessions@openssh.com"}, &sshutils.NoMoreSessionsRequestPayload{}, false},
		{&ssh.Request{Type: "hostkeys-00@openssh.com", Payload: []byte{0x42}}, nil, true},
		{&ssh.Request{Type: "hostkeys-00@openssh.com", Payload: rsaHostkeyRequestPayloadBytes}, &sshutils.HostkeysRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, false},
		{&ssh.Request{Type: "hostkeys-prove-00@openssh.com", Payload: []byte{0x42}}, nil, true},
		{&ssh.Request{Type: "hostkeys-prove-00@openssh.com", Payload: rsaHostkeyRequestPayloadBytes}, &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{rsaHostKey.PublicKey()}}, false},
		{&ssh.Request{Type: "foo"}, nil, true},
		{&ssh.Request{Type: "shell"}, nil, true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload, err := sshutils.UnmarshalGlobalRequestPayload(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("UnmarshalGlobalRequestPayload(..) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("UnmarshalGlobalRequestPayload(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("UnmarshalGlobalRequestPayload(...) = %v, want %v", payload, testCase.expectedPayload)
				}
			}
		})
	}
}

func TestUnmarshalX11RequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.X11RequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{x11RequestPayloadBytes, x11RequestPayload, "x11-req: 0", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.X11RequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalX11RequestPayload(t *testing.T) {
	output := x11RequestPayload.Marshal()
	if !bytes.Equal(output, x11RequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, x11RequestPayloadBytes)
	}
}

func TestUnmarshalPtyRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.PtyRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{append(ptyRequestPayloadBytes, []byte{0x00, 0x00, 0x00, 0x01, 0x42}...), nil, "", true},
		{append(ptyRequestPayloadBytes, ssh.Marshal(struct{ string }{string(append(terminalModesBytes, 0))})...), ptyRequestPayload, "pty-req: xterm, 80x24", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.PtyRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalPtyRequestPayload(t *testing.T) {
	output := ptyRequestPayload.Marshal()
	expectedOutput := make([]byte, 0)
	expectedOutput = append(expectedOutput, ptyRequestPayloadBytes...)
	expectedOutput = append(expectedOutput, ssh.Marshal(struct{ string }{string(append(terminalModesBytes, 0))})...)
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Marshal() = %v, want %v", output, expectedOutput)
	}
}

func TestUnmarshalEnvRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.EnvRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{envRequestPayloadBytes, envRequestPayload, "env: foo=bar", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.EnvRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalEnvRequestPayload(t *testing.T) {
	output := envRequestPayload.Marshal()
	if !bytes.Equal(output, envRequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, envRequestPayloadBytes)
	}
}

func TestUnmarshalShellRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.ShellRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, &sshutils.ShellRequestPayload{}, "shell", false},
		{[]byte{}, &sshutils.ShellRequestPayload{}, "shell", false},
		{[]byte{0x42}, nil, "", true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.ShellRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalShellRequestPayload(t *testing.T) {
	payload := &sshutils.ShellRequestPayload{}
	output := payload.Marshal()
	expectedOutput := []byte{}
	if !bytes.Equal(output, expectedOutput) {
		t.Errorf("Marshal() = %v, want %v", output, expectedOutput)
	}
}

func TestUnmarshalExecRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.ExecRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{execRequestPayloadBytes, execRequestPayload, "exec: /bin/sh", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.ExecRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalExecRequestPayload(t *testing.T) {
	output := execRequestPayload.Marshal()
	if !bytes.Equal(output, execRequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, execRequestPayloadBytes)
	}
}

func TestUnmarshalSubsystemRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.SubsystemRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{subsystemRequestPayloadBytes, subsystemRequestPayload, "subsystem: sftp", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.SubsystemRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalSubsystemRequestPayload(t *testing.T) {
	output := subsystemRequestPayload.Marshal()
	if !bytes.Equal(output, subsystemRequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, subsystemRequestPayloadBytes)
	}
}

func TestUnmarshalWindowChangeRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.WindowChangeRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{windowChangeRequestPayloadBytes, windowChangeRequestPayload, "window-change: 120x80", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.WindowChangeRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalWindowChangeRequestPayload(t *testing.T) {
	output := windowChangeRequestPayload.Marshal()
	if !bytes.Equal(output, windowChangeRequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, windowChangeRequestPayloadBytes)
	}
}

func TestUnmarshalExitStatusRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           []byte
		expectedPayload *sshutils.ExitStatusRequestPayload
		expectedString  string
		expectedError   bool
	}{
		{nil, nil, "", true},
		{[]byte{}, nil, "", true},
		{[]byte{0x42}, nil, "", true},
		{exitStatusRequestPayloadBytes, exitStatusRequestPayload, "exit-status: 1", false},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload := new(sshutils.ExitStatusRequestPayload)
			err := payload.Unmarshal(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Unmarshal(...) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unmarshal(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("Unmarshal(...) = %v, want %v", payload, testCase.expectedPayload)
				}
				if payload.String() != testCase.expectedString {
					t.Errorf("Unmarshal(...).String() = %v, want %v", payload.String(), testCase.expectedString)
				}
			}
		})
	}
}

func TestMarshalExitStatusRequestPayload(t *testing.T) {
	output := exitStatusRequestPayload.Marshal()
	if !bytes.Equal(output, exitStatusRequestPayloadBytes) {
		t.Errorf("Marshal() = %v, want %v", output, exitStatusRequestPayloadBytes)
	}
}

func TestUnmarshalChannelRequestPayload(t *testing.T) {
	for i, testCase := range []struct {
		input           *ssh.Request
		expectedPayload sshutils.Payload
		expectedError   bool
	}{
		{&ssh.Request{Type: "x11-req"}, nil, true},
		{&ssh.Request{Type: "x11-req", Payload: x11RequestPayloadBytes}, x11RequestPayload, false},
		{&ssh.Request{Type: "pty-req"}, nil, true},
		{&ssh.Request{Type: "pty-req", Payload: append(ptyRequestPayloadBytes, ssh.Marshal(struct{ string }{string(append(terminalModesBytes, 0))})...)}, ptyRequestPayload, false},
		{&ssh.Request{Type: "env"}, nil, true},
		{&ssh.Request{Type: "env", Payload: envRequestPayloadBytes}, envRequestPayload, false},
		{&ssh.Request{Type: "shell", Payload: []byte{0x42}}, nil, true},
		{&ssh.Request{Type: "shell"}, &sshutils.ShellRequestPayload{}, false},
		{&ssh.Request{Type: "exec"}, nil, true},
		{&ssh.Request{Type: "exec", Payload: execRequestPayloadBytes}, execRequestPayload, false},
		{&ssh.Request{Type: "subsystem"}, nil, true},
		{&ssh.Request{Type: "subsystem", Payload: subsystemRequestPayloadBytes}, subsystemRequestPayload, false},
		{&ssh.Request{Type: "window-change"}, nil, true},
		{&ssh.Request{Type: "window-change", Payload: windowChangeRequestPayloadBytes}, windowChangeRequestPayload, false},
		{&ssh.Request{Type: "exit-status"}, nil, true},
		{&ssh.Request{Type: "exit-status", Payload: exitStatusRequestPayloadBytes}, exitStatusRequestPayload, false},
		{&ssh.Request{Type: "foo"}, nil, true},
		{&ssh.Request{Type: "no-more-sessions@openssh.com"}, nil, true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			payload, err := sshutils.UnmarshalChannelRequestPayload(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("UnmarshalGlobalRequestPayload(..) = %v, want non-nil", err)
				}
			} else {
				if err != nil {
					t.Fatalf("UnmarshalGlobalRequestPayload(...) = %v, want nil", err)
				}
				if !reflect.DeepEqual(payload, testCase.expectedPayload) {
					t.Errorf("UnmarshalGlobalRequestPayload(...) = %v, want %v", payload, testCase.expectedPayload)
				}
			}
		})
	}
}
