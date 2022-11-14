package sshutils_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

type fakeNewChannel struct {
	channelType string
	extraData   []byte
}

func (newChannel *fakeNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	panic("not implemented")
}

func (newChannel *fakeNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	panic("not implemented")
}

func (newChannel *fakeNewChannel) ChannelType() string {
	return newChannel.channelType
}

func (newChannel *fakeNewChannel) ExtraData() []byte {
	return newChannel.extraData
}

func testPayload(
	t *testing.T,
	rawPayload []byte,
	payload sshutils.Payload, err error,
	expectedPayload sshutils.Payload, expectedString string, expectedError string,
) {
	t.Helper()
	if err != nil || expectedError != "" {
		if (err != nil && (expectedError == "" || !strings.HasPrefix(err.Error(), expectedError))) ||
			(err == nil && expectedError != "") {
			t.Errorf("Unmarshal() error = %v, want %q", err, expectedError)
		}
		return
	}
	if !reflect.DeepEqual(payload, expectedPayload) {
		t.Errorf("Unmarshal() = %#v, want %#v", payload, expectedPayload)
	}
	if str := payload.String(); str != expectedString {
		t.Errorf("String() = %v, want %v", str, expectedString)
	}
	if data := payload.Marshal(); !bytes.Equal(data, rawPayload) {
		t.Errorf("Marshal() = %v, want %v", data, rawPayload)
	}
}

func TestNewChannelPayload(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		newChannel *fakeNewChannel
		payload    sshutils.Payload
		str        string
		err        string
	}{
		{
			"session",
			&fakeNewChannel{
				"session",
				[]byte{},
			},
			&sshutils.SessionChannelPayload{},
			"session",
			"",
		},
		{
			"session_invalid_payload",
			&fakeNewChannel{
				"session",
				[]byte{42},
			},
			nil,
			"",
			"failed to unmarshal new channel payload: invalid payload: non-empty payload",
		},
		{
			"x11",
			&fakeNewChannel{
				"x11",
				ssh.Marshal(struct {
					a string
					b uint32
				}{"foo", 42}),
			},
			&sshutils.X11ChannelPayload{"foo", 42},
			"x11: foo:42",
			"",
		},
		{
			"x11_invalid_payload",
			&fakeNewChannel{
				"x11",
				[]byte{},
			},
			nil,
			"",
			"failed to unmarshal new channel payload: invalid payload: ssh: parse error",
		},
		{
			"forwarded_tcpip",
			&fakeNewChannel{
				"forwarded-tcpip",
				ssh.Marshal(struct {
					a string
					b uint32
					c string
					d uint32
				}{"foo", 42, "bar", 43}),
			},
			&sshutils.ForwardedTcpipChannelPayload{"foo", 42, "bar", 43},
			"forwarded-tcpip: bar:43 -> foo:42",
			"",
		},
		{
			"forwarded_tcpip_invalid_payload",
			&fakeNewChannel{
				"forwarded-tcpip",
				[]byte{},
			},
			nil,
			"",
			"failed to unmarshal new channel payload: invalid payload: ssh: parse error",
		},
		{
			"direct_tcpip",
			&fakeNewChannel{
				"direct-tcpip",
				ssh.Marshal(struct {
					a string
					b uint32
					c string
					d uint32
				}{"foo", 42, "bar", 43}),
			},
			&sshutils.DirectTcpipChannelPayload{"foo", 42, "bar", 43},
			"direct-tcpip: bar:43 -> foo:42",
			"",
		},
		{
			"direct_tcpip_invalid_payload",
			&fakeNewChannel{
				"direct-tcpip",
				[]byte{},
			},
			nil,
			"",
			"failed to unmarshal new channel payload: invalid payload: ssh: parse error",
		},
		{
			"tun_ppp",
			&fakeNewChannel{
				"tun@openssh.com",
				ssh.Marshal(struct {
					a uint32
					b uint32
				}{1, 42}),
			},
			&sshutils.TunChannelPayload{1, 42},
			"tun: point-to-point, interface: 42",
			"",
		},
		{
			"tun_ethernet",
			&fakeNewChannel{
				"tun@openssh.com",
				ssh.Marshal(struct {
					a uint32
					b uint32
				}{2, 42}),
			},
			&sshutils.TunChannelPayload{2, 42},
			"tun: ethernet, interface: 42",
			"",
		},
		{
			"tun_unknown",
			&fakeNewChannel{
				"tun@openssh.com",
				ssh.Marshal(struct {
					a uint32
					b uint32
				}{3, 42}),
			},
			&sshutils.TunChannelPayload{3, 42},
			"tun: unknown mode (3), interface: 42",
			"",
		},
		{
			"tun_invalid_payload",
			&fakeNewChannel{
				"tun@openssh.com",
				[]byte{},
			},
			nil,
			"",
			"failed to unmarshal new channel payload: invalid payload: ssh: parse error",
		},
		{
			"direct_streamlocal",
			&fakeNewChannel{
				"direct-streamlocal@openssh.com",
				ssh.Marshal(struct {
					a string
					b string
					c uint32
				}{"foo", "bar", 42}),
			},
			&sshutils.DirectStreamlocalChannelPayload{"foo", "bar", 42},
			"direct-streamlocal: foo",
			"",
		},
		{
			"direct_streamlocal_invalid_payload",
			&fakeNewChannel{
				"direct-streamlocal@openssh.com",
				[]byte{},
			},
			nil,
			"",
			"failed to unmarshal new channel payload: invalid payload: ssh: parse error",
		},
		{
			"forwarded_streamlocal",
			&fakeNewChannel{
				"forwarded-streamlocal@openssh.com",
				ssh.Marshal(struct {
					a string
					b string
				}{"foo", "bar"}),
			},
			&sshutils.ForwardedStreamlocalChannelPayload{"foo", "bar"},
			"forwarded-streamlocal: foo",
			"",
		},
		{
			"forwarded_streamlocal_invalid_payload",
			&fakeNewChannel{
				"forwarded-streamlocal@openssh.com",
				[]byte{},
			},
			nil,
			"",
			"failed to unmarshal new channel payload: invalid payload: ssh: parse error",
		},
		{
			"unknown",
			&fakeNewChannel{
				"lorem_ipsum",
				[]byte{42, 43},
			},
			&sshutils.UnknownPayload{sshutils.RawPayload{42, 43}, "lorem_ipsum"},
			"unknown type (lorem_ipsum), payload: 2a2b",
			"",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload, err := sshutils.UnmarshalNewChannelPayload(tt.newChannel)
			testPayload(t, tt.newChannel.extraData, payload, err, tt.payload, tt.str, tt.err)
		})
	}
}

func TestGlobalRequestPayload(t *testing.T) {
	t.Parallel()
	key1, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	key2, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.ECDSA)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	for _, tt := range []struct {
		name          string
		globalRequest *ssh.Request
		payload       sshutils.Payload
		str           string
		err           string
	}{
		{
			"tcpip_forward",
			&ssh.Request{
				Type:      "tcpip-forward",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b uint32
				}{"foo", 42}),
			},
			&sshutils.TcpipForwardRequestPayload{"foo", 42},
			"tcpip-forward: foo:42",
			"",
		},
		{
			"tcpip_forward_invalid_payload",
			&ssh.Request{
				Type:      "tcpip-forward",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: ssh: parse error",
		},
		{
			"cancel_tcpip_forward",
			&ssh.Request{
				Type:      "cancel-tcpip-forward",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b uint32
				}{"foo", 42}),
			},
			&sshutils.CancelTcpipForwardRequestPayload{"foo", 42},
			"cancel-tcpip-forward: foo:42",
			"",
		},
		{
			"cancel_tcpip_forward_invalid_payload",
			&ssh.Request{
				Type:      "cancel-tcpip-forward",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: ssh: parse error",
		},
		{
			"no-more-sessions",
			&ssh.Request{
				Type:      "no-more-sessions@openssh.com",
				WantReply: true,
				Payload:   []byte{},
			},
			&sshutils.NoMoreSessionsRequestPayload{},
			"no-more-sessions",
			"",
		},
		{
			"no-more-sessions_invalid_payload",
			&ssh.Request{
				Type:      "no-more-sessions@openssh.com",
				WantReply: true,
				Payload:   []byte{42},
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: non-empty payload",
		},
		{
			"streamlocal_forward",
			&ssh.Request{
				Type:      "streamlocal-forward@openssh.com",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
				}{"foo"}),
			},
			&sshutils.StreamlocalForwardRequestPayload{"foo"},
			"streamlocal-forward: foo",
			"",
		},
		{
			"streamlocal_forward_invalid_payload",
			&ssh.Request{
				Type:      "streamlocal-forward@openssh.com",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: ssh: parse error",
		},
		{
			"cancel_streamlocal_forward",
			&ssh.Request{
				Type:      "cancel-streamlocal-forward@openssh.com",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
				}{"foo"}),
			},
			&sshutils.CancelStreamlocalForwardRequestPayload{"foo"},
			"cancel-streamlocal-forward: foo",
			"",
		},
		{
			"cancel_streamlocal_forward_invalid_payload",
			&ssh.Request{
				Type:      "cancel-streamlocal-forward@openssh.com",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: ssh: parse error",
		},
		{
			"hostkeys-00",
			&ssh.Request{
				Type:      "hostkeys-00@openssh.com",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b string
				}{string(key1.PublicKey().Marshal()), string(key2.PublicKey().Marshal())}),
			},
			&sshutils.HostkeysRequestPayload{sshutils.PublicKeys{key1.PublicKey(), key2.PublicKey()}},
			fmt.Sprintf("hostkeys: [%v, %v]",
				ssh.FingerprintSHA256(key1.PublicKey()), ssh.FingerprintSHA256(key2.PublicKey())),
			"",
		},
		{
			"hostkeys-00_invalid_payload",
			&ssh.Request{
				Type:      "hostkeys-00@openssh.com",
				WantReply: true,
				Payload:   []byte{42},
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: failed to unmarshal public keys: " +
				"failed to unmarshal bytes: ssh: unmarshal error",
		},
		{
			"hostkeys-00_invalid_public_key",
			&ssh.Request{
				Type:      "hostkeys-00@openssh.com",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
				}{"foo"}),
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: failed to parse public key: ssh: short read",
		},
		{
			"hostkeys-prove-00",
			&ssh.Request{
				Type:      "hostkeys-prove-00@openssh.com",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b string
				}{string(key1.PublicKey().Marshal()), string(key2.PublicKey().Marshal())}),
			},
			&sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key1.PublicKey(), key2.PublicKey()}},
			fmt.Sprintf("hostkeys-prove: [%v, %v]",
				ssh.FingerprintSHA256(key1.PublicKey()), ssh.FingerprintSHA256(key2.PublicKey())),
			"",
		},
		{
			"hostkeys-prove-00_invalid_payload",
			&ssh.Request{
				Type:      "hostkeys-prove-00@openssh.com",
				WantReply: true,
				Payload:   []byte{42},
			},
			nil,
			"",
			"failed to unmarshal global request payload: invalid payload: failed to unmarshal public keys: " +
				"failed to unmarshal bytes: ssh: unmarshal error",
		},
		{
			"unknown",
			&ssh.Request{
				Type:      "lorem_ipsum",
				WantReply: true,
				Payload:   []byte{42, 43},
			},
			&sshutils.UnknownPayload{sshutils.RawPayload{42, 43}, "lorem_ipsum"},
			"unknown type (lorem_ipsum), payload: 2a2b",
			"",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload, err := sshutils.UnmarshalGlobalRequestPayload(tt.globalRequest)
			testPayload(t, tt.globalRequest.Payload, payload, err, tt.payload, tt.str, tt.err)
		})
	}
}

func TestTcpipForwardRequestPayload(t *testing.T) {
	t.Parallel()
	payload := &sshutils.TcpipForwardRequestPayload{"foo", 42}
	response := payload.Response(43)
	expectedResponse := ssh.Marshal(struct{ uint32 }{43})
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Response() = %v, want %v", response, expectedResponse)
	}
}

type fakeRandReader struct {
	fail bool
}

func (r *fakeRandReader) Read(p []byte) (int, error) {
	if r.fail {
		return 0, errors.New("fake error")
	}
	for i := range p {
		p[i] = 42
	}
	return len(p), nil
}

func TestHostkeysProveRequestPayload(t *testing.T) {
	t.Parallel()
	key1, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	signature1, err := key1.Sign(&fakeRandReader{false}, ssh.Marshal(struct {
		a string
		b string
		c string
	}{"hostkeys-prove-00@openssh.com", "foo", string(key1.PublicKey().Marshal())}))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	key2, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.ECDSA)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	signature2, err := key2.Sign(&fakeRandReader{false}, ssh.Marshal(struct {
		a string
		b string
		c string
	}{"hostkeys-prove-00@openssh.com", "foo", string(key2.PublicKey().Marshal())}))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	payload := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key1.PublicKey(), key2.PublicKey()}}
	response, err := payload.Response(&fakeRandReader{false}, []*sshutils.HostKey{key1, key2}, []byte("foo"))
	if err != nil {
		t.Fatalf("Response() error = %v", err)
	}
	expectedResponse := ssh.Marshal(struct {
		a string
		b string
	}{
		string(ssh.Marshal(signature1)),
		string(ssh.Marshal(signature2)),
	})
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Response() = %v, want %v", response, expectedResponse)
	}
	if err := payload.VerifyResponse(response, []byte("foo")); err != nil {
		t.Errorf("VerifyResponse() error = %v", err)
	}
}

func TestHostkeysProveRequestPayloadResponse_NotFound(t *testing.T) {
	t.Parallel()
	key, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	payload := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key.PublicKey()}}
	expectedError := "invalid payload: no matching host key"
	_, err = payload.Response(&fakeRandReader{false}, []*sshutils.HostKey{}, []byte("foo"))
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Response() error = %v, want %v", err, expectedError)
	}
}

func TestHostkeysProveRequestPayloadResponse_SignError(t *testing.T) {
	t.Parallel()
	key, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.ECDSA)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	payload := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key.PublicKey()}}
	expectedError := "failed to sign data: fake error"
	_, err = payload.Response(&fakeRandReader{true}, []*sshutils.HostKey{key}, []byte("foo"))
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("Response() error = %v, want %v", err, expectedError)
	}
}

func TestHostkeysProveRequestPayloadVerifyResponse_InvalidPayload(t *testing.T) {
	t.Parallel()
	payload := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{}}
	expectedError := "invalid payload: failed to unmarshal bytes: ssh: unmarshal error"
	err := payload.VerifyResponse([]byte{42}, []byte("foo"))
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("VerifyResponse() error = %v, want %v", err, expectedError)
	}
}

func TestHostkeysProveRequestPayloadVerifyResponse_InvalidCount(t *testing.T) {
	t.Parallel()
	key, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	payload := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key.PublicKey()}}
	expectedError := "invalid payload: invalid number of signatures"
	err = payload.VerifyResponse([]byte{}, []byte("foo"))
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("VerifyResponse() error = %v, want %v", err, expectedError)
	}
}

func TestHostkeysProveRequestPayloadVerifyResponse_InvalidSignaturePayload(t *testing.T) {
	t.Parallel()
	key, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	payload := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key.PublicKey()}}
	expectedError := "invalid payload: ssh: unmarshal error"
	err = payload.VerifyResponse(ssh.Marshal(struct{ string }{"foo"}), []byte("foo"))
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("VerifyResponse() error = %v, want %v", err, expectedError)
	}
}

func TestHostkeysProveRequestPayloadVerifyResponse_InvalidSignature(t *testing.T) {
	t.Parallel()
	key1, err := sshutils.GenerateHostKey(&fakeRandReader{false}, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	key2, err := sshutils.GenerateHostKey(rand.Reader, sshutils.Ed25519)
	if err != nil {
		t.Fatalf("GenerateHostKey() error = %v", err)
	}
	payload1 := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key1.PublicKey()}}
	payload2 := &sshutils.HostkeysProveRequestPayload{sshutils.PublicKeys{key2.PublicKey()}}
	response, err := payload2.Response(&fakeRandReader{false}, []*sshutils.HostKey{key2}, []byte("foo"))
	if err != nil {
		t.Fatalf("Response() error = %v", err)
	}
	expectedError := "invalid payload: ssh: signature did not verify"
	err = payload1.VerifyResponse(response, []byte("foo"))
	if err == nil || !strings.HasPrefix(err.Error(), expectedError) {
		t.Errorf("VerifyResponse() error = %v, want %v", err, expectedError)
	}
}

func TestChannelRequestPayload(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name           string
		channelRequest *ssh.Request
		payload        sshutils.Payload
		str            string
		err            string
	}{
		{
			"pty-req",
			&ssh.Request{
				Type:      "pty-req",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b uint32
					c uint32
					d uint32
					e uint32
					f string
				}{"foo", 42, 43, 44, 45, string([]byte{1, 0, 0, 0, 42, 0})}),
			},
			&sshutils.PtyRequestPayload{"foo", 42, 43, 44, 45, ssh.TerminalModes{1: 42}},
			"pty-req: foo, 42x43",
			"",
		},
		{
			"pty-req_invalid_payload",
			&ssh.Request{
				Type:      "pty-req",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"pty-req_invalid_terminal_modes",
			&ssh.Request{
				Type:      "pty-req",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b uint32
					c uint32
					d uint32
					e uint32
					f string
				}{"foo", 42, 43, 44, 45, string([]byte{1})}),
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"x11-req",
			&ssh.Request{
				Type:      "x11-req",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a bool
					b string
					c string
					d uint32
				}{true, "foo", "bar", 42}),
			},
			&sshutils.X11RequestPayload{true, "foo", "bar", 42},
			"x11-req: 42",
			"",
		},
		{
			"x11-req_invalid_payload",
			&ssh.Request{
				Type:      "x11-req",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"env",
			&ssh.Request{
				Type:      "env",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b string
				}{"foo", "bar"}),
			},
			&sshutils.EnvRequestPayload{"foo", "bar"},
			"env: foo=bar",
			"",
		},
		{
			"env_invalid_payload",
			&ssh.Request{
				Type:      "env",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"shell",
			&ssh.Request{
				Type:      "shell",
				WantReply: true,
				Payload:   []byte{},
			},
			&sshutils.ShellRequestPayload{},
			"shell",
			"",
		},
		{
			"shell_invalid_payload",
			&ssh.Request{
				Type:      "shell",
				WantReply: true,
				Payload:   []byte{42},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: non-empty payload",
		},
		{
			"exec",
			&ssh.Request{
				Type:      "exec",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
				}{"foo"}),
			},
			&sshutils.ExecRequestPayload{"foo"},
			"exec: foo",
			"",
		},
		{
			"exec_invalid_payload",
			&ssh.Request{
				Type:      "exec",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"subsystem",
			&ssh.Request{
				Type:      "subsystem",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
				}{"foo"}),
			},
			&sshutils.SubsystemRequestPayload{"foo"},
			"subsystem: foo",
			"",
		},
		{
			"subsystem_invalid_payload",
			&ssh.Request{
				Type:      "subsystem",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"window-change",
			&ssh.Request{
				Type:      "window-change",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a uint32
					b uint32
					c uint32
					d uint32
				}{42, 43, 44, 45}),
			},
			&sshutils.WindowChangeRequestPayload{42, 43, 44, 45},
			"window-change: 42x43",
			"",
		},
		{
			"window-change_invalid_payload",
			&ssh.Request{
				Type:      "window-change",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"xon-xoff",
			&ssh.Request{
				Type:      "xon-xoff",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a bool
				}{true}),
			},
			&sshutils.XonXoffRequestPayload{true},
			"xon-xoff: true",
			"",
		},
		{
			"xon-xoff_invalid_payload",
			&ssh.Request{
				Type:      "xon-xoff",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"signal",
			&ssh.Request{
				Type:      "signal",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
				}{"foo"}),
			},
			&sshutils.SignalRequestPayload{"foo"},
			"signal: foo",
			"",
		},
		{
			"signal_invalid_payload",
			&ssh.Request{
				Type:      "signal",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"exit-status",
			&ssh.Request{
				Type:      "exit-status",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a uint32
				}{42}),
			},
			&sshutils.ExitStatusRequestPayload{42},
			"exit-status: 42",
			"",
		},
		{
			"exit-status_invalid_payload",
			&ssh.Request{
				Type:      "exit-status",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"exit-signal",
			&ssh.Request{
				Type:      "exit-signal",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					a string
					b bool
					c string
					d string
				}{"foo", true, "bar", "baz"}),
			},
			&sshutils.ExitSignalRequestPayload{"foo", true, "bar", "baz"},
			"exit-signal: foo",
			"",
		},
		{
			"exit-signal_invalid_payload",
			&ssh.Request{
				Type:      "exit-signal",
				WantReply: true,
				Payload:   []byte{},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: ssh: parse error",
		},
		{
			"eow",
			&ssh.Request{
				Type:      "eow@openssh.com",
				WantReply: true,
				Payload:   []byte{},
			},
			&sshutils.EowRequestPayload{},
			"eow",
			"",
		},
		{
			"eow_invalid_payload",
			&ssh.Request{
				Type:      "eow@openssh.com",
				WantReply: true,
				Payload:   []byte{42},
			},
			nil,
			"",
			"failed to unmarshal channel request payload: invalid payload: non-empty payload",
		},
		{
			"unknown",
			&ssh.Request{
				Type:      "lorem_ipsum",
				WantReply: true,
				Payload:   []byte{42, 43},
			},
			&sshutils.UnknownPayload{sshutils.RawPayload{42, 43}, "lorem_ipsum"},
			"unknown type (lorem_ipsum), payload: 2a2b",
			"",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload, err := sshutils.UnmarshalChannelRequestPayload(tt.channelRequest)
			testPayload(t, tt.channelRequest.Payload, payload, err, tt.payload, tt.str, tt.err)
		})
	}
}
