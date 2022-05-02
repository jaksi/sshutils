package sshutils_test

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

func ExampleListen() {
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == "hunter2" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", conn.User())
		},
	}

	hostKey1, err := sshutils.LoadHostKey("id_rsa")
	if err != nil {
		log.Panic("Failed to load host key: ", err)
	}
	config.AddHostKey(hostKey1)

	hostKey2, err := sshutils.GenerateHostKey(sshutils.ECDSA)
	if err != nil {
		log.Panic("Failed to generate host key: ", err)
	}
	if err := hostKey2.Save("id_ecdsa"); err != nil {
		log.Panic("Failed to save host key: ", err)
	}
	config.AddHostKey(hostKey2)

	listener, err := sshutils.Listen("localhost:2022", config)
	if err != nil {
		log.Panic("Failed to listen: ", err)
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		log.Panic("Failed to accept incoming connection: ", err)
	}
	defer conn.Close()

	go ssh.DiscardRequests(conn.Requests)

	for newChannel := range conn.NewChannels {
		if newChannel.ChannelType() != "session" {
			if err := newChannel.Reject(ssh.UnknownChannelType, "unknown channel type"); err != nil {
				log.Panic("Failed to reject channel: ", err)
			}
			continue
		}

		channel, err := newChannel.AcceptChannel()
		if err != nil {
			log.Panic("Failed to accept channel: ", err)
		}
		defer channel.Close()

		go ssh.DiscardRequests(channel.Requests)

		fmt.Fprint(channel, "Hello, world!\n")
	}
}

func ExampleDial() {
	config := &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.AuthMethod{
			ssh.Password("hunter2"),
		},
	}

	conn, err := sshutils.Dial("localhost:2022", config)
	if err != nil {
		log.Panic("Failed to dial: ", err)
	}
	defer conn.Close()

	if _, _, err := conn.Request("direct-tcpip", false, &sshutils.DirectTcpipChannelPayload{
		Address:           "localhost",
		Port:              80,
		OriginatorAddress: "localhost",
		OriginatorPort:    8080,
	}); err != nil {
		log.Panic("Failed to request direct-tcpip: ", err)
	}

	session, err := conn.Channel("session", nil)
	if err != nil {
		log.Panic("Failed to open channel: ", err)
	}
	defer session.Close()

	if _, err := session.Request("exec", false, &sshutils.ExecRequestPayload{"/usr/bin/whoami"}); err != nil {
		log.Panic("Failed to send exec request: ", err)
	}

	stdout, err := ioutil.ReadAll(session)
	if err != nil {
		log.Panic("Failed to read session stdout: ", err)
	}

	fmt.Println(string(stdout))
}
