package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	// g2g "gopkg.in/libgit2/git2go.v23"
)

const RyansPublicKey = `???`

func main() {
	parts := strings.Split(RyansPublicKey, " ")
	if len(parts) != 3 {
		panic("bad key format!")
	}
	keyType, keyData, keyUser := parts[0], parts[1], parts[2]

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			d := string(base64.StdEncoding.EncodeToString(key.Marshal()))

			if key.Type() == keyType && d == keyData {
				fmt.Printf("User %s is connecting!\n", keyUser)

				return &ssh.Permissions{
					CriticalOptions: map[string]string{
						"user": keyUser,
					},
				}, nil
			}

			fmt.Println("user key did not match")

			return nil, fmt.Errorf("public key rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		panic("failed to listen for connection")
	}
	nConn, err := listener.Accept()
	if err != nil {
		panic("failed to accept incoming connection")
	}

	for {
		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			panic(fmt.Sprintf("failed to handshake: %s", err))
		}
		fmt.Printf("We got a connection from user %s\n", conn.Permissions.CriticalOptions["user"])

		fmt.Println("Got a connection!")
		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		// Service the incoming Channel channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of a shell, the type is
			// "session" and ServerShell may be used to present a simple
			// terminal interface.
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				panic("could not accept channel.")
			}

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the
			// "shell" request.
			go func(in <-chan *ssh.Request) {
				for req := range in {
					ok := false
					switch req.Type {
					case "shell":
						ok = true
						if len(req.Payload) > 0 {
							// We don't accept any
							// commands, only the
							// default shell.
							ok = false
						}
					}
					req.Reply(ok, nil)
				}
			}(requests)

			term := terminal.NewTerminal(channel, "> ")

			go func() {
				defer channel.Close()
				for {
					line, err := term.ReadLine()
					if err != nil {
						break
					}
					fmt.Println(line)
				}
			}()
		}
	}
}
