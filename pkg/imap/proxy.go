// Copyright 2022 Linka Cloud  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/commands"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"go.linka.cloud/o365-imap-proxy/pkg/oauth"
)

const (
	Login      = "LOGIN"
	Capability = "CAPABILITY"
	No         = "NO"
	Ok         = "OK"
)

type Proxy interface {
	Run(ctx context.Context) error
}

func New(tenant, clientID, clientSecret string, addr string, tlsConfig *tls.Config) (Proxy, error) {
	if tenant == "" {
		return nil, errors.New("tenant is required")
	}
	if clientID == "" {
		return nil, errors.New("clientID is required")
	}
	if clientSecret == "" {
		return nil, errors.New("clientSecret is required")
	}
	if addr == "" {
		if tlsConfig == nil {
			addr = ":143"
		} else {
			addr = ":993"
		}
	}
	return &proxy{
		addr: addr,
		auth: oauth.New(tenant, clientID, clientSecret),
		log:  logrus.StandardLogger().WithField("service", "imap"),
		tls:  tlsConfig,
	}, nil
}

type proxy struct {
	addr string
	auth oauth.Provider
	log  logrus.FieldLogger
	tls  *tls.Config
}

type state struct {
	authenticating bool
	authenticated  bool
	user           string
	token          *oauth2.Token
}

func (p *proxy) Run(ctx context.Context) error {
	p.log.Infof("Starting server at %s", p.addr)
	list, err := (&net.ListenConfig{}).Listen(ctx, "tcp", p.addr)
	if err != nil {
		return err
	}
	defer list.Close()

	if p.tls != nil {
		list = tls.NewListener(list, p.tls)
	}

	conns := make(chan net.Conn)
	go func() {
		for {
			conn, err := list.Accept()
			if err != nil {
				p.log.WithError(err).Error("Error accepting connection")
				return
			}
			conns <- conn
		}
	}()

	count := 0
	var mu sync.Mutex
	for {
		select {
		case conn := <-conns:
			go func() {
				defer conn.Close()
				mu.Lock()
				count++
				p.log.WithField("connections", count).Infof("Accepted connection")
				mu.Unlock()
				defer func() {
					mu.Lock()
					count--
					p.log.WithField("connections", count).Infof("Closed connection")
					mu.Unlock()
				}()
				if err := p.handle(ctx, conn); err != nil {
					if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "connection reset by peer") {
						p.log.WithError(err).Error("Error handling connection")
					}
				}
			}()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *proxy) handle(ctx context.Context, client net.Conn) error {
	log := p.log.WithField("client", client.RemoteAddr())
	log.Debugf("Calling upstream server")
	upstream, err := tls.Dial("tcp", "outlook.office365.com:993", &tls.Config{})
	if err != nil {
		log.WithError(err).Error("Error dialing upstream server")
		return err
	}
	defer upstream.Close()

	clientReader := bufio.NewReader(client)
	clientImapReader := imap.NewConn(client, imap.NewReader(nil), imap.NewClientWriter(nil, nil))
	upstreamReader := bufio.NewReader(upstream)
	upstreamImapReader := imap.NewConn(upstream, imap.NewReader(nil), imap.NewClientWriter(nil, nil))
	log.Infof("Start Proxying")
	errs := make(chan error, 2)

	var mu sync.RWMutex
	var state state

	defer func() {
		mu.RLock()
		defer mu.RUnlock()
		if state.token == nil {
			return
		}
		if err := p.auth.Logout(ctx, state.token); err != nil {
			log.Errorf("failed to logout: %v", err)
		}
		if state.user != "" {
			log.Infof("Logged out %s", state.user)
		} else {
			log.Infof("Logged out")
		}
	}()
	getLoginCmd := func(ctx context.Context, user, pass string) (*imap.Command, error) {
		var (
			mailbox string
			parts   = strings.Split(user, `\`)
		)

		switch len(parts) {
		case 1:
			// Username only
			mailbox = user

		case 2:
			// user\shared_mailbox
			user = parts[0]
			mailbox = parts[1]

		case 3:
			// domain\user\shared_mailbox
			return nil, errors.New("passing domain is unsupported")

		default:
			return nil, errors.New("invalid user format found")
		}

		log.Infof("Login attempt for %s", user)

		state.user = user
		state.token, err = p.auth.Login(ctx, user, pass)
		if err != nil {
			return nil, fmt.Errorf("getting token: %w", err)
		}

		log.Infof("Logged in %s", user)
		xoauth2 := &commands.Authenticate{
			Mechanism:       "XOAUTH2",
			InitialResponse: []byte("user=" + mailbox + "\x01auth=Bearer " + state.token.AccessToken + "\x01\x01"),
		}

		return xoauth2.Command(), nil
	}
	proxyClient := func() error {
		log := log.WithField("direction", "client->upstream")
		mu.RLock()
		if state.authenticated {
			mu.RUnlock()
			if _, err := io.Copy(upstream, clientReader); err != nil {
				return err
			}
			return io.EOF
		}
		mu.RUnlock()
		fields, err := clientImapReader.ReadLine()
		if err != nil && !imap.IsParseError(err) {
			return err
		}
		cmd := &imap.Command{}
		if err := cmd.Parse(fields); err != nil {
			return err
		}
		switch cmd.Name {
		case Login:
			log.Debugf("LOGIN command received")
			mu.Lock()
			defer mu.Unlock()
			state.authenticating = true
			if len(cmd.Arguments) != 2 {
				log.Infof("LOGIN command received with invalid number of arguments")
				return errors.New("login: invalid number of arguments")
			}
			xoauth2, err := getLoginCmd(ctx, cmd.Arguments[0].(string), cmd.Arguments[1].(string))
			if err != nil {
				log.Infof("LOGIN command received with invalid credentials")
				return fmt.Errorf("login: invalid credentials: %w", err)
			}
			xoauth2.Tag = cmd.Tag
			cmd = xoauth2
		default:

		}
		log.WithField("command", cmd.Name).WithField("tag", cmd.Tag).Debugf("Sending command: %v %v", cmd.Name, cmd.Arguments)
		if err := cmd.WriteTo(upstreamImapReader.Writer); err != nil {
			return err
		}
		return nil
	}
	proxyUpstream := func() error {
		log := log.WithField("direction", "upstream->client")
		mu.RLock()
		if state.authenticated {
			mu.RUnlock()
			if _, err := io.Copy(client, upstreamReader); err != nil {
				return err
			}
			return io.EOF
		}
		mu.RUnlock()
		fields, err := upstreamImapReader.ReadLine()
		if err != nil && !imap.IsParseError(err) {
			return err
		}
		cmd := imap.Command{}
		if err := cmd.Parse(fields); err != nil {
			return err
		}
		switch cmd.Name {
		case Capability:
			for i, v := range cmd.Arguments {
				if v.(string) == "AUTH=XOAUTH2" {
					cmd.Arguments[i] = "AUTH=PLAIN"
				}
			}
		case No:
			log.Debugf("NO: %v", cmd.Arguments)
			mu.Lock()
			state.authenticating = false
			mu.Unlock()
		case Ok:
			mu.Lock()
			if state.authenticating && len(cmd.Arguments) > 0 && cmd.Arguments[0] == "AUTHENTICATE" {
				state.authenticating = false
				state.authenticated = true
			}
			mu.Unlock()
		}
		log.WithField("command", cmd.Name).WithField("tag", cmd.Tag).Debugf("Received command: %v %v", cmd.Name, cmd.Arguments)
		if err := cmd.WriteTo(clientImapReader.Writer); err != nil {
			return err
		}
		return nil
	}

	// proxy upstream loop
	go func() {
		for {
			if err := proxyUpstream(); err != nil {
				errs <- err
				return
			}
		}
	}()
	// proxy client loop
	go func() {
		for {
			if err := proxyClient(); err != nil {
				errs <- err
				return
			}
		}
	}()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
