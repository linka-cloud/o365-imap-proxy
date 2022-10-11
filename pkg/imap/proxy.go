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
	"io"
	"net"
	"strings"
	"sync"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/commands"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"go.linka.cloud/mail-proxy/pkg/oauth"
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

func New(tenant, clientID, clientSecret string, addr string) (Proxy, error) {
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
		addr = ":143"
	}
	return &proxy{
		addr: addr,
		auth: oauth.New(tenant, clientID, clientSecret),
		log:  logrus.StandardLogger().WithField("service", "imap"),
	}, nil
}

type proxy struct {
	addr string
	auth oauth.Provider
	log  logrus.FieldLogger
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

	conns := make(chan net.Conn)
	go func() {
		for {
			conn, err := list.Accept()
			if err != nil {
				p.log.WithError(err).Error("Error accepting connection")
				return
			}
			p.log.Infof("Accepted connection")
			conns <- conn
		}
	}()

	for {
		select {
		case conn := <-conns:
			go func() {
				defer conn.Close()
				p.log.Infof("Connected to upstream server")
				if err := p.handle(ctx, conn); err != nil {
					if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "connection reset by peer") {
						p.log.WithError(err).Error("Error handling connection")
					}
				}
				p.log.Infof("Closed connection")
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
			log.Infof("%s: Logged out", state.user)
		} else {
			log.Infof("Logged out")
		}
	}()
	proxyClient := func() error {
		log := log.WithField("direction", "client->upstream")
		mu.RLock()
		if state.authenticated {
			mu.RUnlock()
			if _, err := io.Copy(upstream, clientReader); err != nil {
				return err
			}
			return nil
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
			state.user = cmd.Arguments[0].(string)
			log.Infof("Login attempt for %s", state.user)
			state.token, err = p.auth.Login(ctx, cmd.Arguments[0].(string), cmd.Arguments[1].(string))
			if err != nil {
				log.Infof("LOGIN command received with invalid credentials")
				return errors.New("login: invalid credentials")
			}
			log.Infof("Logged in %s", state.user)
			xoauth2 := (&commands.Authenticate{
				Mechanism:       "XOAUTH2",
				InitialResponse: []byte("user=" + cmd.Arguments[0].(string) + "\x01auth=Bearer " + state.token.AccessToken + "\x01\x01"),
			}).Command()
			xoauth2.Tag = cmd.Tag
			cmd = xoauth2
		default:

		}
		log.WithField("command", cmd.Name).WithField("tag", cmd.Tag).Debugf("Sending command: %v", cmd.Arguments)
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
			return nil
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
			if state.authenticating && len(cmd.Arguments) > 1 && cmd.Arguments[1] == "AUTHENTICATE" {
				state.authenticating = false
				state.authenticated = true
			}
			mu.Unlock()
		}
		log.WithField("command", cmd.Name).WithField("tag", cmd.Tag).Debugf("Received command: %v", cmd.Arguments)
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
