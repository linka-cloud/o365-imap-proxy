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

package main

import (
	"context"
	"os"
	"os/signal"

	cli "github.com/rancher/wrangler-cli"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.linka.cloud/mail-proxy/pkg/imap"
)

func NewImapCmd() *cobra.Command {
	return cli.Command(&ImapCmd{}, cobra.Command{
		Use:           "o365-imap-proxy",
		Short:         "Office365 IMAP proxy",
		Long:          "Office365 IMAP proxy allows to keep using IMAP clients without XOAUTH2 support with Office365 accounts by providing PLAIN AUTH support.",
		SilenceUsage:  true,
		SilenceErrors: true,
	})
}

type ImapCmd struct {
	Tenant       string `env:"TENANT" usage:"The Azure AD tenant id [$TENANT]"`
	ClientID     string `env:"CLIENT_ID" usage:"The Azure App client id [$CLIENT_ID]"`
	ClientSecret string `env:"CLIENT_SECRET" usage:"The Azure App client secret [$CLIENT_SECRET]"`
	Address      string `env:"ADDRESS" default:":143" usage:"The address to listen on [$ADDRESS]"`
	Debug        bool   `env:"DEBUG" usage:"Enable debug logging"`
}

func (c *ImapCmd) Run(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	if c.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	p, err := imap.New(c.Tenant, c.ClientID, c.ClientSecret, c.Address)
	if err != nil {
		return err
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)
	errs := make(chan error, 1)
	go func() {
		errs <- p.Run(ctx)
	}()
	for {
		select {
		case err := <-errs:
			return err
		case <-sigs:
			logrus.Info("shutting down")
			cancel()
		}
	}
}
