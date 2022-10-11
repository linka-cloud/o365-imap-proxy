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

package oauth

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type Provider interface {
	Login(ctx context.Context, username, password string) (*oauth2.Token, error)
	Logout(ctx context.Context, tk *oauth2.Token) error
}

func New(tenant, clientID, clientSecret string) Provider {
	return &provider{
		tenant:       tenant,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

type provider struct {
	tenant       string
	clientID     string
	clientSecret string
}

func (p *provider) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	oauth2Config := oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     microsoft.AzureADEndpoint(p.tenant),
		Scopes:       []string{"https://outlook.office.com/IMAP.AccessAsUser.All"},
	}

	tk, err := oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, err
	}
	return tk, nil
}

func (p *provider) Logout(ctx context.Context, tk *oauth2.Token) error {
	res, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(tk)).Get(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/logout?", p.tenant))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("logout failed: %s %s", res.Status, string(b))
	}
	return nil
}
