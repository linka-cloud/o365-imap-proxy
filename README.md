# Office 365 OAuth2 IMAP Proxy

o365-imap-proxy is a proxy server that allows you to connect to the Office 365 IMAP server using PLAIN AUTH authentication.

It uses the OAuth2 Password flow with the PLAIN AUTH credentials to obtain an access token and then uses it to authenticate to the IMAP server with XAUTH2.

The main use case is to allow incompatible email clients and legacy applications to connect to the Office 365 IMAP server.

## Prerequisites

The proxy needs an Azure AD application to be registered in order to obtain the OAuth2 credentials.

The application must be configured with "**Resource Owner Password Credential Flow**" enabled and have the following permissions:
- `User.Read`
- `IMAP.AccessAsUser.All`


See [Microsoft docs](https://docs.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth#use-client-credentials-grant-flow-to-authenticate-imap-and-pop-connections).

## Installation

### Docker

```bash
docker pull linkacloud/o365-imap-proxy:latest
```

### From source

To build the binary from source, you need to have Go >= 1.18 installed on your machine.

```bash
git clone https://github.com/linka-cloud/o365-imap-proxy.git
cd o365-imap-proxy
make build
```

The binary will be available in the `bin` directory.

## Usage

```bash
$ o365-imap-proxy --help 

Office365 IMAP proxy allows to keep using IMAP clients without XOAUTH2 support with Office365 accounts by providing PLAIN AUTH support.

Usage:
  o365-imap-proxy [flags]

Flags:
      --address string         The address to listen on [$ADDRESS] defaults to :143 or :993 if TLS is enabled
      --client-id string       The Azure App client id [$CLIENT_ID]
      --client-secret string   The Azure App client secret [$CLIENT_SECRET]
      --debug                  Enable debug logging
  -h, --help                   help for o365-imap-proxy
      --tenant string          The Azure AD tenant id [$TENANT]
      --tls                    Enable TLS using generated self-signed certificate
```

The proxy can be configured using environment variables:
- `TENANT`: the Azure AD tenant ID
- `CLIENT_ID`: the Azure AD application client ID
- `CLIENT_SECRET`: the Azure AD application client secret

### Docker

```bash
docker run --name o365-imap-proxy \
  -e TENANT=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  -e CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  -e CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxx \
  -p 143:143 \
  linkacloud/o365-imap-proxy:latest
```

### Docker Compose

The proxy can be deployed using docker-compose:

```yaml
version: '3'
services:
  o365-imap-proxy:
    image: linkacloud/o365-imap-proxy:v0.0.1
    container_name: o365-imap-proxy
    restart: always
    command:
    - --tls
    ports:
      - "993:993"
    environment:
      TENANT: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      CLIENT_ID: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      CLIENT_SECRET: "xxxxxxxxxxxxxxxxxxxx"
```

```bash
docker-compose up -d
```

### From source

```bash
export TENANT=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxx
o365-imap-proxy --tls
```

