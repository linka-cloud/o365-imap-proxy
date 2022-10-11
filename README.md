# Office 365 OAuth2 IMAP Proxy

o365-imap-proxy is a proxy server that allows you to connect to the Office 365 IMAP server using PLAIN AUTH authentication.

It uses the OAuth2 Password flow with the PLAIN AUTH credentials to obtain an access token and then uses it to authenticate to the IMAP server.

The main use case is to allow incompatible email clients to connect to the Office 365 IMAP server.

The proxy needs an Azure AD application to be registered in order to obtain the OAuth2 credentials.

The application must be configured with "Resource Owner Password Credential Flow" enabled and have the following permissions:
- `User.Read`
- `IMAP.AccessAsUser.All`


https://docs.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth#use-client-credentials-grant-flow-to-authenticate-imap-and-pop-connections
