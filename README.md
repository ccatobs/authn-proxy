# Authentication Reverse Proxy

Sits between the TLS termination proxy and the application,
authenticating all requests.

Supports the following identity providers:

* GitHub, via OAuth2
* TLS client certificates

Upstream, the following headers are set:
```
X-Auth-Name
X-Auth-Email
X-Auth-User
X-Auth-Groups
```
Downstream, the above information is available at `/auth/userinfo` as JSON.

## Build and Run

To build:
```
$ go get
$ go build
```

To run, you need the
[Oauth settings from GitHub](https://github.com/organizations/ccatp/settings/applications),
which are passed via environment variables.
You'll also need to specify the port to listen on and upstream URL:
```
GITHUB_OAUTH2_CLIENT_ID=xxx \
GITHUB_OAUTH2_CLIENT_SECRET=xxx \
GITHUB_OAUTH2_CALLBACK_URL=https://example.com/oauth2/callback \
PORT=9000 \
UPSTREAM_URL="http://localhost:9001" \
./authn-proxy
```

## Client Certificates

If the `X-Tls-Client-Subject` header is present,
`authn-proxy` assumes the user presented a valid client certificate,
and that this header contains the value of the certificate's subject name field.

| Subject      | User info |
| ------------ | --------- |
| CN           | Name      |
| emailAddress | Email     |
| UID          | User      |
| OU           | Groups    |

### Generating the CA certificate

This generates a self-signed X.509 certificate authority:
```
openssl req -x509 -newkey rsa:4096 -sha256 -keyout client-ca.key.pem -out client-ca.cert.pem -nodes -days 1000 -subj "/CN=authn-proxy/O=FYST"
```

### Configuring the downstream TLS termination proxy

For [nginx](https://nginx.org/), you need the following configuration:
```
ssl_client_certificate /path/to/client-ca.cert.pem;
ssl_verify_client optional;
location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header X-Tls-Client-Subject $ssl_client_s_dn;
}
```

### Generate and sign the client certificate

```
$ openssl req -newkey rsa:2048 -sha256 -keyout client.key.pem -out client.csr.pem -nodes -subj "/CN=My Name/emailAddress=me@example.com/UID=me/OU=gid1/OU=gid2"
$ openssl x509 -req -sha256 -CA client-ca.cert.pem -CAkey client-ca.key.pem -in client.csr.pem -out client.cert.pem -set_serial 001 -days 390
```

### Connect

```
$ curl --cert client.cert.pem --key client.key.pem https://example.com/auth/userinfo
{"name":"My Name","email":"me@example.com","user":"me","groups":["gid2","gid1"]}
```
