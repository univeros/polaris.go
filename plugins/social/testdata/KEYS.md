# Test keys

`idp-rsa.pem` and `apple-client.pem` are throwaway keys generated for these tests only:
`idp-rsa.pem` signs the recorded ID tokens and matches `jwks.json`; `apple-client.pem` signs the
fake Apple client assertion. They protect nothing and are never used outside `go test`.
