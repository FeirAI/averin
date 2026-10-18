# Recorded RFC 3161 responses

Real TimeStampToken bytes from live timestamp authorities, fetched on 2026-10-15 for the message in
`message.txt` (SHA-256 imprint, `openssl ts -query -sha256 -cert -no_nonce`). They exist so the verifier
is tested against what production TSAs actually send, not only against the in-repo mini-TSA.

| Fixture | TSA | Signature profile |
|---|---|---|
| freetsa | https://freetsa.org/tsr | ECDSA P-384 with SHA-512 |
| digicert | http://timestamp.digicert.com | RSA PKCS#1 v1.5 with SHA-256 |
| sectigo | http://timestamp.sectigo.com | RSA PKCS#1 v1.5 with SHA-384 |

`*.token.der` is the bare timeStampToken (`openssl ts -reply -token_out`). `*.spki.der` is the SubjectPublicKeyInfo
of the TSA signing certificate embedded in that token (the key an operator pins). No secrets are involved.
