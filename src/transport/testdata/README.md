# Test fixtures — never trust these

Throwaway EC P-256 material for the HTTPS transport unit tests. The CA's
private key was deleted right after signing, so nothing more can be issued
from it. Never install `ca.pem` as a trust anchor anywhere.

- `ca.pem` — self-signed test CA (`CN=mina-test-ca`)
- `chain.pem` — client cert (`CN=mina-test-client`) followed by `ca.pem`
- `client.key` — unencrypted PKCS#8 key of the client cert

Regenerate (in a Debian container with `openssl`):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca.key -out ca.pem -days 36500 -subj /CN=mina-test-ca
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout client.key -out client.csr -subj /CN=mina-test-client
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -out client.pem -days 36500
cat client.pem ca.pem > chain.pem
rm ca.key client.csr client.pem
```
- `other.key` — unrelated unencrypted PKCS#8 key (for the key-mismatch test): `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out other.key`
