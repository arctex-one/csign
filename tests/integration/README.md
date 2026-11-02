# Local custody transfer acceptance

Build the plugin for the architecture of your local `hashicorp/vault:latest`
container, for example on Apple Silicon:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/chain-signer-plugin ./cmd/chain-signer-plugin
python3 tests/integration/custody.py
```

This creates and removes one temporary **local development** Vault container.
It uses random in-memory development credentials, no production credentials,
and no existing Vault volumes. It checks ordinary-token ACL denial on all six
custody operations, trailing-slash rejection by Vault, a non-root sudo operator,
encrypted Source-to-target transfer, inactive staging, rejected ordinary status
updates, persisted replay after plugin reload, and explicit activation.

`go test ./...` additionally injects failure at every import, activation, and
abort storage boundary, verifies no active partial set, preserves exact legacy
and current records, and checks conflict/tamper handling.
