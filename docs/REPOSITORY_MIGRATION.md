# Repository and Go module migration

CSign moved to [arctex-one/csign](https://github.com/arctex-one/csign). The canonical Go module is `github.com/arctex-one/csign/v2`, starting with [v2.1.3](https://github.com/arctex-one/csign/releases/tag/v2.1.3).

## Update a checkout

For an existing checkout:

```bash
git remote set-url origin https://github.com/arctex-one/csign.git
git fetch origin --tags
```

To check out the published release in a new directory:

```bash
git clone --branch v2.1.3 https://github.com/arctex-one/csign.git
cd csign
make build
```

This builds `dist/chain-signer-plugin`. The build requires Go 1.27.1 or newer and `make`.

## Migrate a Go consumer

Update imports throughout the consumer, including tests and tools:

| Previous import | Current import |
| --- | --- |
| `github.com/lazysteff/csign/v2/pkg/api/v1` | `github.com/arctex-one/csign/v2/pkg/api/v1` |
| `github.com/lazysteff/csign/v2/pkg/client` | `github.com/arctex-one/csign/v2/pkg/client` |

Apply the same prefix change to other CSign packages. Consumers still using `github.com/chain-signer/chain-signer/...` or an unsuffixed CSign path must also migrate to `github.com/arctex-one/csign/v2/...`.

Remove the previous CSign requirement and any old-path replacement from `go.mod`. For a consumer of the previous v2 module:

```bash
go mod edit -droprequire=github.com/lazysteff/csign/v2
go mod edit -dropreplace=github.com/lazysteff/csign/v2
go get github.com/arctex-one/csign/v2@v2.1.3
go mod tidy
go test ./...
```

Use the corresponding old module path when removing an older unsuffixed requirement. A `replace` directive mapping the previous namespace to the new one does not migrate source imports. See the [Go client guide](api/errors-client.md#install-and-import-the-go-client) for the current import block.

Verify the resolved dependency:

```bash
go list -m -json github.com/arctex-one/csign/v2
```

For the published release, expect `Path` to be `github.com/arctex-one/csign/v2`, `Version` to be `v2.1.3`, and no `Replace` field. Remove any local replacement before checking published module consumption.

## Release artifacts and version history

Download the plugin, `chain-signer-plugin.sha256`, and `version.txt` from [the v2.1.3 release](https://github.com/arctex-one/csign/releases/tag/v2.1.3). Verify the checksum before registering the binary with Vault. To build the plugin from the published Go module inside a consumer module instead:

```bash
go get github.com/arctex-one/csign/v2@v2.1.3
go build -o chain-signer-plugin github.com/arctex-one/csign/v2/cmd/chain-signer-plugin
```

This writes `chain-signer-plugin` in the current directory. Build for the operating system and architecture of the Vault host.

Earlier release tags retain their original module declarations. Versions v2.0.1 through v2.1.2 use the previous module namespace; they are not releases of `github.com/arctex-one/csign/v2`. The original v2.0.0 tag has an invalid v2 module declaration and cannot be consumed as a Go v2 module. Historical changelog entries describe the namespace used at the time.

## Vault compatibility

The repository migration changes source and module locations. The plugin executable remains `chain-signer-plugin`, the example mount remains `chain-signer`, and the HTTP API remains `v1`, including `pkg/api/v1`. Signing policies, custody transfer format, and storage schema are unchanged from v2.1.2.

For upgrades from earlier releases, also read the [changelog](../CHANGELOG.md) and [signing architecture and storage compatibility guidance](SIGNING_ARCHITECTURE.md#managed-records-and-compatibility).
