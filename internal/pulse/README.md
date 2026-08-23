# Vendored Pulse client

This directory is derived from `github.com/jfreymuth/pulse` at commit `d6270f141f0d8188c17517cc5824709b1182d88b` under the MIT license in `LICENSE`.

Local changes:

- imports use `chirik/internal/pulse/proto`;
- protocol-version fields use valid `pulse` struct tags so `go vet` succeeds;
- byte-to-sample views use `unsafe.Slice` instead of `reflect.SliceHeader`;
- `Client.Done` and `Client.Error` expose server disconnects;
- the protocol reader preserves its first parsing error.

The package remains internal and introduces no `go.mod` dependency.
