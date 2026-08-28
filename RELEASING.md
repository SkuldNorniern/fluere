# Releasing

## Order matters

The workspace crates depend on each other, and crates.io resolves a published
dependency from the registry, not from the path. So they go up one at a time,
each waiting for the last:

1. `fluereflow`
2. `fluere-config`
3. `fluere_plugin` (needs `fluereflow` already up)
4. `fluere` (needs all three)

A dry run of a later crate fails until the earlier one is published. That is
expected, not a problem to fix:

```
failed to select a version for the requirement `fluereflow = "^0.8.0"`
```

## Before tagging

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --release -- -D warnings
cargo build --release --no-default-features
cargo package --workspace
```

`--no-default-features` is the build without a plugin runtime. It should run
and report that a configured plugin cannot be loaded, rather than failing.

Bump versions for what actually changed. A crate whose public API broke needs a
minor bump under 0.x, one that did not can stay where it is. `fluere-config` has
sat at 0.3.0 through releases that moved everything else.

Check that `paccel` is a published version and not a git revision. crates.io
will not accept a package that depends only on git.

## Tagging

```sh
git tag v0.8.0
git push origin v0.8.0
```

The tag builds and tests on Linux, macOS and Windows, then builds a deb, an rpm
and an archive per platform and attaches them to the release.

## After

```sh
cargo publish -p fluereflow
cargo publish -p fluere-config
cargo publish -p fluere_plugin
cargo publish -p fluere
```

Then update the wiki if anything in the record or the plugin view changed:
[Format](https://github.com/SkuldNorniern/fluere/wiki/Format) for the CSV,
[Plugins](https://github.com/SkuldNorniern/fluere/wiki/Plugins-(Beta)) for the
schema version, and the migration page if the change breaks anything.
