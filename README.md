# Fortgate Open

Public open-source surface of **Fortgate ID**: hardware trust PoC, Midnight ZK circuits, Noir identity circuits, and the Rust client core.

| Repo | Visibility | Role |
|------|------------|------|
| [`fort-gate/fortgate-open`](https://github.com/fort-gate/fortgate-open) | **Public** | This repo — OSS surface only |
| [`fort-gate/fortgate_id`](https://github.com/fort-gate/fortgate_id) | **Private** | Product monorepo; consumes this repo as a **git submodule** at `open/` |

## Layout

| Path | Contents |
|------|----------|
| `client-sdk/` | Rust `fortgate-id-core` + `hw_trust` + `hw-midnight` + SP1 (e.firma) |
| `docs/` | Specs (HW trust, M_hw, Midnight, geo, credit-sign) |
| `proto/` | Noir circuit (RSA-2048 + Poseidon) |
| `proto-poseidon-check/` | Poseidon alignment smoke tests |

## Quick start

```bash
cd client-sdk && cargo test

cd client-sdk/hw-midnight
./scripts/fetch_srs.sh
cargo run --release --bin fortgate-hw-poc -- demo --tmp /tmp/fg-hw-demo

cd proto-poseidon-check && nargo test
```

## Use from the private monorepo

```bash
git clone --recurse-submodules https://github.com/fort-gate/fortgate_id.git
# or:
git submodule update --init --recursive
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
