# matcher-sdk

Shared Rust library for [Percolator](https://github.com/nicholasgasior/percolator) custom matching programs on Solana.

## Overview

All Percolator matchers share a 320-byte context account layout and a common CPI contract. This crate provides:

- **Context account constants** — `CTX_SIZE` (320 bytes), offsets for return data, magic bytes, and LP PDA
- **Magic byte verification** — `verify_magic` / `read_magic` to validate matcher identity and prevent cross-matcher CPI attacks
- **LP PDA verification** — `verify_lp_pda` ensures the signing account matches the stored LP PDA
- **Init precondition checks** — `verify_init_preconditions` prevents re-initialization of context accounts
- **Header writing** — `write_header` initializes magic, version, mode, and LP PDA fields
- **Execution price** — `write_exec_price` writes the price to the return buffer; `compute_exec_price` applies spread in basis points

## Pricing Formula

```
exec_price = price * (10_000 + spread_bps) / 10_000
```

## Usage

Add to your matcher's `Cargo.toml`:

```toml
[dependencies]
matcher-common = { path = "../../matcher-sdk" }
```

## License

MIT
