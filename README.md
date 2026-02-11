# matcher-sdk

Shared Rust library for [Percolator](https://github.com/nicholasgasior/percolator) custom matching programs on Solana.

All Percolator matchers share a 320-byte context account layout and a common CPI contract. This crate (`matcher-common`) provides the constants, verification functions, and header utilities that every matcher needs.

## Installation

Add to your matcher's `Cargo.toml`:

```toml
[dependencies]
matcher-common = { path = "../../matcher-sdk" }
```

## Context Account Layout

Every Percolator matcher operates on a 320-byte context account with this fixed layout:

```
Offset  | Size  | Field
--------|-------|----------------------------------
0-7     | 8     | Execution price (return data)
8-63    | 56    | Reserved return data
64-71   | 8     | Magic bytes (matcher identity)
72-75   | 4     | Version (= 1)
76      | 1     | Mode (matcher-specific)
77-79   | 3     | Padding
80-111  | 32    | LP PDA (liquidity provider)
112-319 | 208   | Reserved / matcher-specific data
```

The first 64 bytes (return data region) are where the matcher writes results back to Percolator during CPI calls. The magic bytes at offset 64 uniquely identify the matcher type and prevent cross-matcher attacks.

## Magic Values

Each matcher type has a unique 8-byte magic value:

| Matcher | Magic | Hex |
|---------|-------|-----|
| Privacy | `PRIVMATC` | `0x5052_4956_4d41_5443` |
| Volatility | `VOLMATCH` | `0x564F_4c4d_4154_4348` |
| JPY | `JPYMATCH` | `0x4A50_594D_4154_4348` |
| Event | `EVNTMATC` | `0x4556_4e54_4d41_5443` |

## CPI Contract

Percolator relies on these guarantees when invoking matchers via CPI:

1. Context account must be exactly `CTX_SIZE` (320) bytes
2. Magic at offset 64 must match the expected matcher type
3. LP PDA at offset 80 must match the signing account
4. Execution price is written to offset 0 (first 8 bytes) during execution
5. `write_header` produces a context that passes `verify_magic`
6. Uninitialized accounts (zeroed magic) are always rejected

## API Reference

### Constants

```rust
use matcher_common::{CTX_SIZE, RETURN_DATA_OFFSET, RETURN_DATA_SIZE, MAGIC_OFFSET, LP_PDA_OFFSET};

CTX_SIZE: usize = 320            // Standard context account size
RETURN_DATA_OFFSET: usize = 0    // Start of return data region
RETURN_DATA_SIZE: usize = 64     // Size of return data region
MAGIC_OFFSET: usize = 64         // Where magic bytes are stored
LP_PDA_OFFSET: usize = 80        // Where LP PDA is stored
```

### Reading Context Data

```rust
use matcher_common::{read_magic, read_lp_pda, verify_magic};

// Read the magic value from a context account
let magic = read_magic(&ctx_data);

// Read the LP PDA pubkey
let lp_pda = read_lp_pda(&ctx_data);

// Verify magic matches expected value (also checks buffer size >= 320)
let is_valid = verify_magic(&ctx_data, PRIVMATC);
```

### Account Verification

These are the critical security checks every matcher must perform.

#### `verify_lp_pda`

Verifies that the LP PDA account is a signer and matches the stored LP PDA in the context account. Call this on every execution instruction.

```rust
use matcher_common::verify_lp_pda;

// In your matcher's execute instruction:
let lp_pda = &ctx.accounts.lp_pda;
let ctx_account = &ctx.accounts.context;
let magic = 0x5052_4956_4d41_5443u64; // PRIVMATC

verify_lp_pda(lp_pda, ctx_account, magic, "PRIVACY-MATCHER")?;
// Checks:
//   1. lp_pda is a signer
//   2. Context magic matches (account is initialized)
//   3. LP PDA in context matches the signer
```

**Errors:**
- `MissingRequiredSignature` — LP PDA is not a signer
- `UninitializedAccount` — magic mismatch or context not initialized
- `InvalidAccountData` — LP PDA doesn't match stored value

#### `verify_init_preconditions`

Validates that a context account is ready for initialization. Prevents re-initialization attacks.

```rust
use matcher_common::verify_init_preconditions;

// In your matcher's init instruction:
verify_init_preconditions(ctx_account, magic, "PRIVACY-MATCHER")?;
// Checks:
//   1. Account is writable
//   2. Account is at least CTX_SIZE (320) bytes
//   3. Magic is NOT already set (prevents re-init)
```

**Errors:**
- `InvalidAccountData` — account is not writable
- `AccountDataTooSmall` — account is smaller than 320 bytes
- `AccountAlreadyInitialized` — magic is already set

### Writing Context Data

#### `write_header`

Initializes all standard header fields in a context account. Call this in your Init instruction after `verify_init_preconditions`.

```rust
use matcher_common::write_header;

let mut ctx_data = ctx_account.try_borrow_mut_data()?;
write_header(
    &mut ctx_data,
    0x5052_4956_4d41_5443u64,  // magic: PRIVMATC
    0,                          // mode: matcher-specific byte
    &lp_pda.key(),              // LP PDA pubkey
);
// Writes: zeroed return data, magic, version=1, mode, padding, LP PDA
```

#### `write_exec_price`

Writes the execution price to the return buffer (bytes 0-7). This is how your matcher communicates the computed price back to Percolator during CPI.

```rust
use matcher_common::write_exec_price;

let mut ctx_data = ctx_account.try_borrow_mut_data()?;
write_exec_price(&mut ctx_data, 100_500_000); // price in lamports or token units
```

### Price Computation

#### `compute_exec_price`

Applies a spread in basis points to a base price using checked arithmetic.

```rust
use matcher_common::compute_exec_price;

// Formula: price * (10_000 + spread_bps) / 10_000
let price = compute_exec_price(100_000_000, 50)?;
// 100_000_000 * 10_050 / 10_000 = 100_500_000

let price_no_spread = compute_exec_price(100_000_000, 0)?;
// 100_000_000 (unchanged)
```

**Errors:**
- `ArithmeticOverflow` — if the multiplication overflows u128

## Writing a Custom Matcher

Here's the typical structure for implementing a new Percolator matcher:

```rust
use matcher_common::*;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

// Define your matcher's unique magic
const MY_MAGIC: u64 = 0x4D59_4D41_5443_4845; // "MYMATCHE"

// Init instruction: set up the context account
pub fn process_init(accounts: &[AccountInfo], mode: u8) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let lp_pda = next_account_info(account_iter)?;
    let ctx_account = next_account_info(account_iter)?;

    // Verify preconditions (writable, correct size, not already initialized)
    verify_init_preconditions(ctx_account, MY_MAGIC, "MY-MATCHER")?;

    // Initialize the header
    let mut ctx_data = ctx_account.try_borrow_mut_data()?;
    write_header(&mut ctx_data, MY_MAGIC, mode, lp_pda.key);

    // Write any matcher-specific data to bytes 112-319
    // ctx_data[112..144].copy_from_slice(&my_custom_data);

    Ok(())
}

// Execute instruction: compute and write the price
pub fn process_execute(
    accounts: &[AccountInfo],
    oracle_price: u64,
    spread_bps: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let lp_pda = next_account_info(account_iter)?;
    let ctx_account = next_account_info(account_iter)?;

    // Verify LP PDA (signer check + magic check + PDA match)
    verify_lp_pda(lp_pda, ctx_account, MY_MAGIC, "MY-MATCHER")?;

    // Compute execution price with spread
    let exec_price = compute_exec_price(oracle_price, spread_bps)?;

    // Write price to return buffer for Percolator to read
    let mut ctx_data = ctx_account.try_borrow_mut_data()?;
    write_exec_price(&mut ctx_data, exec_price);

    Ok(())
}
```

## Testing

```bash
cargo test
```

The crate includes 16 tests covering:
- Magic byte verification and short buffer handling
- Price computation with and without spread
- Header write/read roundtrips
- Full CPI contract verification (magic mismatch rejection, LP PDA mismatch detection, uninitialized/undersized account rejection, cross-matcher attack prevention)

## License

MIT
