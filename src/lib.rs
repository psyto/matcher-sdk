use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Standard context account size for all Percolator matchers
pub const CTX_SIZE: usize = 320;

/// Return data region: first 64 bytes of the context account
pub const RETURN_DATA_OFFSET: usize = 0;
pub const RETURN_DATA_SIZE: usize = 64;

/// Magic bytes offset (all matchers store magic at byte 64)
pub const MAGIC_OFFSET: usize = 64;

/// LP PDA offset (all matchers store LP PDA at byte 80)
pub const LP_PDA_OFFSET: usize = 80;

/// Read a u64 magic value from the context account
pub fn read_magic(ctx_data: &[u8]) -> u64 {
    if ctx_data.len() < MAGIC_OFFSET + 8 {
        return 0;
    }
    u64::from_le_bytes(ctx_data[MAGIC_OFFSET..MAGIC_OFFSET + 8].try_into().unwrap())
}

/// Read the LP PDA pubkey from the context account
pub fn read_lp_pda(ctx_data: &[u8]) -> Pubkey {
    Pubkey::new_from_array(
        ctx_data[LP_PDA_OFFSET..LP_PDA_OFFSET + 32]
            .try_into()
            .unwrap(),
    )
}

/// Verify that the magic bytes match the expected value
pub fn verify_magic(ctx_data: &[u8], expected_magic: u64) -> bool {
    if ctx_data.len() < CTX_SIZE {
        return false;
    }
    read_magic(ctx_data) == expected_magic
}

/// Verify LP PDA: checks that account[0] is a signer and matches the stored LP PDA
/// in the context account. This is the critical security check for all matchers.
///
/// Returns Ok(()) on success, or an appropriate ProgramError on failure.
///
/// # Arguments
/// * `lp_pda` - The LP PDA account (must be signer)
/// * `ctx_account` - The matcher context account (must be initialized)
/// * `expected_magic` - The magic bytes for this matcher type
/// * `matcher_name` - Name for log messages (e.g., "PRIVACY-MATCHER")
pub fn verify_lp_pda(
    lp_pda: &AccountInfo,
    ctx_account: &AccountInfo,
    expected_magic: u64,
    matcher_name: &str,
) -> ProgramResult {
    // 1. LP PDA must be a signer
    if !lp_pda.is_signer {
        msg!("{}: LP PDA must be a signer", matcher_name);
        return Err(ProgramError::MissingRequiredSignature);
    }

    // 2. Context must be initialized (magic check)
    let ctx_data = ctx_account.try_borrow_data()?;
    if !verify_magic(&ctx_data, expected_magic) {
        msg!("{}: Context not initialized or magic mismatch", matcher_name);
        return Err(ProgramError::UninitializedAccount);
    }

    // 3. LP PDA must match stored value
    let stored_pda = read_lp_pda(&ctx_data);
    if *lp_pda.key != stored_pda {
        msg!(
            "{}: LP PDA mismatch: expected {}, got {}",
            matcher_name,
            stored_pda,
            lp_pda.key
        );
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

/// Verify that the context account is writable, the right size, and not already initialized.
/// Used during Init instructions to prevent re-initialization.
///
/// # Arguments
/// * `ctx_account` - The matcher context account
/// * `expected_magic` - The magic bytes for this matcher type
/// * `matcher_name` - Name for log messages
pub fn verify_init_preconditions(
    ctx_account: &AccountInfo,
    expected_magic: u64,
    matcher_name: &str,
) -> ProgramResult {
    if !ctx_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if ctx_account.data_len() < CTX_SIZE {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let ctx_data = ctx_account.try_borrow_data()?;
    if verify_magic(&ctx_data, expected_magic) {
        msg!("{}: Context already initialized", matcher_name);
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    Ok(())
}

/// Write the standard header fields to a context account during initialization.
/// Writes: return data (zeroed), magic, version (1), mode, padding, LP PDA.
///
/// # Arguments
/// * `ctx_data` - Mutable reference to the context account data
/// * `magic` - The magic bytes for this matcher type
/// * `mode` - The mode byte (matcher-specific)
/// * `lp_pda` - The LP PDA pubkey to store
pub fn write_header(ctx_data: &mut [u8], magic: u64, mode: u8, lp_pda: &Pubkey) {
    // Zero return data region
    ctx_data[RETURN_DATA_OFFSET..RETURN_DATA_OFFSET + RETURN_DATA_SIZE].fill(0);
    // Magic
    ctx_data[MAGIC_OFFSET..MAGIC_OFFSET + 8].copy_from_slice(&magic.to_le_bytes());
    // Version = 1
    ctx_data[72..76].copy_from_slice(&1u32.to_le_bytes());
    // Mode
    ctx_data[76] = mode;
    // Padding
    ctx_data[77..LP_PDA_OFFSET].fill(0);
    // LP PDA
    ctx_data[LP_PDA_OFFSET..LP_PDA_OFFSET + 32].copy_from_slice(&lp_pda.to_bytes());
}

/// Write an execution price to the return buffer (first 8 bytes of context account).
/// This is how matchers communicate the price back to Percolator during CPI.
pub fn write_exec_price(ctx_data: &mut [u8], price: u64) {
    ctx_data[0..8].copy_from_slice(&price.to_le_bytes());
}

/// Compute execution price given an oracle/mark price and spread in bps.
/// Returns `price * (10000 + spread_bps) / 10000` using checked arithmetic.
pub fn compute_exec_price(price: u64, spread_bps: u64) -> Result<u64, ProgramError> {
    let multiplier = 10_000u64.saturating_add(spread_bps);
    let result = (price as u128)
        .checked_mul(multiplier as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?
        / 10_000u128;
    Ok(result as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_magic() {
        let mut data = vec![0u8; 320];
        let magic = 0x5052_4956_4d41_5443u64;
        data[64..72].copy_from_slice(&magic.to_le_bytes());
        assert!(verify_magic(&data, magic));
        assert!(!verify_magic(&data, 0x1234));
    }

    #[test]
    fn test_verify_magic_short_buffer() {
        let data = vec![0u8; 100];
        assert!(!verify_magic(&data, 0x1234));
    }

    #[test]
    fn test_compute_exec_price() {
        // 100_000_000 * (10000 + 50) / 10000 = 100_500_000
        assert_eq!(compute_exec_price(100_000_000, 50).unwrap(), 100_500_000);
    }

    #[test]
    fn test_compute_exec_price_zero_spread() {
        assert_eq!(compute_exec_price(100_000_000, 0).unwrap(), 100_000_000);
    }

    #[test]
    fn test_write_header() {
        let mut data = vec![0u8; 320];
        let magic = 0x5052_4956_4d41_5443u64;
        let lp = Pubkey::new_unique();
        write_header(&mut data, magic, 0, &lp);

        assert_eq!(u64::from_le_bytes(data[64..72].try_into().unwrap()), magic);
        assert_eq!(u32::from_le_bytes(data[72..76].try_into().unwrap()), 1);
        assert_eq!(data[76], 0);
        assert_eq!(Pubkey::new_from_array(data[80..112].try_into().unwrap()), lp);
    }

    #[test]
    fn test_write_exec_price() {
        let mut data = vec![0u8; 320];
        write_exec_price(&mut data, 12345678);
        assert_eq!(u64::from_le_bytes(data[0..8].try_into().unwrap()), 12345678);
    }

    // ===================================================================
    // CPI Contract Verification Tests
    //
    // These tests verify the byte-level contract that Percolator relies on
    // when invoking matchers via CPI. The contract is:
    //   1. Context account must be exactly CTX_SIZE (320) bytes
    //   2. Magic at offset 64 must match the matcher type
    //   3. LP PDA at offset 80 must match the signing account
    //   4. Execution price is written to offset 0 (first 8 bytes)
    //   5. write_header produces a context that passes verify_magic
    // ===================================================================

    #[test]
    fn test_cpi_contract_header_roundtrip() {
        // Verify that write_header creates a context that passes all CPI checks
        let mut data = vec![0u8; CTX_SIZE];
        let magic = 0x4556_4e54_4d41_5443u64; // EVENT_MATCHER_MAGIC
        let lp = Pubkey::new_unique();

        write_header(&mut data, magic, 1, &lp);

        // CPI check 1: magic verification passes
        assert!(verify_magic(&data, magic));

        // CPI check 2: LP PDA can be read back
        assert_eq!(read_lp_pda(&data), lp);

        // CPI check 3: version is 1
        assert_eq!(u32::from_le_bytes(data[72..76].try_into().unwrap()), 1);

        // CPI check 4: mode is preserved
        assert_eq!(data[76], 1);

        // CPI check 5: return data region is zeroed
        assert!(data[RETURN_DATA_OFFSET..RETURN_DATA_OFFSET + RETURN_DATA_SIZE]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn test_cpi_contract_exec_price_location() {
        // Percolator reads the exec price from bytes 0..8 of the context account.
        // Verify the price is written at the correct offset and doesn't corrupt
        // other fields.
        let mut data = vec![0u8; CTX_SIZE];
        let magic = 0x564F_4c4d_4154_4348u64; // VOL_MATCHER_MAGIC
        let lp = Pubkey::new_unique();

        write_header(&mut data, magic, 0, &lp);
        write_exec_price(&mut data, 42_000_000);

        // Price is at offset 0
        assert_eq!(
            u64::from_le_bytes(data[0..8].try_into().unwrap()),
            42_000_000
        );

        // Magic is not corrupted (at offset 64, well past the 8-byte price)
        assert!(verify_magic(&data, magic));

        // LP PDA is not corrupted (at offset 80)
        assert_eq!(read_lp_pda(&data), lp);
    }

    #[test]
    fn test_cpi_contract_magic_mismatch_rejected() {
        // A matcher initialized with one magic must reject another magic.
        // This prevents cross-matcher CPI attacks.
        let mut data = vec![0u8; CTX_SIZE];
        let privacy_magic = 0x5052_4956_4d41_5443u64;
        let vol_magic = 0x564F_4c4d_4154_4348u64;

        write_header(&mut data, privacy_magic, 0, &Pubkey::new_unique());

        // Correct magic passes
        assert!(verify_magic(&data, privacy_magic));
        // Wrong magic is rejected
        assert!(!verify_magic(&data, vol_magic));
    }

    #[test]
    fn test_cpi_contract_lp_pda_mismatch_detected() {
        // The LP PDA stored in the context must match the signer.
        // Verify that read_lp_pda returns a different pubkey when the
        // context was initialized with a different LP.
        let mut data = vec![0u8; CTX_SIZE];
        let lp_a = Pubkey::new_unique();
        let lp_b = Pubkey::new_unique();

        write_header(&mut data, 0x1234_5678_9ABC_DEF0, 0, &lp_a);

        // Correct LP passes
        assert_eq!(read_lp_pda(&data), lp_a);
        // Different LP detected
        assert_ne!(read_lp_pda(&data), lp_b);
    }

    #[test]
    fn test_cpi_contract_uninitialized_context_rejected() {
        // A zeroed-out context account must fail magic verification.
        // This prevents matchers from processing trades on uninitialized accounts.
        let data = vec![0u8; CTX_SIZE];
        let any_magic = 0x5052_4956_4d41_5443u64;

        assert!(!verify_magic(&data, any_magic));
    }

    #[test]
    fn test_cpi_contract_undersized_context_rejected() {
        // Context accounts smaller than CTX_SIZE must fail verification.
        let mut data = vec![0u8; 200]; // < 320
        let magic = 0x5052_4956_4d41_5443u64;
        // Even if we write magic at the right offset, size check should fail
        if data.len() > MAGIC_OFFSET + 8 {
            data[MAGIC_OFFSET..MAGIC_OFFSET + 8].copy_from_slice(&magic.to_le_bytes());
        }
        assert!(!verify_magic(&data, magic));
    }

    #[test]
    fn test_cpi_contract_all_four_magics_unique() {
        // All four matcher magics must be distinct to prevent cross-matcher confusion.
        let privacy = 0x5052_4956_4d41_5443u64; // "PRIVMATC"
        let vol = 0x564F_4c4d_4154_4348u64;     // "VOLMATCH"
        let jpy = 0x4A50_594D_4154_4348u64;     // "JPYMATCH"
        let event = 0x4556_4e54_4d41_5443u64;   // "EVNTMATC"

        let magics = [privacy, vol, jpy, event];
        for i in 0..magics.len() {
            for j in (i + 1)..magics.len() {
                assert_ne!(magics[i], magics[j], "Magic values must be unique");
            }
        }

        // Each magic only validates against itself
        let mut data = vec![0u8; CTX_SIZE];
        for &magic in &magics {
            data[MAGIC_OFFSET..MAGIC_OFFSET + 8].copy_from_slice(&magic.to_le_bytes());
            assert!(verify_magic(&data, magic));
            for &other in &magics {
                if other != magic {
                    assert!(!verify_magic(&data, other));
                }
            }
        }
    }

    #[test]
    fn test_cpi_contract_exec_price_overwrite() {
        // Verify that writing a new exec price correctly overwrites the old one.
        // This is important because Percolator reads this on every CPI call.
        let mut data = vec![0u8; CTX_SIZE];
        write_exec_price(&mut data, 100_000_000);
        assert_eq!(u64::from_le_bytes(data[0..8].try_into().unwrap()), 100_000_000);

        write_exec_price(&mut data, 200_000_000);
        assert_eq!(u64::from_le_bytes(data[0..8].try_into().unwrap()), 200_000_000);
    }

    #[test]
    fn test_cpi_contract_read_magic_short_data() {
        // read_magic must handle data shorter than MAGIC_OFFSET + 8 gracefully
        let data = vec![0u8; 50]; // Less than MAGIC_OFFSET (64) + 8
        assert_eq!(read_magic(&data), 0);
    }
}
