mod create_api_token;
mod delete_api_token;
mod get_api_tokens;
mod update_api_token;
mod validate_api_token;

pub use create_api_token::{CreateApiTokenUseCase, CreatedApiToken};
pub use delete_api_token::DeleteApiTokenUseCase;
pub use get_api_tokens::GetApiTokensUseCase;
pub use update_api_token::UpdateApiTokenUseCase;
pub use validate_api_token::ValidateApiTokenUseCase;

use super::auth::session_factory::hex_encode;

/// Leading bytes of a key shown to admins so they can tell keys apart.
const KEY_PREFIX_LEN: usize = 8;

/// Display prefix and SHA-256 hash stored for a raw API key.
fn key_material(raw_token: &str) -> (&str, String) {
    // Custom keys may be any UTF-8; cut at the last char boundary within the prefix length.
    let end = (0..=KEY_PREFIX_LEN.min(raw_token.len()))
        .rev()
        .find(|&i| raw_token.is_char_boundary(i))
        .unwrap_or(0);
    (&raw_token[..end], hash_token(raw_token))
}

fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex_encode(&Sha256::digest(token.as_bytes()))
}
