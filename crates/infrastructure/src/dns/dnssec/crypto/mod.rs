use super::types::{DnskeyRecord, DsRecord, RrsigRecord};
use super::validation::authority::to_fqdn;
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use ferrous_dns_domain::DomainError;
use hickory_proto::dnssec::rdata::sig::SigInput;
use hickory_proto::dnssec::Algorithm;
use hickory_proto::dnssec::TBS;
use hickory_proto::rr::{DNSClass, Name, Record, SerialNumber};
use ring::signature;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384};
use std::str::FromStr;

pub fn verify_rrsig(
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    domain: &str,
    records: &[Record],
    now_secs: u32,
) -> Result<bool, DomainError> {
    let name = to_fqdn(domain).ok_or_else(|| {
        DomainError::InvalidDnsResponse(format!("invalid RRset owner name: {domain}"))
    })?;
    verify_rrsig_with_name(rrsig, dnskey, &name, records, now_secs)
}

/// Like [`verify_rrsig`], but takes the RRset owner as a parsed [`Name`].
///
/// Preferred when the owner is already available as a `Name`: it avoids a
/// presentation-format round-trip that mangles labels with characters the
/// display form escapes (e.g. `!`), which would otherwise fail to re-parse.
pub fn verify_rrsig_with_name(
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    name: &Name,
    records: &[Record],
    now_secs: u32,
) -> Result<bool, DomainError> {
    if !rrsig.is_valid_at(now_secs) {
        return Ok(false);
    }

    if dnskey.calculate_key_tag() != rrsig.key_tag || dnskey.algorithm != rrsig.algorithm {
        return Ok(false);
    }

    let signer_name = Name::from_str(&rrsig.signer_name)
        .map_err(|e| DomainError::InvalidDnsResponse(e.to_string()))?;

    let sig_input = SigInput {
        type_covered: RecordTypeMapper::to_hickory(&rrsig.type_covered),
        algorithm: Algorithm::from_u8(rrsig.algorithm),
        num_labels: rrsig.labels,
        original_ttl: rrsig.original_ttl,
        sig_expiration: SerialNumber::from(rrsig.signature_expiration),
        sig_inception: SerialNumber::from(rrsig.signature_inception),
        key_tag: rrsig.key_tag,
        signer_name,
    };

    let tbs = TBS::from_input(name, DNSClass::IN, &sig_input, records.iter())
        .map_err(|e| DomainError::InvalidDnsResponse(e.to_string()))?;
    let data = tbs.as_ref();
    let sig = rrsig.signature.as_slice();

    // 1024-bit RSA ZSKs are still common in deployed DNSSEC zones (RFC 8624
    // discourages but does not forbid them), so accept the full 1024..=8192
    // range — the stricter 2048-minimum verifier rejects them and produces
    // a false Bogus. Matches the behaviour of unbound/bind validators.
    match rrsig.algorithm {
        5 | 7 => verify_rsa(
            &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            data,
            sig,
            dnskey,
        ),
        8 => verify_rsa(
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            data,
            sig,
            dnskey,
        ),
        10 => verify_rsa(
            &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            data,
            sig,
            dnskey,
        ),
        13 => verify_ecdsa::<64>(
            &signature::ECDSA_P256_SHA256_FIXED,
            "ECDSA P-256",
            data,
            sig,
            dnskey,
        ),
        14 => verify_ecdsa::<96>(
            &signature::ECDSA_P384_SHA384_FIXED,
            "ECDSA P-384",
            data,
            sig,
            dnskey,
        ),
        15 => verify_ed25519(data, sig, dnskey),
        16 => Err(DomainError::InvalidDnsResponse(
            "Ed448 (algorithm 16) is not supported by this build".into(),
        )),
        _ => Err(DomainError::InvalidDnsResponse(format!(
            "Unsupported DNSSEC algorithm: {}",
            rrsig.algorithm
        ))),
    }
}

/// Whether this build implements the given DNSSEC signature algorithm
/// (matches the dispatch arms in [`verify_rrsig_with_name`]). Used to decide,
/// per RFC 6840 §5.2, whether a zone whose DS RRset names only algorithms we
/// cannot process must be treated as Insecure rather than Bogus.
pub fn is_supported_algorithm(algorithm: u8) -> bool {
    matches!(algorithm, 5 | 7 | 8 | 10 | 13 | 14 | 15)
}

pub fn verify_ds(
    ds: &DsRecord,
    dnskey: &DnskeyRecord,
    owner_name: &str,
) -> Result<bool, DomainError> {
    if dnskey.calculate_key_tag() != ds.key_tag || dnskey.algorithm != ds.algorithm {
        return Ok(false);
    }

    let dnskey_data = build_dnskey_data(dnskey, owner_name)?;

    let computed_digest = match ds.digest_type {
        1 => Sha1::digest(&dnskey_data).to_vec(),
        2 => Sha256::digest(&dnskey_data).to_vec(),
        4 => Sha384::digest(&dnskey_data).to_vec(),
        _ => {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Unsupported DS digest type: {}",
                ds.digest_type
            )))
        }
    };

    Ok(computed_digest == ds.digest)
}

fn verify_rsa(
    params: &'static signature::RsaParameters,
    data: &[u8],
    sig: &[u8],
    dnskey: &DnskeyRecord,
) -> Result<bool, DomainError> {
    let (exponent, modulus) = parse_rsa_key(&dnskey.public_key)?;
    let public_key = signature::RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    };
    Ok(public_key.verify(params, data, sig).is_ok())
}

/// `KEY_LEN` is the uncompressed point without its 0x04 prefix (RFC 6605 §4),
/// which is also the fixed-width `r || s` signature length.
fn verify_ecdsa<const KEY_LEN: usize>(
    alg: &'static signature::EcdsaVerificationAlgorithm,
    name: &str,
    data: &[u8],
    sig: &[u8],
    dnskey: &DnskeyRecord,
) -> Result<bool, DomainError> {
    if dnskey.public_key.len() != KEY_LEN {
        return Err(DomainError::InvalidDnsResponse(format!(
            "Invalid {name} public key length"
        )));
    }
    if sig.len() != KEY_LEN {
        return Err(DomainError::InvalidDnsResponse(format!(
            "Invalid {name} signature length"
        )));
    }

    // Sized for the largest supported curve (P-384).
    let mut point = [0u8; 97];
    point[0] = 0x04;
    point[1..=KEY_LEN].copy_from_slice(&dnskey.public_key);

    Ok(signature::UnparsedPublicKey::new(alg, &point[..=KEY_LEN])
        .verify(data, sig)
        .is_ok())
}

fn verify_ed25519(data: &[u8], sig: &[u8], dnskey: &DnskeyRecord) -> Result<bool, DomainError> {
    if dnskey.public_key.len() != 32 {
        return Err(DomainError::InvalidDnsResponse(
            "Invalid Ed25519 public key length".into(),
        ));
    }
    if sig.len() != 64 {
        return Err(DomainError::InvalidDnsResponse(
            "Invalid Ed25519 signature length".into(),
        ));
    }

    Ok(
        signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.public_key)
            .verify(data, sig)
            .is_ok(),
    )
}

/// Splits RFC 3110 RSA key material into (exponent, modulus).
fn parse_rsa_key(key_data: &[u8]) -> Result<(&[u8], &[u8]), DomainError> {
    let (exp_len, exp_start) = match key_data {
        [] => {
            return Err(DomainError::InvalidDnsResponse(
                "Empty RSA public key".into(),
            ))
        }
        [0, hi, lo, ..] => (usize::from(u16::from_be_bytes([*hi, *lo])), 3),
        [0, ..] => {
            return Err(DomainError::InvalidDnsResponse(
                "RSA key too short for long form".into(),
            ))
        }
        [len, ..] => (usize::from(*len), 1),
    };

    let exp_end = exp_start + exp_len;
    if exp_end > key_data.len() {
        return Err(DomainError::InvalidDnsResponse(
            "RSA exponent extends beyond key data".into(),
        ));
    }

    let (exponent, modulus) = key_data[exp_start..].split_at(exp_len);
    if modulus.is_empty() {
        return Err(DomainError::InvalidDnsResponse(
            "RSA modulus is empty".into(),
        ));
    }

    Ok((exponent, modulus))
}

fn build_dnskey_data(dnskey: &DnskeyRecord, owner_name: &str) -> Result<Vec<u8>, DomainError> {
    let mut data = name_to_wire(owner_name)?;
    data.extend_from_slice(&dnskey.flags.to_be_bytes());
    data.push(dnskey.protocol);
    data.push(dnskey.algorithm);
    data.extend_from_slice(&dnskey.public_key);
    Ok(data)
}

/// Canonical (lowercased, RFC 4034 §6.2) wire form of a presentation name.
fn name_to_wire(name: &str) -> Result<Vec<u8>, DomainError> {
    let name = name.trim_end_matches('.');
    let mut wire = Vec::with_capacity(name.len() + 2);

    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() {
                return Err(DomainError::InvalidDnsResponse("Empty DNS label".into()));
            }
            if label.len() > 63 {
                return Err(DomainError::InvalidDnsResponse("DNS label too long".into()));
            }
            wire.push(label.len() as u8);
            wire.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
        }
    }

    wire.push(0);
    Ok(wire)
}
