use super::cache::DnssecCache;
use super::trust_anchor::TrustAnchorStore;
use super::validation::authority::{self as auth_check, now_secs, to_fqdn};
use super::validation::denial::{
    prove_denial, prove_wildcard_expansion, VerifiedNsec, VerifiedNsec3,
};
use super::validation::ChainVerifier;
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DnssecStatus, DomainError, RecordType};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record};
use std::sync::Arc;
use tracing::{debug, warn};

/// Upper bound on distinct signer zones a single answer may carry before it is
/// rejected without walking any chain. Each distinct zone drives an independent
/// chain walk (per-label DS + DNSKEY fetches), so an attacker can pack RRSIGs
/// naming many bogus signer zones to multiply upstream queries. A legitimate
/// answer — even a long cross-zone CNAME chain — names only a few zones; this
/// ceiling is well above any real case while bounding the walk fan-out.
const MAX_SIGNER_ZONES: usize = 8;

pub struct DnssecValidator {
    pool_manager: Arc<PoolManager>,

    chain_verifier: ChainVerifier,

    timeout_ms: u64,
}

impl DnssecValidator {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        trust_store: TrustAnchorStore,
        dnssec_cache: Arc<DnssecCache>,
        timeout_ms: u64,
    ) -> Self {
        let chain_verifier =
            ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache, timeout_ms);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms,
        }
    }

    pub async fn validate_query(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<DnssecStatus, DomainError> {
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC validation"
        );

        let start = std::time::Instant::now();

        let domain_arc: Arc<str> = Arc::from(domain);
        let upstream_result = self
            .pool_manager
            .query(&domain_arc, &record_type, self.timeout_ms, true)
            .await?;

        debug!(
            domain = %domain,
            server = %upstream_result.server,
            latency_ms = upstream_result.latency_ms,
            "DNS query completed"
        );

        let validation_status = self
            .validate_message(domain, record_type, &upstream_result.response.message)
            .await;

        let elapsed = start.elapsed().as_millis() as u64;

        debug!(
            domain = %domain,
            status = %validation_status.as_str(),
            elapsed_ms = elapsed,
            "DNSSEC validation completed"
        );

        Ok(validation_status)
    }

    pub async fn validate_with_message(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> DnssecStatus {
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC validation (pre-fetched response)"
        );

        let start = std::time::Instant::now();

        let validation_status = self.validate_message(domain, record_type, message).await;

        let elapsed = start.elapsed().as_millis() as u64;

        debug!(
            domain = %domain,
            status = %validation_status.as_str(),
            elapsed_ms = elapsed,
            "DNSSEC validation completed (pre-fetched)"
        );

        validation_status
    }

    pub fn insert_zone_keys_for_test(
        &mut self,
        zone: &str,
        keys: Vec<crate::dns::dnssec::types::DnskeyRecord>,
    ) {
        self.chain_verifier.insert_zone_keys_for_test(zone, keys);
    }

    fn extract_signer_zone(answers: &[Record]) -> Option<String> {
        for record in answers {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data {
                let input = rrsig.input();
                if input.type_covered != hickory_proto::rr::RecordType::DNSKEY {
                    return Some(input.signer_name.to_string());
                }
            }
        }
        None
    }

    /// Distinct signer zones across all non-DNSKEY RRSIGs in `answers`, in order
    /// of first appearance. A cross-zone CNAME chain is signed by more than one
    /// zone, each of which must be anchored before its RRset can be trusted.
    fn extract_signer_zones(answers: &[Record]) -> Vec<String> {
        let mut zones: Vec<String> = Vec::new();
        for record in answers {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data {
                let input = rrsig.input();
                if input.type_covered == hickory_proto::rr::RecordType::DNSKEY {
                    continue;
                }
                let signer = input.signer_name.to_string();
                if !zones.contains(&signer) {
                    zones.push(signer);
                }
            }
        }
        zones
    }

    /// Combines per-zone chain-validation outcomes for a multi-signer answer.
    /// The answer is only `Secure` when every signer zone validates; otherwise
    /// the most severe outcome wins (Bogus > Indeterminate > Insecure).
    fn combine_chain_status(a: DnssecStatus, b: DnssecStatus) -> DnssecStatus {
        match (a, b) {
            (DnssecStatus::Bogus, _) | (_, DnssecStatus::Bogus) => DnssecStatus::Bogus,
            (DnssecStatus::Indeterminate, _) | (_, DnssecStatus::Indeterminate) => {
                DnssecStatus::Indeterminate
            }
            (DnssecStatus::Insecure, _) | (_, DnssecStatus::Insecure) => DnssecStatus::Insecure,
            (DnssecStatus::Secure, DnssecStatus::Secure) => DnssecStatus::Secure,
        }
    }

    /// Runs full validation over an already-fetched message: positive answers go
    /// through RRset signature + wildcard-expansion checks; empty answers
    /// (NXDOMAIN / NODATA) go through authenticated denial of existence.
    async fn validate_message(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> DnssecStatus {
        if message.answers.is_empty() {
            return self.validate_negative(domain, record_type, message).await;
        }

        // Establish the chain of trust for *every* signer zone present in the
        // answer (a cross-zone CNAME chain carries more than one), so each answer
        // RRset can later be checked against the keys of its own signer zone. If
        // the answer is unsigned there are no signer zones; fall back to the
        // queried name so an insecure delegation is still detected.
        let mut signer_zones = Self::extract_signer_zones(&message.answers);
        if signer_zones.is_empty() {
            signer_zones.push(domain.to_owned());
        }

        // Anti-amplification: cap the number of independent chain walks one
        // answer can trigger. More distinct signer zones than any legitimate
        // answer would carry means a crafted response trying to multiply
        // upstream DS/DNSKEY queries — reject it before walking anything.
        if signer_zones.len() > MAX_SIGNER_ZONES {
            warn!(
                domain = %domain,
                zones = signer_zones.len(),
                "answer names too many signer zones; refusing chain walk (possible amplification)"
            );
            return DnssecStatus::Bogus;
        }

        let mut status = DnssecStatus::Secure;
        for zone in &signer_zones {
            let zone_status = self.chain_verifier.verify_chain(zone).await;
            status = Self::combine_chain_status(status, zone_status);
            // Bogus is terminal under `combine_chain_status` (it dominates every
            // other outcome), so once any zone is Bogus the remaining walks
            // cannot change the verdict — stop and save the queries.
            if status == DnssecStatus::Bogus {
                break;
            }
        }

        if status == DnssecStatus::Secure {
            status = self.verify_rrset_signatures(domain, &message.answers);
            if status == DnssecStatus::Secure {
                status = self.verify_wildcard_proof(domain, &message.answers, &message.authorities);
            }
        }
        status
    }

    /// Validates a negative response. Anchors the chain at the authority's signer
    /// zone, then proves the denial from the NSEC/NSEC3 records.
    async fn validate_negative(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> DnssecStatus {
        let Some(zone) = Self::extract_signer_zone(&message.authorities) else {
            // No signed authority section: unsigned negative, serve without AD.
            return DnssecStatus::Insecure;
        };

        // The authority's signer zone must enclose the queried name. Otherwise a
        // validly-signed denial from an unrelated zone the attacker controls
        // could be presented as a proof about `domain`; the chain walk below
        // would happily anchor that real zone, and the NSEC/NSEC3 owners would
        // be checked against it — never against the victim name. Reject it as
        // Bogus before doing any of that work.
        match (to_fqdn(domain), to_fqdn(&zone)) {
            (Some(qname), Some(zone_name)) if auth_check::name_encloses(&zone_name, &qname) => {}
            _ => {
                warn!(
                    domain = %domain,
                    zone = %zone,
                    "negative-answer signer zone does not enclose the queried name"
                );
                return DnssecStatus::Bogus;
            }
        }

        let chain_status = self.chain_verifier.verify_chain(&zone).await;
        if chain_status != DnssecStatus::Secure {
            return chain_status;
        }
        self.validate_denial(
            domain,
            record_type,
            message.response_code,
            &zone,
            &message.authorities,
        )
    }

    /// [`auth_check::rrset_is_authentic`] against the zone keys this walk has established.
    fn rrset_is_authentic(
        &self,
        owner: &Name,
        rtype: hickory_proto::rr::RecordType,
        rrset: &[Record],
        sigs: &[Record],
        now_secs: u32,
    ) -> bool {
        auth_check::rrset_is_authentic(owner, rtype, rrset, sigs, now_secs, &|zone| {
            self.chain_verifier.get_zone_keys(zone).cloned()
        })
    }

    /// [`auth_check::collect_verified_denial`] against the zone keys this walk has established.
    fn collect_verified_denial<'a>(
        &self,
        authority: &'a [Record],
        now_secs: u32,
    ) -> (Vec<VerifiedNsec3<'a>>, Vec<VerifiedNsec<'a>>) {
        auth_check::collect_verified_denial(authority, now_secs, &|zone| {
            self.chain_verifier.get_zone_keys(zone).cloned()
        })
    }

    /// Validates an authenticated denial of existence (NXDOMAIN / NODATA) using
    /// the NSEC/NSEC3 records of the authority section. `soa_zone` is the signed
    /// zone apex already established in the chain.
    fn validate_denial(
        &self,
        qname: &str,
        qtype: RecordType,
        rcode: ResponseCode,
        soa_zone: &str,
        authority: &[Record],
    ) -> DnssecStatus {
        let (nsec3s, nsecs) = self.collect_verified_denial(authority, now_secs());

        if nsec3s.is_empty() && nsecs.is_empty() {
            // Signed zone but no authenticated denial records: stripped / forged.
            return DnssecStatus::Bogus;
        }

        let (Some(qname_name), Some(soa_name)) = (to_fqdn(qname), to_fqdn(soa_zone)) else {
            return DnssecStatus::Insecure;
        };
        let qtype_hickory = RecordTypeMapper::to_hickory(&qtype);

        let result = prove_denial(
            &qname_name,
            qtype_hickory,
            rcode,
            &soa_name,
            &nsec3s,
            &nsecs,
        );
        debug!(
            domain = %qname,
            zone = %soa_zone,
            ?rcode,
            nsec3 = nsec3s.len(),
            nsec = nsecs.len(),
            status = %result.as_str(),
            "denial of existence validated"
        );
        result
    }

    /// Verifies the wildcard-expansion proof for a *positive* answer
    /// (RFC 4035 §5.3.4). Returns `Secure` when the answer is not wildcard-
    /// expanded (nothing to prove) or the proof is valid; `Bogus` when the
    /// claimed expansion lacks a denial of the exact name.
    fn verify_wildcard_proof(
        &self,
        qname: &str,
        answers: &[Record],
        authority: &[Record],
    ) -> DnssecStatus {
        let mut wildcard_labels: Option<u8> = None;
        for record in answers {
            if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data {
                let input = rrsig.input();
                if input.type_covered == hickory_proto::rr::RecordType::DNSKEY {
                    continue;
                }
                if input.num_labels < record.name.num_labels() {
                    wildcard_labels = Some(input.num_labels);
                    break;
                }
            }
        }
        let Some(wildcard_labels) = wildcard_labels else {
            return DnssecStatus::Secure;
        };

        let (nsec3s, nsecs) = self.collect_verified_denial(authority, now_secs());
        let Some(qname_name) = to_fqdn(qname) else {
            return DnssecStatus::Insecure;
        };
        prove_wildcard_expansion(&qname_name, wildcard_labels, &nsec3s, &nsecs)
    }

    pub fn verify_rrset_signatures(&self, domain: &str, all_answers: &[Record]) -> DnssecStatus {
        let mut has_data = false;
        let mut has_rrsig = false;
        for record in all_answers {
            match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    if rrsig.input().type_covered != hickory_proto::rr::RecordType::DNSKEY {
                        has_rrsig = true;
                    }
                }
                _ => has_data = true,
            }
        }

        if !has_data {
            // Empty answers are routed to authenticated denial of existence
            // before reaching here; treat any stray empty RRset as undecided
            // rather than blindly authentic.
            debug!(domain = %domain, "No answer RRset to verify");
            return DnssecStatus::Indeterminate;
        }
        if !has_rrsig {
            debug!(domain = %domain, "No RRSIG for RRset — returning Bogus");
            return DnssecStatus::Bogus;
        }

        let now = now_secs();

        // Group the answer records into RRsets keyed by (owner, type). EVERY
        // RRset must be covered by an RRSIG that verifies against a trusted key
        // (RFC 4035 §5.3.1): verifying just one and returning Secure would let an
        // attacker append unsigned (or untrusted) RRsets to a response carrying a
        // single legitimately-signed RRset and still have the whole answer — and
        // therefore the AD bit — flagged Secure.
        let mut rrsets: Vec<(&Name, hickory_proto::rr::RecordType, Vec<Record>)> = Vec::new();
        for record in all_answers {
            if matches!(record.data, RData::DNSSEC(DNSSECRData::RRSIG(_))) {
                continue;
            }
            let owner = &record.name;
            let rtype = record.record_type();
            match rrsets
                .iter_mut()
                .find(|(o, t, _)| *o == owner && *t == rtype)
            {
                Some(entry) => entry.2.push(record.clone()),
                None => rrsets.push((owner, rtype, vec![record.clone()])),
            }
        }

        for (owner, rtype, records) in &rrsets {
            if !self.rrset_is_authentic(owner, *rtype, records.as_slice(), all_answers, now) {
                warn!(
                    domain = %domain,
                    owner = %owner,
                    rtype = ?rtype,
                    "answer RRset not covered by a valid RRSIG — returning Bogus"
                );
                return DnssecStatus::Bogus;
            }
        }

        debug!(domain = %domain, rrsets = rrsets.len(), "all answer RRsets verified");
        DnssecStatus::Secure
    }
}
