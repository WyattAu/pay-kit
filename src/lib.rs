//! Payment webhooks in, settled ledger entries out.
//!
//! # The two halves, and why they are one crate
//!
//! **Verification** is [`webhookkit`]'s constant-time HMAC-SHA256, applied to
//! two providers' schemes: Stripe's timestamped `t=…,v1=…` header (which adds
//! a replay-tolerance window and key-rotation support) and GoCardless's plain
//! body signature. **Settlement** is an accounting act — bank debited, debtor
//! credited, allocation applied to the invoice — via [`double_entry`] and
//! [`invoice_kit`]. One crate because the seam between them is where payment
//! fraud actually lands: a webhook that verifies but does not reconcile is a
//! notification; one that reconciles without verifying is a remote posting
//! API.
//!
//! # The ordering rule
//!
//! **Verify first, parse second, post last.** The signature covers the raw
//! bytes, so any parse-before-verify hands an attacker a parse gadget that
//! runs on unauthenticated input. And a settlement is posted only from a
//! *verified, parsed* event — never from the raw body — so nothing the wire
//! says can reach the ledger unverified.
//!
//! # What this crate is not
//!
//! Not an HTTP server. The webhook route, retries, and idempotency-at-the-
//! queue belong to the application; this crate verifies bytes and posts
//! entries. Idempotency note for the caller: Stripe redelivers on failure,
//! so key your deduplication on the event id, not the payment id — the same
//! payment id legitimately appears in `charge.succeeded` *and* its redelivery.

use double_entry::Amount;
use double_entry::money::Currency;
use double_entry::{JournalEntry, Ledger, Line};
use serde::Deserialize;

/// Why a webhook cannot become a settled entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookError {
    /// The `Stripe-Signature` header was absent or had neither `t=` nor
    /// `v1=`.
    MalformedSignatureHeader,
    /// The timestamp was outside the tolerance window: a replay.
    ReplaySuspected {
        /// The signed timestamp, unix seconds.
        timestamp: i64,
        /// The tolerance that was in force.
        tolerance_seconds: i64,
    },
    /// The HMAC did not match, via [`webhookkit`]'s constant-time compare.
    InvalidSignature,
    /// The verified body was not the event shape this crate parses.
    MalformedEvent {
        /// What was missing or wrong.
        detail: String,
    },
    /// A currency code the estate's money table does not carry.
    UnknownCurrency(String),
}

/// A verified Stripe event, narrowed to what a settlement needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripePayment {
    /// The event id (`evt_…`) — the caller's idempotency key.
    pub event_id: String,
    /// The payment intent id (`pi_…`).
    pub intent_id: String,
    /// The amount, minor units, always positive on success.
    pub amount_minor: u64,
    /// The ISO 4217 code, upper-cased from Stripe's lowercase wire form.
    pub currency: String,
}

/// Verify a Stripe webhook and extract the payment.
///
/// `raw_body` must be the **exact request bytes** — the signature covers the
/// body as received, so any re-serialisation breaks verification (which is
/// the point). `tolerance_seconds` guards replays; Stripe recommends five
/// minutes.
pub fn verify_stripe(
    raw_body: &[u8],
    signature_header: &str,
    secret: &str,
    now_unix: i64,
    tolerance_seconds: i64,
) -> Result<StripePayment, WebhookError> {
    let (timestamp, signatures) = parse_stripe_header(signature_header)?;
    if (now_unix - timestamp).abs() > tolerance_seconds {
        return Err(WebhookError::ReplaySuspected {
            timestamp,
            tolerance_seconds,
        });
    }
    let mut signed_payload = timestamp.to_string().into_bytes();
    signed_payload.push(b'.');
    signed_payload.extend_from_slice(raw_body);

    // Any one matching v1 passes: Stripe rotates keys, and during rotation
    // the old and new secrets both sign.
    let mut verified = false;
    for signature in &signatures {
        if webhookkit::verify_hmac_sha256(&signed_payload, secret.as_bytes(), signature.as_bytes())
            .is_ok()
        {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(WebhookError::InvalidSignature);
    }

    // Verified. Now, and only now, parse.
    let event: serde_json::Value =
        serde_json::from_slice(raw_body).map_err(|e| WebhookError::MalformedEvent {
            detail: e.to_string(),
        })?;
    let event_id = event
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WebhookError::MalformedEvent {
            detail: "no event id".into(),
        })?
        .to_string();
    let object = event
        .get("data")
        .and_then(|d| d.get("object"))
        .ok_or_else(|| WebhookError::MalformedEvent {
            detail: "no data.object".into(),
        })?;
    let intent_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let amount_minor = object
        .get("amount")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| WebhookError::MalformedEvent {
            detail: "no amount".into(),
        })?;
    let currency = object
        .get("currency")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WebhookError::MalformedEvent {
            detail: "no currency".into(),
        })?
        .to_uppercase();
    Ok(StripePayment {
        event_id,
        intent_id,
        amount_minor: amount_minor as u64,
        currency,
    })
}

/// `t=1614556800,v1=abc…,v1=def…`
fn parse_stripe_header(header: &str) -> Result<(i64, Vec<String>), WebhookError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        match key {
            "t" => {
                timestamp = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| WebhookError::MalformedSignatureHeader)?,
                );
            }
            "v1" => signatures.push(value.to_string()),
            _ => {}
        }
    }
    match (timestamp, signatures.is_empty()) {
        (Some(t), false) => Ok((t, signatures)),
        _ => Err(WebhookError::MalformedSignatureHeader),
    }
}

/// A verified GoCardless event, narrowed to what a settlement needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoCardlessEvent {
    /// The event id (`EV…`) — the caller's idempotency key.
    pub event_id: String,
    /// `payments`, `subscriptions`, …
    pub resource_type: String,
    /// `confirmed`, `paid_out`, `failed`, …
    pub action: String,
    /// The linked payment id (`PM…`), when the event links one.
    pub payment_id: Option<String>,
}

/// Verify a GoCardless webhook and extract its events.
///
/// GoCardless signs the raw body with the plain HMAC — no timestamp, because
/// their delivery model re-sends on failure and expects deduplication by
/// event id; the replay window is the caller's dedup window.
pub fn verify_gocardless(
    raw_body: &[u8],
    signature_hex: &str,
    secret: &str,
) -> Result<Vec<GoCardlessEvent>, WebhookError> {
    webhookkit::verify_hmac_sha256(raw_body, secret.as_bytes(), signature_hex.as_bytes())
        .map_err(|_| WebhookError::InvalidSignature)?;

    #[derive(Deserialize)]
    struct Envelope {
        events: Vec<RawEvent>,
    }
    #[derive(Deserialize)]
    struct RawEvent {
        id: String,
        #[serde(rename = "resourceType")]
        resource_type: String,
        action: String,
        links: Option<serde_json::Value>,
    }
    let envelope: Envelope =
        serde_json::from_slice(raw_body).map_err(|e| WebhookError::MalformedEvent {
            detail: e.to_string(),
        })?;
    Ok(envelope
        .events
        .into_iter()
        .map(|e| GoCardlessEvent {
            payment_id: e
                .links
                .as_ref()
                .and_then(|l| l.get("payment"))
                .and_then(|p| p.as_str())
                .map(String::from),
            event_id: e.id,
            resource_type: e.resource_type,
            action: e.action,
        })
        .collect())
}

/// A settled payment, ready to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// The invoice this settles, by the caller's numbering.
    pub invoice_id: String,
    /// The settled amount, minor units, always positive.
    pub amount_minor: u64,
    /// The currency.
    pub currency: Currency,
    /// The provider's own reference, for the ledger memo and the audit.
    pub external_ref: String,
}

/// Where a settlement lands in the caller's chart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementAccounts {
    /// The bank/cash account to debit.
    pub bank: String,
    /// The trade-debtors account to credit.
    pub debtor: String,
    /// The entry's date, `YYYY-MM-DD`.
    pub date: String,
    /// The entry's period, `YYYY-MM`.
    pub period: String,
}

/// Post a settlement: bank debited, debtor credited.
///
/// The pair is generated here — a settlement that posts one side and errors
/// on the other is a ledger that lies about its own history.
pub fn post_settlement(
    ledger: &mut Ledger,
    version: u64,
    entry_id: &str,
    accounts: &SettlementAccounts,
    settlement: &Settlement,
) -> Result<u64, double_entry::PostError> {
    let amount = Amount::minor(settlement.amount_minor as i64, settlement.currency);
    ledger.post(
        &JournalEntry::draft(
            entry_id,
            &accounts.date,
            &accounts.period,
            vec![
                Line::debit(&accounts.bank, amount)
                    .with_memo(format!("settled {}", settlement.external_ref)),
                Line::credit(&accounts.debtor, amount),
            ],
        ),
        version,
    )
}

/// The allocation a settlement applies, via `invoice-kit`'s allocator.
///
/// Separated from [`post_settlement`] because the allocation is a *documents*
/// act (which invoices are satisfied) while the posting is a *cash* act
/// (which accounts moved). A caller that does only one has either a paid
/// invoice with no cash, or cash with no satisfied invoice — and the split
/// makes the half-done state nameable.
pub fn allocate(
    payment_id: &str,
    settlement: &Settlement,
    outstanding: &[(String, i64)],
) -> Result<invoice_kit::allocation::Payment, invoice_kit::AllocationError> {
    invoice_kit::allocation::allocate(
        payment_id,
        Amount::minor(settlement.amount_minor as i64, settlement.currency),
        outstanding,
        settlement.currency,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use double_entry::money::currencies;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    const SECRET: &str = "whsec_test_5f1a";

    fn sign(payload: &str, secret: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("key size");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn stripe_body() -> String {
        r#"{"id":"evt_1","object":"event","type":"payment_intent.succeeded","data":{"object":{"id":"pi_3","amount":14400,"currency":"gbp","metadata":{"invoice":"INV-071"}}}}"#.to_string()
    }

    #[test]
    fn a_valid_stripe_webhook_verifies_and_yields_the_payment() {
        let body = stripe_body();
        let timestamp = 1_767_139_200i64;
        let signed = format!("{timestamp}.{body}");
        let header = format!("t={timestamp},v1={}", sign(&signed, SECRET));

        let payment =
            verify_stripe(body.as_bytes(), &header, SECRET, timestamp + 60, 300).expect("verifies");
        assert_eq!(payment.event_id, "evt_1");
        assert_eq!(payment.intent_id, "pi_3");
        assert_eq!(payment.amount_minor, 14_400);
        assert_eq!(payment.currency, "GBP", "Stripe's lowercase wire form");
    }

    #[test]
    fn a_tampered_body_never_verifies() {
        let body = stripe_body();
        let timestamp = 1_767_139_200i64;
        let header = format!(
            "t={timestamp},v1={}",
            sign(&format!("{timestamp}.{body}"), SECRET)
        );
        // One penny of tampering — the whole reason verification covers the
        // raw bytes and re-serialisation is forbidden.
        let tampered = body.replace("14400", "14401");
        assert_eq!(
            verify_stripe(tampered.as_bytes(), &header, SECRET, timestamp, 300),
            Err(WebhookError::InvalidSignature)
        );
    }

    #[test]
    fn a_stale_timestamp_is_a_replay_not_a_signature_failure() {
        let body = stripe_body();
        let timestamp = 1_767_139_200i64;
        let header = format!(
            "t={timestamp},v1={}",
            sign(&format!("{timestamp}.{body}"), SECRET)
        );
        // The same (valid!) signature, replayed six minutes later: refused,
        // and named as a replay so the caller can alert rather than log noise.
        assert_eq!(
            verify_stripe(body.as_bytes(), &header, SECRET, timestamp + 400, 300),
            Err(WebhookError::ReplaySuspected {
                timestamp,
                tolerance_seconds: 300
            })
        );
    }

    #[test]
    fn key_rotation_accepts_either_secret() {
        let body = stripe_body();
        let timestamp = 1_767_139_200i64;
        let old_secret = "whsec_old";
        let new_secret = "whsec_new";
        // Signed with the old secret; the header carries two v1 entries.
        let header = format!(
            "t={timestamp},v1={},v1={}",
            sign(&format!("{timestamp}.{body}"), old_secret),
            sign(&format!("{timestamp}.{body}"), new_secret),
        );
        let payment = verify_stripe(body.as_bytes(), &header, new_secret, timestamp, 300)
            .expect("the new secret's entry matches during rotation");
        assert_eq!(payment.event_id, "evt_1");
    }

    #[test]
    fn a_header_without_a_timestamp_or_signature_is_malformed() {
        let body = stripe_body();
        assert_eq!(
            verify_stripe(body.as_bytes(), "v1=abc", SECRET, 0, 300),
            Err(WebhookError::MalformedSignatureHeader)
        );
        assert_eq!(
            verify_stripe(body.as_bytes(), "t=123", SECRET, 0, 300),
            Err(WebhookError::MalformedSignatureHeader)
        );
    }

    const GC_BODY: &str = r#"{"events":[{"id":"EV001","resourceType":"payments","action":"confirmed","links":{"payment":"PM001"}}]}"#;

    #[test]
    fn a_valid_gocardless_webhook_yields_its_events() {
        let header = sign(GC_BODY, SECRET);
        let events = verify_gocardless(GC_BODY.as_bytes(), &header, SECRET).expect("verifies");
        assert_eq!(events.len(), 1);
        let event = events.first().expect("one event");
        assert_eq!(event.event_id, "EV001");
        assert_eq!(event.resource_type, "payments");
        assert_eq!(event.action, "confirmed");
        assert_eq!(event.payment_id.as_deref(), Some("PM001"));
    }

    #[test]
    fn a_gocardless_body_signed_with_the_wrong_secret_never_verifies() {
        let header = sign(GC_BODY, "whsec_other");
        assert_eq!(
            verify_gocardless(GC_BODY.as_bytes(), &header, SECRET),
            Err(WebhookError::InvalidSignature)
        );
    }

    #[test]
    fn a_verified_settlement_posts_both_sides_and_allocates() {
        let mut ledger = Ledger::new();
        for (id, name, kind) in [
            ("1000", "Current account", double_entry::AccountType::Asset),
            ("1100", "Trade debtors", double_entry::AccountType::Asset),
            ("3100", "Owner's equity", double_entry::AccountType::Equity),
            (
                "4000",
                "Consulting revenue",
                double_entry::AccountType::Revenue,
            ),
        ] {
            ledger.add_account(double_entry::Account::new(id, name, kind));
        }
        // Invoice out.
        let v = ledger
            .post(
                &JournalEntry::draft(
                    "JE-AR",
                    "2026-07-01",
                    "2026-07",
                    vec![
                        Line::debit("1100", double_entry::Amount::minor(14_400, currencies::GBP)),
                        Line::credit("4000", double_entry::Amount::minor(14_400, currencies::GBP)),
                    ],
                ),
                0,
            )
            .expect("invoice posts");

        let settlement = Settlement {
            invoice_id: "INV-071".into(),
            amount_minor: 14_400,
            currency: currencies::GBP,
            external_ref: "pi_3".into(),
        };
        let version = post_settlement(
            &mut ledger,
            v,
            "JE-PAY",
            &SettlementAccounts {
                bank: "1000".into(),
                debtor: "1100".into(),
                date: "2026-07-03".into(),
                period: "2026-07".into(),
            },
            &settlement,
        )
        .expect("the settlement posts");

        assert_eq!(
            ledger.balance(&double_entry::AccountId::new("1000")),
            14_400
        );
        assert_eq!(
            ledger.balance(&double_entry::AccountId::new("1100")),
            0,
            "the debtor cleared"
        );

        // And the allocation: the invoice is satisfied to the penny.
        let payment =
            allocate("PAY-1", &settlement, &[("INV-071".into(), 14_400)]).expect("allocates");
        assert_eq!(payment.allocations.len(), 1);
        let _ = version;
    }
}
