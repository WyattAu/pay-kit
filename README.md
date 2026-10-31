# pay-kit

Payment webhooks in, settled ledger entries out. Stripe and GoCardless
signature verification via
[`webhookkit`](https://crates.io/crates/webhookkit)'s constant-time HMAC;
settlements posted through
[`double-entry`](https://crates.io/crates/double-entry); allocations applied
via [`invoice-kit`](https://crates.io/crates/invoice-kit).

## The two halves, and why they are one crate

**Verification** is constant-time HMAC-SHA256 applied to two providers'
schemes: Stripe's timestamped `t=…,v1=…` header (replay-tolerance window,
key-rotation support) and GoCardless's plain body signature. **Settlement**
is an accounting act; bank debited, debtor credited, allocation applied to
the invoice. One crate because the seam between them is where payment fraud
actually lands: a webhook that verifies but does not reconcile is a
notification; one that reconciles without verifying is a remote posting API.

## The ordering rule

**Verify first, parse second, post last.** The signature covers the raw
bytes, so any parse-before-verify hands an attacker a parse gadget that runs
on unauthenticated input. A settlement is posted only from a *verified,
parsed* event; never from the raw body.

## Caller notes

- Stripe redelivers on failure: key your deduplication on the **event id**,
  not the payment id; the same payment id legitimately appears in
  redeliveries.
- The signature covers the body **as received**: no re-serialisation between
  the wire and this crate, or verification breaks (which is the point).
- `post_settlement` and `allocate` are deliberately separate: the posting is
  a *cash* act, the allocation a *documents* act, and a caller doing only one
  has either a paid invoice with no cash or cash with no paid invoice; the
  split makes the half-done state nameable.

## Licence

MIT OR Apache-2.0.
