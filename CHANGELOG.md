# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.1.2] - 2026-10-27

### Changed

- Tracks `invoice-kit 1.1.1` (BR-CO coverage constants). No behavioural change.


## [0.1.1] - 2026-10-27

### Changed

- Tracks `invoice-kit 1.1.0` (VAT-inclusive pricing) and `double-entry 0.1.1` — the estate graph's convergence pins. No behavioural change.


## [0.1.0] - 2026-10-25

Initial release.

### Added

- `verify_stripe` — `t=…,v1=…` header parsing, replay-tolerance window,
  key-rotation via multiple `v1` entries, verification through `webhookkit`'s
  constant-time HMAC. Parse happens only after verification.
- `verify_gocardless` — plain body HMAC, event-list extraction.
- `post_settlement` + `SettlementAccounts` — the bank/debtor pair generated
  atomically.
- `allocate` — the documents-side allocation via `invoice-kit`'s allocator,
  deliberately separate from the cash posting.
