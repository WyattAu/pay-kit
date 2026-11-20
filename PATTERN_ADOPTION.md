# PATTERN_ADOPTION

Pattern relationships for pay-kit, declared against the WyattAu
pattern canon per references/adoption-format.md. Rows claim what the
code shows; patterns with no relationship here are omitted.

| Pattern | Status | Evidence |
|---|---|---|
| P54 | adopted | src/lib.rs:79 (verify_stripe enforces the timestamp tolerance window at src/lib.rs:87 and constant-time HMAC at src/lib.rs:101 before any parse; GoCardless body signature at src/lib.rs:197) |
| T33 | partial | src/lib.rs:63 (event ids are published as the caller's idempotency key, GoCardless equivalent at src/lib.rs:185; the barrier itself stays caller-owned per src/lib.rs:25) |
| T27 | partial | src/lib.rs:31 (settlements post through double_entry JournalEntry, Ledger, and Line types; ledger ownership is downstream) |
