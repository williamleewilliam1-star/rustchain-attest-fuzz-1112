# RustChain /attest/submit bounded fuzz report — bounty #1112

**Run:** 2026-09-27 17:35–17:37 UTC  
**Target exercised:** https://50.28.86.131/attest/submit  
**Operator:** @williamleewilliam1-star / RTC wallet Babydov

## Result

The endpoint handled all 100 malformed/adversarial requests without a server-side crash or accidental success.

| Outcome | Count |
|---|---:|
| HTTP 400 | 52 |
| HTTP 422 | 48 |
| HTTP 2xx | 0 |
| HTTP 5xx | 0 |
| HTTP 429 | 0 |
| Transport errors | 0 |
| **Total** | **100** |

No vulnerability is claimed from this run. The useful result is a negative robustness finding: every tested malformed class failed closed with a 4xx response.

## Test matrix

| Category | Tests | 400 | 422 | 5xx |
|---|---:|---:|---:|---:|
| Missing / partial fields | 25 | 10 | 15 | 0 |
| Wrong JSON types | 25 | 17 | 8 | 0 |
| Bounded oversized inputs | 25 | 5 | 20 | 0 |
| Basic injection-style strings | 25 | 20 | 5 | 0 |
| **Total** | **100** | **52** | **48** | **0** |

The largest request body was 32,867 bytes. Oversized tests were intentionally bounded to 2–32 KiB; this was not a denial-of-service load test. Requests were sent sequentially with a 250 ms inter-request delay.

## Representative observations

1. Empty JSON returned HTTP 400 with MISSING_MINER.
2. A request containing only a syntactically valid miner identifier returned HTTP 422 with MISSING_DEVICE.
3. miner set to null returned HTTP 400 with MISSING_MINER.
4. A 2 KiB miner identifier returned HTTP 400 with INVALID_MINER; the server explicitly reports a 128-character identifier limit.
5. Oversized challenge/signature/device/extra-field cases reached later validation and returned HTTP 422 rather than raising.
6. SQL-like, path-traversal-like, HTML-like, shell-like, template-like, and prototype-style strings placed in the miner field were rejected with 400/422 validation responses; none returned 2xx or 5xx.
7. No rate limiting response occurred during the bounded run.

The raw results.jsonl contains the status, category, request size, latency, response preview, and any transport error for every test case.

## Validation behavior

The endpoint appears to apply early miner identifier validation before deeper attestation validation. Invalid or overlong miner strings are rejected as HTTP 400. Requests with an acceptable miner-shaped identifier but insufficient hardware/device evidence frequently progress to HTTP 422, most commonly MISSING_DEVICE.

That distinction is internally consistent across the matrix and is useful for clients: malformed identity input is treated as a request error, while structurally present identity with incomplete attestation evidence reaches semantic validation.

## Transport note

From the test Mac, https://rustchain.org/attest/submit failed during the TLS connection preflight with SSL_ERROR_SYSCALL. The production IP endpoint answered normally, so the fuzz matrix used https://50.28.86.131/attest/submit with certificate verification disabled because the certificate cannot be validated against the bare IP. This report treats that as a transport observation, not as a #1112 application vulnerability.

## Reproduction

Run the included fuzz_1112.py with Python 3. The script uses Python's standard library, sends exactly 100 deliberately invalid POST requests, caps oversized fields at 32 KiB, stores one JSON record per request, and writes a machine-readable summary.json.

## Security disclosure handling

The bounty instructs researchers to report any crash, 500-class failure, or potentially exploitable result privately. This run found none, so there is no private advisory associated with this report.

## Artifacts

- fuzz_1112.py — exact bounded request generator
- summary.json — machine-readable aggregate results
- results.jsonl — per-case result ledger
