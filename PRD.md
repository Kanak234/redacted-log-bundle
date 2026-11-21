# PRD — Redacted Log Bundle

## Problem
Support engineers often have to send a log to a vendor, a colleague or a public issue tracker. Those logs carry e-mails, phone numbers, Aadhaar and PAN numbers, IPs and API tokens. Manual find-and-replace misses values. Blanket masking (`***`) destroys the one thing the reader needs, which is "is this the same user or the same token as on line 40?".

## Users
- **Primary:** a support or SRE engineer sharing a UTF-8 text log from their own machine.
- **Secondary:** the recipient, who reads `redacted.txt` or `preview.html` and correlates events.

## Goals
1. Hide every supported sensitive value, keeping the log readable (timestamps, levels, event names).
2. Map each distinct value to one stable placeholder, so joins and searches still work.
3. Run fully offline after one setup step.
4. Never publish a partial bundle.

## Non-goals
- Guaranteeing zero leaks. Detection is best-effort, and the user still reviews `preview.html`.
- Binary formats, PDFs, images, or non-UTF-8 input.
- Reversing placeholders. The key holder can only re-hash a known value and compare.

## Features
| Feature | Behaviour |
|---|---|
| Detection | Presidio (person and account entities) + Aadhaar/PAN/Indian-phone formats + internal-suffix e-mail + Gitleaks secrets |
| Placeholder | `[R-<first 32 hex of HMAC-SHA256(key, value)>]` |
| Key | 32 random bytes, created with exclusive-create (`0600`) on first run and reused after |
| Output | `redacted.txt`, `summary.json` (counts per label), `preview.html` (HTML-escaped) |
| Fail-closed | Any detector or I/O error leaves no output directory |

## Workflow
1. `python setup_project.py` (once, online).
2. `python bundle.py support.log bundle-out private.key`.
3. Open `bundle-out/preview.html` and check it.
4. Share `bundle-out/`. Keep `private.key`.

## Acceptance criteria
- `python -m pytest -q` passes, including the subprocess integration test.
- `bench.py` single-value suite: the bundle hides 100% of every category, changes 0/24 benign lines and preserves 72/72 pairs.
- `bench.py` mixed-lines suite: the bundle gets an exact token for 100% of values and keeps 24/24 timestamps.
- An existing output path is refused. A key file that is not 32 bytes is refused.

## Edge cases
See `edge-cases.md`.
