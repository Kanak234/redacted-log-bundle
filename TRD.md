# TRD — Redacted Log Bundle

## Stack
| Part | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Presidio and spaCy are Python-first |
| PII detection | presidio-analyzer 2.2.366 + spaCy `en_core_web_sm` 3.8.0 | Mature recognizers, offline once the model is installed |
| India formats | Presidio `PatternRecognizer` with regexes in `FORMATS` | Same span type as built-in results, so one merge path |
| Secret detection | Gitleaks 8.30.1 binary (`gitleaks stdin`, JSON report) | Large maintained rule set; SHA-256-pinned download |
| Pseudonymization | HMAC-SHA256, truncated to 128 bits | Deterministic per key, so joins work; not reversible without the key |
| Tests | pytest | Unit and subprocess integration |

## Data flow
1. Read the whole input as bytes and decode as UTF-8. Bad bytes raise, so nothing is published.
2. `pii(text)` analyzes one line at a time, so a span never crosses a record. It passes `entities=BUNDLE_ENTITIES` to Presidio and adds three India recognizers and a bare-mailbox pattern. Two cleanups follow:
   - It trims a `key=` / `key:` prefix from e-mail spans.
   - It drops `PERSON` spans that contain digits, `=`, `:`, `@`, `/` or `_`.
3. `leaks(text)` writes nothing to the bundle. It runs Gitleaks in a temporary directory and masks every literal occurrence of each finding. It errors if a finding cannot be found in the text.
4. `render()` sorts the spans, merges any that intersect, and replaces each merged range with its HMAC placeholder. It also counts labels.
5. `main()` writes the three files into `<output parent>/tmp*/bundle` and renames that folder to the output path. The rename is atomic on one filesystem.

## Key decisions
- **Entity allowlist (changed 2026-11-21).** Stock entities masked timestamps (`DATE_TIME`), hostnames (`URL`) and Indian phones as `US_BANK_NUMBER`. Their wide spans merged with neighbouring fields and broke joins. The mixed-lines benchmark now guards against a regression.
- **Union over priority.** When two detectors overlap, the whole union is replaced. This is safer than choosing one span, which could leave a visible suffix of the value.
- **Gitleaks discovery.** `gitleaks_path()` looks in `sysconfig.get_path("scripts")` before `PATH`, so a venv that isn't activated still works.

## Security
- The key file is created with `O_CREAT | O_EXCL`, mode 0600. It is never overwritten.
- `preview.html` is fully `html.escape`d, so script tags in logs can't run.
- The raw Gitleaks report lives only in a `TemporaryDirectory`.

## Performance and limits
The input and the spaCy model live in memory. Analysis runs one line at a time, so cost is linear in the line count.

## Testing
- `test_bundle.py` covers merge, join and rotation, empty input, invalid spans and format regexes.
- `test_integration.py` runs the real CLI with spaCy and Gitleaks, and has a mixed-line regression test.
- `bench.py` has two suites (see README).
