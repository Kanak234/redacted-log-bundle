# Presentation — Redacted Log Bundle

1. I defined the local sharing workflow in PRD.md.
2. I combined Presidio, India-format rules and Gitleaks in bundle.py.
3. I hashed each value with a private key and merged overlapping spans before replacement.
4. I added a realistic mixed-line benchmark. It exposed timestamp masking and broken e-mail joins, which I fixed by restricting entities and trimming `key=` prefixes.
5. I exercised the complete CLI in test_integration.py and measured everything in bench.py.

**Main limitation.** A missed detection can still expose data, and format rules can mask ordinary numbers.
