1. I defined the local sharing workflow in PRD.md.
2. I combined Presidio, India-format rules and Gitleaks in bundle.py.
3. I used a keyed digest for repeated values and merged overlapping spans before replacement.
4. I exercised the complete CLI in test_integration.py.
5. I measured category recall, false redactions and join preservation in bench.py.

**Main limitation.** Missed detections can expose data, and format rules can mask ordinary values.
