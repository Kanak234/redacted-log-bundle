"""Compare the shipped pipeline against stock Presidio and stock Gitleaks."""

import json
import random
import re
import secrets
from bundle import pii, leaks, render


def main():
    rng = random.Random(42)
    rows = []
    for i in range(12):
        # Non-issued fixtures are constructed locally. The token has no associated account.
        for category, value in [
            ("email", f"tester{i}@example.invalid"),
            ("PAN", f"ZZZZZ{i:04}Z"),
            ("Aadhaar", f"2345 0000 {i:04}"),
            ("phone", f"+91 900000{i:04}"),
            (
                "secret",
                "ghp_"
                + "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=36)),
            ),
            ("benign", f"build-step-{i}"),
        ]:
            rows.extend([(category, value)] * 2)
    rng.shuffle(rows)
    text = "\n".join(value for _, value in rows)
    key = secrets.token_bytes(32)
    stock, secret = list(pii(text, False)), list(leaks(text))
    for name, hits in [
        ("Presidio", stock),
        ("Gitleaks", secret),
        ("Bundle", list(pii(text)) + secret),
    ]:
        lines = render(text, hits, key)[0].split("\n")
        if len(lines) != len(rows):
            raise ValueError("A finding crossed benchmark records")
        scores, pairs, false = {}, {}, 0
        for (category, value), line in zip(rows, lines):
            if category == "benign":
                false += line != value
                continue
            masked = bool(re.fullmatch(r"\[R-[0-9a-f]{32}\]", line))
            scores.setdefault(category, []).append(masked)
            pairs.setdefault(value, []).append(line if masked else None)
        # A missed pair cannot get join credit merely because both raw strings survived.
        joins = sum(a is not None and a == b for a, b in pairs.values())
        print(
            json.dumps(
                dict(
                    detector=name,
                    recall={k: sum(v) / len(v) for k, v in scores.items()},
                    false_redactions=false,
                    preserved_pairs=joins,
                    total_pairs=len(pairs),
                )
            )
        )


if __name__ == "__main__":
    main()
